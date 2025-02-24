use super::super::{address_type, request_command, ProxySteam};
use super::addons::Addons;
use super::xtls::{TrafficState, VisionReader, VisionWriter};
use super::VlessFlow;
use crate::common::{new_io_error, Address};
use crate::impl_asyncwrite_flush_shutdown;
use bytes::{BufMut, BytesMut};
use futures::ready;
use prost::Message;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

const VLESS_VERSION: u8 = 0;

pub struct VlessHeaderRequest {
    addr: Address,
    id: Uuid,
    addons: Option<Addons>,
}

/// VLESS request header
/// https://xtls.github.io/development/protocols/vless.html
/// ```plain
/// +-----+------+-------+-------+---------+------+-----------+------+
/// | VER | UUID | M LEN | ADDON | COMMAND | PORT | ADDR TYPE | ADDR |
/// +-----+------+-------+-------+---------+------+-----------+------+
/// |  1  |  16  |   1   |   M   |    1    |   2  |     1     |   S  |
/// +-----+------+-------+-------+---------+------+-----------+------+
/// ```
/// ADDON Type: Protobuf
///
impl VlessHeaderRequest {
    pub fn new(addr: Address, id: Uuid, flow: VlessFlow) -> Self {
        let addons = match flow {
            VlessFlow::None => None,
            _ => Some(Addons {
                flow: flow.to_string(),
                ..Default::default()
            }),
        };
        Self { addr, id, addons }
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.id.as_bytes());
        match self.addons {
            Some(ref addon) => {
                buf.put_u8(addon.encoded_len() as u8);
                buf.put_slice(addon.encode_to_vec().as_slice());
            }
            None => buf.put_u8(0),
        };
        buf.put_u8(request_command::TCP);
        buf.put_u16(self.addr.port());
        write_address(&self.addr, buf);
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        let addon_len = match self.addons {
            Some(ref addon) => addon.encoded_len(),
            None => 0,
        };
        1 + 16 + 1 + addon_len + 1 + 2 + 1 + get_addr_len(&self.addr)
    }
}

#[inline]
fn get_addr_len(addr: &Address) -> usize {
    match *addr {
        Address::SocketAddress(SocketAddr::V4(..)) => 4,
        Address::SocketAddress(SocketAddr::V6(..)) => 16,
        Address::DomainNameAddress(ref dmname, _) => 1 + dmname.len(),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(SocketAddr::V4(ref addr)) => {
            buf.put_u8(address_type::IPV4);
            buf.put_slice(&addr.ip().octets());
        }
        Address::SocketAddress(SocketAddr::V6(ref addr)) => {
            buf.put_u8(address_type::IPV6);
            for seg in &addr.ip().segments() {
                buf.put_u16(*seg); // Ipv6 bytes
            }
        }
        Address::DomainNameAddress(ref dnaddr, _) => {
            buf.put_u8(address_type::DOMAIN);
            buf.put_u8(dnaddr.len() as u8);
            buf.put_slice(dnaddr[..].as_bytes());
        }
    }
}

/// VLESS response header
/// ```plain
/// +-----+-------+-------+
/// | VER | N LEN | ADDON |
/// +-----+-------+-------+
/// |  1  |   1   |   N   |
/// +-----+-------+-------+
/// ```
/// ADDON Type: Protobuf
///
pub struct VlessHeaderResponse {
    pub ver: u8,
    pub flow: VlessFlow,
}

impl VlessHeaderResponse {
    pub async fn read_from<R>(r: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;
        let ver = buf[0];
        let flow = match buf[1] {
            0 => VlessFlow::None,
            len => {
                let mut buf = vec![0u8; len as usize];
                let _ = r.read_exact(&mut buf).await?;
                let addon = Addons::decode(buf.as_slice())?;
                VlessFlow::from_str(&addon.flow).map_err(new_io_error)?
            }
        };
        Ok(Self { ver, flow })
    }
}

#[derive(Debug)]
enum VlessStreamReadState {
    HeaderVersion([u8; 2]),
    DecodeHeaderFlow(Box<[u8]>),
    DecodeBody,
}

pub(crate) struct VlessStream<S> {
    stream: S,
    stream_id: u32,
    read_state: VlessStreamReadState,
    addr: Address,
    flow: VlessFlow,
    xtls: Option<(TrafficState, VisionReader, VisionWriter)>,
}

impl<S> VlessStream<S>
where
    S: ProxySteam,
{
    pub fn new(stream: S, addr: Address, id: Uuid, flow: VlessFlow, stream_id: u32) -> Self {
        let xtls = match flow {
            VlessFlow::None => None,
            _ => Some((
                TrafficState::new(stream_id, id),
                VisionReader::new(),
                VisionWriter::new(),
            )),
        };
        Self {
            stream,
            stream_id,
            read_state: VlessStreamReadState::HeaderVersion([0u8; 2]),
            addr,
            flow,
            xtls,
        }
    }
}

impl<S> AsyncRead for VlessStream<S>
where
    S: ProxySteam,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                VlessStreamReadState::HeaderVersion(ref mut buffer) => {
                    ready!(this.stream.poll_read_exact(cx, buffer))?;
                    let ver = buffer[0];
                    if ver != VLESS_VERSION {
                        return Err(new_io_error(format!(
                            "Invalid VLESS version {} received",
                            ver
                        )))
                        .into();
                    }
                    match buffer[1] {
                        0 => {
                            log::debug!("{} Received ver: {} flow: empty", this.stream_id, ver);
                            this.read_state = VlessStreamReadState::DecodeBody;
                        }
                        len => {
                            let buffer = vec![0u8; len as usize].into_boxed_slice();
                            log::debug!(
                                "{} Received ver: {} flow: len {}",
                                this.stream_id,
                                ver,
                                len
                            );
                            this.read_state = VlessStreamReadState::DecodeHeaderFlow(buffer);
                        }
                    };
                }
                VlessStreamReadState::DecodeHeaderFlow(ref mut buffer) => {
                    ready!(this.stream.poll_read_exact(cx, buffer))?;
                    let addon = Addons::decode(buffer.as_ref())?;
                    let flow = VlessFlow::from_str(&addon.flow).map_err(new_io_error)?;

                    log::debug!("{} Received flow: {}", this.stream_id, flow);
                    // It seems that it won't response the same vless flow in request
                    // if this.flow != flow {
                    //     log::error!("Invalid VLESS flow {} received", flow);
                    //     return Err(new_io_error(format!(
                    //         "Invalid VLESS flow {} received",
                    //         flow
                    //     )))
                    //     .into();
                    // }

                    this.read_state = VlessStreamReadState::DecodeBody;
                }
                VlessStreamReadState::DecodeBody => {
                    log::debug!("{} Reading response body", this.stream_id);
                    match this.flow {
                        VlessFlow::None => {
                            return Pin::new(&mut this.stream)
                                .poll_read(cx, buf)
                                .map_err(Into::into);
                        }
                        _ => {
                            let (traffic_state, vision_reader, _) =
                                this.xtls.as_mut().expect("xtls reader");
                            return vision_reader.read(&mut this.stream, cx, buf, traffic_state);
                        }
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for VlessStream<S>
where
    S: ProxySteam,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        log::debug!(
            "{} Writing buf size: {} of {}",
            this.stream_id,
            buf.len(),
            this.addr
        );

        match this.flow {
            VlessFlow::None => Pin::new(&mut this.stream)
                .poll_write(cx, buf)
                .map_err(Into::into),
            _ => {
                let (traffic_state, _, vision_writer) = this.xtls.as_mut().expect("xtls writer");
                vision_writer.write(&mut this.stream, cx, buf, traffic_state)
            }
        }
    }

    impl_asyncwrite_flush_shutdown!(stream);
}
