use super::super::{address_type, mux_command, LocalAddr, ProxySocket, ProxyStream};
use super::addons::Addons;
use super::xtls::VisionStream;
use super::VlessFlow;
use crate::common::{from_str, invalid_data_error, to_string, Address, DEFAULT_BUF_SIZE};
use crate::impl_asyncwrite_flush_shutdown;
use crate::proxy::request_command;
use bytes::{Buf, BufMut, BytesMut};
use futures::{ready, FutureExt};
use prost::Message;
use std::io::{Cursor, Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use uuid::Uuid;

const VLESS_VERSION: u8 = 0;

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
pub struct VlessHeaderRequest<'a> {
    addr: &'a Address,
    id: &'a Uuid,
    addons: Option<Addons>,
    command: u8,
}

impl<'a> VlessHeaderRequest<'a> {
    pub fn new(addr: &'a Address, id: &'a Uuid, flow: &'a VlessFlow, command: u8) -> Self {
        let addons = match flow {
            VlessFlow::None => None,
            _ => Some(Addons {
                flow: to_string(flow),
                ..Default::default()
            }),
        };
        Self {
            addr,
            id,
            addons,
            command,
        }
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> Result<()>
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
        buf.put_u8(self.command);
        if self.command != request_command::MUX {
            buf.put_u16(self.addr.port());
            write_address(self.addr, buf);
        }
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        let addon_len = match self.addons {
            Some(ref addon) => addon.encoded_len(),
            None => 0,
        };
        if self.command != request_command::MUX {
            1 + 16 + 1 + addon_len + 1
        } else {
            1 + 16 + 1 + addon_len + 1 + self.addr.serialized_len()
        }
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
            buf.put_slice(dnaddr.as_bytes());
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
    pub async fn read_from<R>(r: &mut R) -> Result<Self>
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
                from_str(&addon.flow)?
            }
        };
        Ok(Self { ver, flow })
    }
}

#[derive(Debug)]
enum VlessStreamReadState {
    HeaderVersion([u8; 2]),
    DecodeBody,
}

pub(crate) struct VlessStream {
    stream: Box<dyn ProxyStream>,
    stream_id: u32,
    read_state: VlessStreamReadState,
    addr: Address,
    flow: VlessFlow,
}

impl VlessStream {
    pub fn new(
        stream: Box<dyn ProxyStream>,
        addr: Address,
        id: Uuid,
        flow: VlessFlow,
        stream_id: u32,
    ) -> Self {
        let stream: Box<dyn ProxyStream> = match flow {
            VlessFlow::None => stream,
            _ => Box::new(VisionStream::new(stream, id, stream_id)),
        };
        Self {
            stream,
            stream_id,
            read_state: VlessStreamReadState::HeaderVersion([0u8; 2]),
            addr,
            flow,
        }
    }
}

impl LocalAddr for VlessStream {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.stream.local_addr()
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                VlessStreamReadState::HeaderVersion(ref mut buffer) => {
                    let raw_stream = match this.flow {
                        VlessFlow::None => this.stream.as_mut(),
                        _ => this
                            .stream
                            .as_mut()
                            .as_any_mut()
                            .downcast_mut::<VisionStream>()
                            .expect("vision stream")
                            .as_mut_ref(),
                    };

                    ready!(raw_stream.poll_read_exact(cx, buffer))?;
                    let ver = buffer[0];
                    if ver != VLESS_VERSION {
                        return Err(invalid_data_error(format!(
                            "Invalid VLESS version {} received",
                            ver
                        )))
                        .into();
                    }
                    match buffer[1] {
                        0 => {
                            log::debug!("{} Received ver: {} flow: empty", this.stream_id, ver);
                        }
                        len => {
                            let mut buffer = vec![0u8; len as usize].into_boxed_slice();
                            log::debug!(
                                "{} Received ver: {} flow: len {}",
                                this.stream_id,
                                ver,
                                len
                            );
                            ready!(raw_stream.poll_read_exact(cx, &mut buffer))?;
                            let addon = Addons::decode(buffer.as_ref())?;
                            let flow: VlessFlow = from_str(&addon.flow)?;

                            log::debug!("{} Received flow: {:?}", this.stream_id, flow);
                            // It seems that it won't response the same vless flow in request
                            // if this.flow != flow {
                            //     log::error!("Invalid VLESS flow {} received", flow);
                            //     return Err(invalid_data_error(format!(
                            //         "Invalid VLESS flow {} received",
                            //         flow
                            //     )))
                            //     .into();
                            // }
                        }
                    };
                    this.read_state = VlessStreamReadState::DecodeBody;
                }
                VlessStreamReadState::DecodeBody => {
                    log::debug!("{} Reading response body", this.stream_id);
                    return Pin::new(&mut this.stream).poll_read(cx, buf);
                }
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();
        log::debug!(
            "{} Writing buf size: {} of {}",
            this.stream_id,
            buf.len(),
            this.addr
        );

        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    impl_asyncwrite_flush_shutdown!(stream);
}

pub(crate) struct VlessUdpStream {
    // bool is used to indicate whether to decode header when poll_recv_from
    stream: Mutex<(Box<dyn ProxyStream>, bool)>,
    target: Address,
}

impl VlessUdpStream {
    pub fn new(stream: Box<dyn ProxyStream>, target: Address) -> Self {
        Self {
            stream: Mutex::new((stream, true)),
            target,
        }
    }
}

impl ProxySocket for VlessUdpStream {
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>> {
        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let (stream, decode_header) = stream.deref_mut();
        if *decode_header {
            let mut buffer = [0u8; 2];
            ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut buffer))?;
            let ver = buffer[0];
            if ver != VLESS_VERSION {
                return Err(invalid_data_error(format!(
                    "Invalid VLESS version {} received",
                    ver
                )))
                .into();
            }
            match buffer[1] {
                0 => {
                    log::debug!("Received ver: {} flow: empty", ver);
                }
                len => {
                    let mut buffer = vec![0u8; len as usize];
                    log::debug!("Received ver: {} flow: len {}", ver, len);
                    ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut buffer))?;
                    let addon = Addons::decode(buffer.as_ref())?;
                    let flow: VlessFlow = from_str(&addon.flow)?;
                    log::debug!("Received flow: {:?}", flow);
                }
            };
            *decode_header = false;
        }
        let mut buffer = [0u8; 2];
        ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut buffer))?;
        let len = ((buffer[0] as usize) << 8) | (buffer[1] as usize);
        log::debug!("Content length: {}", len);
        if buf.capacity() < len {
            return Err(Error::new(ErrorKind::Interrupted, "Small buffer")).into();
        }
        Pin::new(&mut *stream)
            .poll_read_exact(cx, buf.initialize_unfilled_to(len))
            .map_ok(|_| {
                buf.set_filled(len);
                self.target.clone()
            })
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        _target: Address,
    ) -> Poll<Result<usize>> {
        if buf.len() + 2 > DEFAULT_BUF_SIZE {
            todo!("VlessUdpStream large packets")
        }
        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let (stream, _) = stream.deref_mut();
        let mut buffer = BytesMut::with_capacity(buf.len() + 2);
        buffer.put_u8((buf.len() >> 8) as u8);
        buffer.put_u8(buf.len() as u8);
        buffer.put_slice(buf);
        // TODO:
        // if the payload is too long, it need to be sent in multiple tcp packets
        Pin::new(stream)
            .poll_write(cx, &buffer)
            .map_ok(|_| buf.len())
    }
}

/// Mux.Cool Protocol
/// https://xtls.github.io/development/protocols/muxcool.htm
/// ```New
/// +-----+------+-------+----------+------+-----------+------+-----------+
/// | ID  | 0x01 |  OPT  | NET TYPE | PORT | ADDR TYPE | ADDR | GLOBAL ID |
/// +-----+------+-------+----------+------+-----------+------+-----------+
/// |  2  |   1  |   1   |     1    |   2  |     1     |   A  |     8     |
/// +-----+------+-------+----------+------+-----------+------+-----------+
/// ```
///
/// ```UDP Keep
/// +-----+------+-------+----------+------+-----------+------+
/// | ID  | 0x02 |  OPT  | NET TYPE | PORT | ADDR TYPE | ADDR |
/// +-----+------+-------+----------+------+-----------+------+
/// |  2  |   1  |   1   |     1    |   2  |     1     |   A  |
/// +-----+------+-------+----------+------+-----------+------+
/// ```
///
/// ```TCP Keep
/// +-----+------+-------+
/// | ID  | 0x02 |  OPT  |
/// +-----+------+-------+
/// |  2  |   1  |   1   |
/// +-----+------+-------+
/// ```
///
/// ```End
/// +-----+------+-------+
/// | ID  | 0x03 |  OPT  |
/// +-----+------+-------+
/// |  2  |   1  |   1   |
/// +-----+------+-------+
/// ```
///
/// ```KeepAlive
/// +-----+------+-------+
/// | ID  | 0x04 |  OPT  |
/// +-----+------+-------+
/// |  2  |   1  |   1   |
/// +-----+------+-------+
/// ```
pub struct MuxCoolLong {
    pub cmd: u8,
    pub opt: u8,
    pub net_type: u8,
    pub addr: Address,
    pub global_id: Option<[u8; 8]>,
}

impl MuxCoolLong {
    pub fn new(cmd: u8, opt: u8, net_type: u8, addr: Address, global_id: Option<[u8; 8]>) -> Self {
        Self {
            cmd,
            opt,
            net_type,
            addr,
            global_id,
        }
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        // xudp id always to be 0
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(self.cmd);
        buf.put_u8(self.opt);
        buf.put_u8(self.net_type);
        buf.put_u16(self.addr.port());
        write_address(&self.addr, buf);
        if let Some(id) = self.global_id {
            buf.put_slice(&id);
        }
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        if self.global_id.is_some() {
            2 + 1 + 1 + 1 + self.addr.serialized_len() + 8
        } else {
            2 + 1 + 1 + 1 + self.addr.serialized_len()
        }
    }

    pub fn read_from<T: AsRef<[u8]>>(cur: &mut Cursor<T>) -> Result<Self> {
        if cur.remaining() < 8 {
            return Err(invalid_data_error("Invalid Mux Cool Packets"));
        }
        // id
        cur.get_u16();
        let cmd = cur.get_u8();
        let opt = cur.get_u8();
        let net_type = cur.get_u8();
        let port = cur.get_u16();
        let addr_type = cur.get_u8();
        let addr = match addr_type {
            address_type::IPV4 => {
                if cur.remaining() < 4 {
                    return Err(invalid_data_error("Invalid Mux Cool Packets"));
                }
                let addr = Ipv4Addr::from(cur.get_u32());
                Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(addr, port)))
            }
            address_type::IPV6 => {
                if cur.remaining() < 16 {
                    return Err(invalid_data_error("Invalid Mux Cool Packets"));
                }
                let addr = Ipv6Addr::from(cur.get_u128());
                Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)))
            }
            address_type::DOMAIN => {
                if cur.remaining() < 1 {
                    return Err(invalid_data_error("Invalid Mux Cool Packets"));
                }
                let len = cur.get_u8() as usize;
                if cur.remaining() < len {
                    return Err(invalid_data_error("Invalid Mux Cool Packets"));
                }
                let mut buf = vec![0u8; len];
                cur.copy_to_slice(&mut buf);
                let addr = String::from_utf8(buf)
                    .map_err(|_| invalid_data_error("Invalid Mux Cool Packets"))?;
                Address::DomainNameAddress(addr, port)
            }
            _ => return Err(invalid_data_error("Invalid Mux Cool Packets")),
        };
        Ok(Self {
            cmd,
            opt,
            net_type,
            addr,
            global_id: None,
        })
    }
}

pub(crate) struct VlessMuxStream {
    stream: Mutex<(VisionStream, bool, bool)>,
    global_id: [u8; 8],
}

impl VlessMuxStream {
    pub fn new(stream: Box<dyn ProxyStream>, id: Uuid, global_id: [u8; 8], stream_id: u32) -> Self {
        Self {
            stream: Mutex::new((VisionStream::new(stream, id, stream_id), true, true)),
            global_id,
        }
    }
}

impl ProxySocket for VlessMuxStream {
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>> {
        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let (stream, decode_header, _) = stream.deref_mut();
        let mut raw_stream = stream.as_mut_ref();
        if *decode_header {
            let mut buffer = [0u8; 2];
            ready!(Pin::new(&mut raw_stream).poll_read_exact(cx, &mut buffer))?;
            let ver = buffer[0];
            if ver != VLESS_VERSION {
                return Err(invalid_data_error(format!(
                    "Invalid VLESS version {} received",
                    ver
                )))
                .into();
            }
            match buffer[1] {
                0 => {
                    log::debug!("Received ver: {} flow: empty", ver);
                }
                len => {
                    let mut buffer = vec![0u8; len as usize];
                    log::debug!("Received ver: {} flow: len {}", ver, len);
                    ready!(Pin::new(&mut raw_stream).poll_read_exact(cx, &mut buffer))?;
                    let addon = Addons::decode(buffer.as_ref())?;
                    let flow: VlessFlow = from_str(&addon.flow)?;
                    log::debug!("Received flow: {:?}", flow);
                }
            };
            *decode_header = false;
        }
        loop {
            let mut buffer = [0u8; 2];
            ready!(stream.poll_read_exact(cx, &mut buffer))?;
            let len = ((buffer[0] as usize) << 8) | (buffer[1] as usize);
            if len < 4 {
                return Err(Error::from(ErrorKind::UnexpectedEof)).into();
            }
            log::debug!("Content length: {}", len);
            let mut buffer = vec![0u8; len].into_boxed_slice();
            ready!(stream.poll_read_exact(cx, &mut buffer))?;
            match buffer[2] {
                mux_command::KEEP if len > 4 && buffer[4] == request_command::UDP => {
                    let mut cur = Cursor::new(buffer);
                    let mux_cool = MuxCoolLong::read_from(&mut cur)?;
                    log::debug!("Received UDP request from {}", mux_cool.addr);
                    let mut buffer = [0u8; 2];
                    ready!(stream.poll_read_exact(cx, &mut buffer))?;
                    let len = ((buffer[0] as usize) << 8) | (buffer[1] as usize);
                    if buf.capacity() < len {
                        return Err(Error::new(ErrorKind::Interrupted, "Small buffer")).into();
                    }
                    return Pin::new(&mut *stream)
                        .poll_read_exact(cx, buf.initialize_unfilled_to(len))
                        .map_ok(|_| {
                            buf.set_filled(len);
                            mux_cool.addr
                        });
                }
                mux_command::KEEP_ALIVE => {
                    continue;
                }
                _ => return Err(Error::from(ErrorKind::UnexpectedEof)).into(),
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>> {
        if buf.len() + 666 > DEFAULT_BUF_SIZE {
            todo!("VlessMuxStream large packets")
        }

        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let (stream, _, new_conn) = stream.deref_mut();

        let mux_cool = if *new_conn {
            *new_conn = false;
            MuxCoolLong::new(
                mux_command::NEW,
                1,
                request_command::UDP,
                target,
                Some(self.global_id),
            )
        } else {
            MuxCoolLong::new(mux_command::KEEP, 1, request_command::UDP, target, None)
        };
        let mux_cool_len = mux_cool.serialized_len();

        let mut buffer = BytesMut::with_capacity(mux_cool_len + 2 + buf.len() + 2);
        buffer.put_u8((mux_cool_len >> 8) as u8);
        buffer.put_u8(mux_cool_len as u8);
        mux_cool.write_to_buf(&mut buffer);
        buffer.put_u8((buf.len() >> 8) as u8);
        buffer.put_u8(buf.len() as u8);
        buffer.put_slice(buf);

        // TODO:
        // if the payload is too long, it need to be sent in multiple tcp packets
        Pin::new(stream)
            .poll_write(cx, &buffer)
            .map_ok(|_| buf.len())
    }
}
