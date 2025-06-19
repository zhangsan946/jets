use super::super::{LocalAddr, ProxyStream};
use crate::common::{find_str_in_str, DEFAULT_BUF_SIZE};
use crate::impl_asyncwrite_flush_shutdown;
use crate::transport::tls::TlsStream;
use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use rand::prelude::*;
use std::io::Result;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

const TLS_HANDSHAKE_PREFIX_SERVER: &[u8; 3] = &[0x16, 0x03, 0x03];
const TLS_HANDSHAKE_PREFIX_CLIENT: &[u8; 2] = &[0x16, 0x03];
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const TLS_APPLICATOIN_DATA_PREFIX: &[u8; 3] = &[0x17, 0x03, 0x03];

const TLS_13_SUPPORTED_VERSIONS: &[u8; 6] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum PaddingCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
    Unknown(u8) = 0xFF,
}

impl From<u8> for PaddingCommand {
    fn from(value: u8) -> Self {
        match value {
            0 => PaddingCommand::Continue,
            1 => PaddingCommand::End,
            2 => PaddingCommand::Direct,
            v => PaddingCommand::Unknown(v),
        }
    }
}

impl From<PaddingCommand> for u8 {
    fn from(val: PaddingCommand) -> Self {
        match val {
            PaddingCommand::Continue => 0,
            PaddingCommand::End => 1,
            PaddingCommand::Direct => 2,
            PaddingCommand::Unknown(v) => v,
        }
    }
}

impl std::fmt::Display for PaddingCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaddingCommand::Continue => f.write_str("Continue"),
            PaddingCommand::End => f.write_str("End"),
            PaddingCommand::Direct => f.write_str("Direct"),
            PaddingCommand::Unknown(v) => f.write_str(format!("Unknown({})", v).as_str()),
        }
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub(crate) enum Tls13CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes128CcmSha256 = 0x1304,
    TlsAes128Ccm8Sha256 = 0x1305,
    Unknown(u16) = 0xFFFF,
}

impl std::fmt::Display for Tls13CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tls13CipherSuite::TlsAes128GcmSha256 => f.write_str("TLS_AES_128_GCM_SHA256"),
            Tls13CipherSuite::TlsAes256GcmSha384 => f.write_str("TLS_AES_256_GCM_SHA384"),
            Tls13CipherSuite::TlsChacha20Poly1305Sha256 => {
                f.write_str("TLS_CHACHA20_POLY1305_SHA256")
            }
            Tls13CipherSuite::TlsAes128CcmSha256 => f.write_str("TLS_AES_128_CCM_SHA256"),
            Tls13CipherSuite::TlsAes128Ccm8Sha256 => f.write_str("TLS_AES_128_CCM_8_SHA256"),
            Tls13CipherSuite::Unknown(v) => f.write_str(format!("Unknown({})", v).as_str()),
        }
    }
}

impl From<u16> for Tls13CipherSuite {
    fn from(v: u16) -> Self {
        match v {
            0x1301 => Tls13CipherSuite::TlsAes128GcmSha256,
            0x1302 => Tls13CipherSuite::TlsAes256GcmSha384,
            0x1303 => Tls13CipherSuite::TlsChacha20Poly1305Sha256,
            0x1304 => Tls13CipherSuite::TlsAes128CcmSha256,
            0x1305 => Tls13CipherSuite::TlsAes128Ccm8Sha256,
            v => Tls13CipherSuite::Unknown(v),
        }
    }
}

struct TrafficState {
    pub stream_id: u32,
    pub uuid: Uuid,
    pub is_uuid_written: bool,
    pub number_of_packet_to_filter: u32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: Tls13CipherSuite,
    pub remaining_server_hello: u32,

    // for writer
    pub need_padding: bool,

    // for reader
    pub within_padding_buffers: bool,
    pub remaining_content: usize,
    pub remaining_padding: usize,
    pub padding_command: PaddingCommand,
}

impl TrafficState {
    pub fn new(stream_id: u32, uuid: Uuid) -> Self {
        Self {
            stream_id,
            uuid,
            is_uuid_written: false,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: Tls13CipherSuite::Unknown(0xFFFF),
            remaining_server_hello: 0,

            need_padding: true,

            within_padding_buffers: true,
            remaining_content: 0,
            remaining_padding: 0,
            padding_command: PaddingCommand::Unknown(255),
        }
    }
}

enum ReadState {
    Reading,
    Unpadding(usize),
    Output(BytesMut, Option<BytesMut>),
}

// https://github.com/XTLS/Xray-core/discussions/1295
// https://github.com/e1732a364fed/xtls-?tab=readme-ov-file#%E6%80%BB%E7%BB%93-xtls%E7%9A%84%E5%8E%9F%E7%90%86
pub(crate) struct VisionStream {
    stream: Box<dyn ProxyStream>,
    traffic_state: TrafficState,

    // for read
    direct_read: bool,
    read_buffer: [u8; DEFAULT_BUF_SIZE],
    read_state: ReadState,

    // for write
    direct_write: bool,
    write_buffer: BytesMut,
}

impl LocalAddr for VisionStream {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.stream.local_addr()
    }
}

impl VisionStream {
    pub fn new(stream: Box<dyn ProxyStream>, id: Uuid, stream_id: u32) -> Self {
        Self {
            stream,
            traffic_state: TrafficState::new(stream_id, id),

            direct_write: false,
            write_buffer: BytesMut::new(),

            direct_read: false,
            read_buffer: [0u8; DEFAULT_BUF_SIZE],
            read_state: ReadState::Reading,
        }
    }

    pub fn as_mut_ref(&mut self) -> &mut dyn ProxyStream {
        self.stream.as_mut()
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        if this.direct_read {
            let tls_stream = this
                .stream
                .as_any_mut()
                .downcast_mut::<TlsStream>()
                .expect("tls stream");
            let tcp_stream = tls_stream.as_mut_ref();
            return Pin::new(tcp_stream).poll_read(cx, buf);
        }
        loop {
            match &mut this.read_state {
                ReadState::Reading => {
                    let mut read_buffer = ReadBuf::new(&mut this.read_buffer);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buffer)).map_err(
                        |e| {
                            log::error!("Xtls read tls error: {:#}", e);
                            e
                        },
                    )?;
                    log::debug!(
                        "{} Vision reader reads {} bytes",
                        this.traffic_state.stream_id,
                        read_buffer.filled().len()
                    );
                    if read_buffer.filled().is_empty() {
                        return Ok(()).into();
                    }
                    this.read_state = ReadState::Unpadding(read_buffer.filled().len());
                }
                ReadState::Unpadding(filled_size) => {
                    let mut buffer = BytesMut::from(&this.read_buffer[..*filled_size]);
                    let bytes_left = if this.traffic_state.within_padding_buffers
                        || this.traffic_state.number_of_packet_to_filter > 0
                    {
                        let bytes_left = xtls_unpadding(&mut buffer, &mut this.traffic_state);
                        if this.traffic_state.remaining_content > 0
                            || this.traffic_state.remaining_padding > 0
                            || this.traffic_state.padding_command == PaddingCommand::Continue
                        {
                            this.traffic_state.within_padding_buffers = true;
                        } else if this.traffic_state.padding_command == PaddingCommand::End {
                            this.traffic_state.within_padding_buffers = false;
                        } else if this.traffic_state.padding_command == PaddingCommand::Direct {
                            this.traffic_state.within_padding_buffers = false;
                            this.direct_read = true;
                            log::debug!(
                                "{} Enable direct copy for reader",
                                this.traffic_state.stream_id
                            );
                        } else {
                            log::error!(
                                "{} XtlsRead unknown command {}",
                                this.traffic_state.stream_id,
                                this.traffic_state.padding_command
                            )
                        }
                        if this.traffic_state.number_of_packet_to_filter > 0 {
                            xtls_filter_tls(&buffer, &mut this.traffic_state, "Reader");
                        }
                        bytes_left
                    } else {
                        None
                    };
                    this.read_state = ReadState::Output(buffer, bytes_left);
                }
                ReadState::Output(ref mut buffer, bytes_left) => {
                    let len = buf.remaining();
                    if len >= buffer.remaining() {
                        buf.put_slice(buffer);
                        if let Some(bytes_left) = bytes_left {
                            log::debug!(
                                "{} Xtls package has {} bytes remaining after unpadding",
                                this.traffic_state.stream_id,
                                bytes_left.len()
                            );
                            let mut read_buffer = ReadBuf::new(&mut this.read_buffer);
                            read_buffer.put_slice(bytes_left);
                            this.read_state = ReadState::Unpadding(bytes_left.len());
                            continue;
                        }
                        this.read_state = ReadState::Reading;
                        return Ok(()).into();
                    } else {
                        let buffer_left = buffer.split_off(len);
                        buf.put_slice(buffer);
                        this.read_state = ReadState::Output(buffer_left, bytes_left.clone());
                        return Ok(()).into();
                    }
                }
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    // https://github.com/XTLS/Xray-core/blob/6b6fbcb459a870c5c5cda17ed0f6886d39b9a6cf/proxy/proxy.go#L222
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();
        if this.direct_write {
            let tls_stream = this
                .stream
                .as_any_mut()
                .downcast_mut::<TlsStream>()
                .expect("tls stream");
            let tcp_stream = tls_stream.as_mut_ref();
            return Pin::new(tcp_stream).poll_write(cx, buf);
        }
        loop {
            if this.write_buffer.is_empty() {
                this.write_buffer = if this.traffic_state.need_padding {
                    if this.traffic_state.number_of_packet_to_filter > 0 {
                        xtls_filter_tls(buf, &mut this.traffic_state, "Writer");
                    }
                    // TODO:
                    // mb = ReshapeMultiBuffer(w.ctx, bytes)
                    if this.traffic_state.is_tls
                        && buf.len() >= 6
                        && *TLS_APPLICATOIN_DATA_PREFIX == buf[0..3]
                    {
                        let mut command = PaddingCommand::End;
                        if this.traffic_state.enable_xtls {
                            this.direct_write = true;
                            command = PaddingCommand::Direct;
                            log::debug!(
                                "{} Enable direct copy for writer",
                                this.traffic_state.stream_id
                            );
                        }
                        this.traffic_state.need_padding = false; // padding going to end
                        xtls_padding(buf, command, &mut this.traffic_state, true)
                    } else if !this.traffic_state.is_tls12_or_above
                        && this.traffic_state.number_of_packet_to_filter <= 1
                    {
                        // For compatibility with earlier vision receiver, we finish padding 1 packet early
                        this.traffic_state.need_padding = false;
                        let long_padding = this.traffic_state.is_tls;
                        xtls_padding(
                            buf,
                            PaddingCommand::End,
                            &mut this.traffic_state,
                            long_padding,
                        )
                    } else {
                        let long_padding = this.traffic_state.is_tls;
                        xtls_padding(
                            buf,
                            PaddingCommand::Continue,
                            &mut this.traffic_state,
                            long_padding,
                        )
                    }
                } else {
                    BytesMut::from(buf)
                };
            } else {
                let n = ready!(Pin::new(&mut this.stream).poll_write(cx, &this.write_buffer))?;
                debug_assert!(n == this.write_buffer.len());
                this.write_buffer = BytesMut::new();
                return Ok(buf.len()).into();
            }
        }
    }

    impl_asyncwrite_flush_shutdown!(stream);
}

// https://github.com/XTLS/Xray-core/blob/6b6fbcb459a870c5c5cda17ed0f6886d39b9a6cf/proxy/proxy.go#L307
fn xtls_padding(
    bytes: &[u8],
    command: PaddingCommand,
    traffic_state: &mut TrafficState,
    long_padding: bool,
) -> BytesMut {
    let content_len = bytes.len() as u32;

    let mut rng = rand::rng();
    let mut padding_len = if content_len < 900 && long_padding {
        let l: u32 = rng.random_range(..500);
        l + 900 - content_len
    } else {
        rng.random_range(..256)
    };
    if padding_len > (DEFAULT_BUF_SIZE as u32 - 21 - content_len) {
        padding_len = DEFAULT_BUF_SIZE as u32 - 21 - content_len;
    }
    let mut buf = BytesMut::with_capacity(bytes.len() + 21 + padding_len as usize);
    if !traffic_state.is_uuid_written {
        buf.put_slice(traffic_state.uuid.as_bytes());
        traffic_state.is_uuid_written = true;
    }

    buf.put_slice(&[
        command.into(),
        (content_len >> 8) as u8,
        content_len as u8,
        (padding_len >> 8) as u8,
        padding_len as u8,
    ]);
    buf.put_slice(bytes);
    buf.resize(buf.len() + padding_len as usize, 0);
    log::debug!(
        "XtlsPadding {}, {}, {}, {}",
        content_len,
        padding_len,
        buf.len(),
        command
    );
    buf
}

fn xtls_unpadding(bytes: &mut BytesMut, traffic_state: &mut TrafficState) -> Option<BytesMut> {
    if traffic_state.remaining_content == 0 && traffic_state.remaining_padding == 0 {
        if traffic_state.padding_command == PaddingCommand::Unknown(255) {
            if bytes.len() >= 21 && bytes[0..16] == *traffic_state.uuid.as_bytes() {
                bytes.advance(16);
            } else {
                log::warn!(
                    "{} Xtls Unpadding ignored packet {}",
                    traffic_state.stream_id,
                    bytes.len()
                );
                return None;
            }
        }
        traffic_state.padding_command = PaddingCommand::from(bytes[0]);
        traffic_state.remaining_content = ((bytes[1] as usize) << 8) | (bytes[2] as usize);
        traffic_state.remaining_padding = ((bytes[3] as usize) << 8) | (bytes[4] as usize);
        log::debug!(
            "{} Xtls Unpadding content: {}, padding: {}, command: {}",
            traffic_state.stream_id,
            traffic_state.remaining_content,
            traffic_state.remaining_padding,
            traffic_state.padding_command
        );
        bytes.advance(5);
    }

    let mut content_len = traffic_state.remaining_content;
    if bytes.len() < content_len {
        content_len = bytes.len();
    }
    traffic_state.remaining_content -= content_len;

    let bytes_left = if traffic_state.remaining_content == 0 {
        let mut padding_len = traffic_state.remaining_padding;
        if (bytes.len() - content_len) <= padding_len {
            padding_len = bytes.len() - content_len;
            bytes.truncate(bytes.len() - padding_len);
            traffic_state.remaining_padding -= padding_len;
            None
        } else {
            let mut bytes_left = bytes.split_off(content_len);
            let bytes_left = bytes_left.split_off(traffic_state.remaining_padding);
            traffic_state.remaining_padding = 0;
            Some(bytes_left)
        }
    } else {
        None
    };

    log::debug!(
        "{} Xtls Unpadding remaining_content: {}, remaining_padding: {}, command: {}",
        traffic_state.stream_id,
        traffic_state.remaining_content,
        traffic_state.remaining_padding,
        traffic_state.padding_command
    );

    bytes_left
}

// https://github.com/XTLS/Xray-core/blob/6b6fbcb459a870c5c5cda17ed0f6886d39b9a6cf/proxy/proxy.go#L415
fn xtls_filter_tls(bytes: &[u8], traffic_state: &mut TrafficState, src: &str) {
    log::debug!(
        "{} Xtls filter tls from {}, packge to filter {}",
        traffic_state.stream_id,
        src,
        traffic_state.number_of_packet_to_filter
    );
    traffic_state.number_of_packet_to_filter -= 1;
    if bytes.len() > 6 {
        if *TLS_HANDSHAKE_PREFIX_SERVER == bytes[0..3]
            && bytes[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            log::debug!(
                "{} XtlsFilterTls found tls server hello! from {}",
                traffic_state.stream_id,
                src
            );
            traffic_state.remaining_server_hello =
                (((bytes[3] as u32) << 8) | (bytes[4] as u32)) + 5;
            traffic_state.is_tls12_or_above = true;
            traffic_state.is_tls = true;
            if bytes.len() >= 79 && traffic_state.remaining_server_hello > 0 {
                let session_id_len = bytes[43] as usize;
                let cipher_suite = bytes
                    .get((43 + session_id_len + 1)..(43 + session_id_len + 3))
                    .expect("Get cipher suite");
                traffic_state.cipher = Tls13CipherSuite::from(
                    ((cipher_suite[0] as u16) << 8) | (cipher_suite[1] as u16),
                );
            } else {
                log::debug!(
                    "{} XtlsFilterTls found short server hello({}), tls 1.2 or older?",
                    traffic_state.stream_id,
                    traffic_state.remaining_server_hello
                );
            }
        } else if *TLS_HANDSHAKE_PREFIX_CLIENT == bytes[0..2]
            && bytes[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            traffic_state.is_tls = true;
            log::debug!(
                "{} XtlsFilterTls found tls client hello! from {}",
                traffic_state.stream_id,
                src
            );
        }
    }
    if traffic_state.remaining_server_hello > 0 {
        let mut end = traffic_state.remaining_server_hello;
        if end > bytes.len() as u32 {
            end = bytes.len() as u32;
        }
        traffic_state.remaining_server_hello -= end;
        let hello_bytes = bytes
            .get(0..(end as usize))
            .expect("Get remaining hello bytes");
        if find_str_in_str(hello_bytes, TLS_13_SUPPORTED_VERSIONS) {
            if (Tls13CipherSuite::TlsAes128Ccm8Sha256 != traffic_state.cipher)
                && !matches!(traffic_state.cipher, Tls13CipherSuite::Unknown(_))
            {
                traffic_state.enable_xtls = true;
            }
            log::debug!(
                "{} XtlsFilterTls found tls 1.3! Cipher: {}",
                traffic_state.stream_id,
                traffic_state.cipher
            );
            traffic_state.number_of_packet_to_filter = 0;
            return;
        } else if traffic_state.remaining_server_hello == 0 {
            log::debug!("{} XtlsFilterTls found tls 1.2!", traffic_state.stream_id);
            traffic_state.number_of_packet_to_filter = 0;
            return;
        }
        log::debug!(
            "{} XtlsFilterTls found inconclusive server hello, remainning size: {}",
            traffic_state.stream_id,
            traffic_state.remaining_server_hello
        );
    }
    if traffic_state.number_of_packet_to_filter == 0 {
        log::debug!(
            "{} XtlsFilterTls stop filtering {}",
            traffic_state.stream_id,
            src
        );
    }
}

#[cfg(test)]
mod test {
    use super::Tls13CipherSuite;
    #[test]
    fn test_tls13_cipher_suite_init() {
        assert_eq!(
            Tls13CipherSuite::from(0x1303),
            Tls13CipherSuite::TlsChacha20Poly1305Sha256,
        );
        assert_eq!(
            true,
            matches!(Tls13CipherSuite::from(0x11), Tls13CipherSuite::Unknown(_)),
        );
    }
}
