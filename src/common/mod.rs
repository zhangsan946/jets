pub mod log;

use serde::de::{value, Deserialize, IntoDeserializer};
use serde::ser::Serialize;
pub use shadowsocks::relay::Address;
//pub use shadowsocks::relay::tcprelay::utils::copy_bidirectional;
use std::io::{Error, ErrorKind, Result};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite};

/// shadowsocks-rust, xray and tokio copy_bidirectional method all use 8k buffer
pub const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// https://github.com/shadowsocks/shadowsocks-rust/blob/c02d2edbff27d8be4cf542c3c3cd0fc6a059c8bd/crates/shadowsocks/src/relay/udprelay/mod.rs#L66-L70
/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub const TCP_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn invalid_input_error<T: ToString>(message: T) -> Error {
    Error::new(ErrorKind::InvalidInput, message.to_string())
}

pub fn invalid_data_error<T: ToString>(message: T) -> Error {
    Error::new(ErrorKind::InvalidData, message.to_string())
}

pub fn from_str<'a, T: Deserialize<'a>>(s: &'a str) -> Result<T> {
    // https://docs.rs/serde/latest/serde/de/value/index.html
    let result =
        T::deserialize(s.into_deserializer()).map_err(|_: value::Error| invalid_input_error(s))?;
    Ok(result)
}

pub fn to_string<T: ?Sized + Serialize + std::fmt::Display>(value: &T) -> String {
    value.to_string()
}

// find substr in bytes
// https://users.rust-lang.org/t/finding-a-u8-n-u8-in-a-vec-u8/87648
pub fn find_str_in_str(src: &[u8], target: &[u8]) -> bool {
    src.windows(target.len()).any(|w| w == target)
}

// https://github.com/tokio-rs/tokio/blob/365269adaf6ec75743c0693f2378c3c6d04f806b/tokio/src/time/instant.rs#L57-L63
#[inline]
pub fn far_future_instant() -> Instant {
    Instant::now() + Duration::from_secs(86400 * 365 * 30)
}

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let size: usize = DEFAULT_BUF_SIZE;
    copy_bidirectional_with_sizes(a, b, size, size).await
}

#[macro_export]
macro_rules! impl_asyncwrite_flush_shutdown {
    ($stream:tt) => {
        fn poll_flush(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.$stream), ctx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.$stream), ctx)
        }
    };
}

#[macro_export]
macro_rules! impl_display {
    ($type:tt) => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.serialize(f)
            }
        }
    };
}

#[macro_export]
macro_rules! pre_check_addr {
    ($addr:expr) => {
        match $addr {
            Address::DomainNameAddress(ref addr, _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    format!("{} is not resolvable yet", addr),
                ));
            }
            Address::SocketAddress(ref addr) => addr,
        }
    };
}

#[cfg(test)]
mod test {
    use super::find_str_in_str;

    #[test]
    fn test_find_str_in_str() {
        let test_str = "hello";
        let str1 = "ll";
        let str2 = "no";
        assert_eq!(true, find_str_in_str(test_str.as_bytes(), str1.as_bytes()));
        assert_eq!(false, find_str_in_str(test_str.as_bytes(), str2.as_bytes()));
    }
}
