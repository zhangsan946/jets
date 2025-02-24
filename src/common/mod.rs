use once_cell::sync::Lazy;
use shadowsocks::config::ServerType;
use shadowsocks::context::{Context, SharedContext};
pub use shadowsocks::net::{ConnectOpts, TcpStream};
pub use shadowsocks::relay::Address;
//pub use shadowsocks::relay::tcprelay::utils::copy_bidirectional;
use std::io;
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite};

pub const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub static DEFAULT_CONTEXT: Lazy<SharedContext> =
    Lazy::new(|| Context::new_shared(ServerType::Local));

pub fn new_io_error<T: ToString>(message: T) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error: {}", message.to_string()),
    )
}

// find substr in bytes
// https://users.rust-lang.org/t/finding-a-u8-n-u8-in-a-vec-u8/87648
pub fn find_str_in_str(src: &[u8], target: &[u8]) -> bool {
    src.windows(target.len()).any(|w| w == target)
}

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    // TODO: to align with multibuffer
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
