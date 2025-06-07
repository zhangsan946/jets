//! Service Utilities

use futures::ready;
use std::{
    future::Future,
    io::{Error, Result},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::signal::ctrl_c;
use tokio::task::JoinHandle;

/// Wrapper of `tokio::task::JoinHandle`, which links to a server instance.
///
/// `ServerHandle` implements `Future` which will join the `JoinHandle` and get the result.
/// When `ServerHandle` drops, it will abort the task.
pub struct ServerHandle(pub JoinHandle<Result<()>>);

impl Drop for ServerHandle {
    #[inline]
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Future for ServerHandle {
    type Output = Result<()>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(res) => res.into(),
            Err(err) => Err(Error::other(err)).into(),
        }
    }
}

pub async fn create_abort_signal() -> Result<()> {
    let _ = ctrl_c().await;
    Ok(())
}
