//! A request body with a deadline, for a client that sends too slowly.

use hyper::body::Body;
use hyper::body::Frame;
use hyper::body::SizeHint;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use tokio::time::Instant;
use tokio::time::Sleep;
use tokio::time::sleep_until;

/// The error of a body that did not finish before its deadline.
#[derive(Debug)]
pub struct ClientTimeout;

impl fmt::Display for ClientTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the client did not send the request body in time")
    }
}

impl Error for ClientTimeout {}

/// A body that fails with `ClientTimeout` if it is not complete at `deadline`.
///
/// The deadline is for the whole body, not for each frame. When it passes,
/// the body sets a flag that the caller can read with `expired_flag`.
pub struct DeadlineBody<B> {
    inner: B,
    sleep: Pin<Box<Sleep>>,
    expired: Arc<AtomicBool>,
}

impl<B> DeadlineBody<B> {
    /// Wrap `inner`. The body fails after `deadline`.
    pub fn new(inner: B, deadline: Instant) -> Self {
        Self {
            inner,
            sleep: Box::pin(sleep_until(deadline)),
            expired: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag that is `true` after the body failed because of the deadline.
    pub fn expired_flag(&self) -> Arc<AtomicBool> {
        self.expired.clone()
    }
}

impl<B> Body for DeadlineBody<B>
where
    B: Body + Unpin,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = Box<dyn Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        if this.inner.is_end_stream() {
            return Poll::Ready(None);
        }
        if this.sleep.as_mut().poll(cx).is_ready() {
            this.expired.store(true, Ordering::SeqCst);
            return Poll::Ready(Some(Err(Box::new(ClientTimeout))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use http_body_util::Full;
    use std::time::Duration;

    /// A body that never sends a frame.
    struct Stalled;

    impl Body for Stalled {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn passes_a_body_that_finishes_before_the_deadline() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let body = DeadlineBody::new(Full::new(Bytes::from_static(b"hello")), deadline);
        let expired = body.expired_flag();

        let bytes = body.collect().await.unwrap().to_bytes();

        assert_eq!(&bytes[..], b"hello");
        assert!(!expired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fails_and_sets_the_flag_when_the_body_is_too_slow() {
        let deadline = Instant::now() + Duration::from_millis(50);
        let body = DeadlineBody::new(Stalled, deadline);
        let expired = body.expired_flag();

        let err = body.collect().await.unwrap_err();

        assert!(err.downcast_ref::<ClientTimeout>().is_some(), "got: {err}");
        assert!(expired.load(Ordering::SeqCst));
    }
}
