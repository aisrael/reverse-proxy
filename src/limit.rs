//! A body that counts its bytes and fails when it is too large.

use bytes::Buf;
use hyper::body::Body;
use hyper::body::Frame;
use hyper::body::SizeHint;
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

/// The error of a body that has more bytes than the limit.
#[derive(Debug)]
pub struct BodyTooLarge {
    /// The limit in bytes.
    pub limit: u64,
}

impl fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the body is larger than the limit of {} bytes",
            self.limit
        )
    }
}

impl Error for BodyTooLarge {}

/// A body that fails with `BodyTooLarge` when it has more than `limit` bytes.
///
/// The body counts the bytes of the data frames while it streams. It does not
/// keep the data. It does not count the trailers. When the limit is passed, the
/// body sets a flag that the caller can read with `exceeded_flag`, and it does
/// not read more frames from the inner body.
pub struct LimitBody<B> {
    inner: B,
    limit: Option<u64>,
    seen: u64,
    exceeded: Arc<AtomicBool>,
}

impl<B> LimitBody<B> {
    /// Wrap `inner`. `limit` is the largest number of bytes. `None` means no
    /// limit.
    pub fn new(inner: B, limit: Option<u64>) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            exceeded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag that is `true` after the body failed because of the limit.
    pub fn exceeded_flag(&self) -> Arc<AtomicBool> {
        self.exceeded.clone()
    }
}

impl<B> Body for LimitBody<B>
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
        if let Some(limit) = this.limit
            && this.exceeded.load(Ordering::SeqCst)
        {
            return Poll::Ready(Some(Err(Box::new(BodyTooLarge { limit }))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(limit), Some(data)) = (this.limit, frame.data_ref()) {
                    this.seen = this.seen.saturating_add(data.remaining() as u64);
                    if this.seen > limit {
                        this.exceeded.store(true, Ordering::SeqCst);
                        return Poll::Ready(Some(Err(Box::new(BodyTooLarge { limit }))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
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
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;

    /// A body with chunks of these sizes. It counts how many chunks the reader
    /// took.
    struct Chunks {
        sizes: std::vec::IntoIter<usize>,
        taken: Arc<AtomicUsize>,
    }

    fn chunks(sizes: Vec<usize>, taken: Arc<AtomicUsize>) -> Chunks {
        Chunks {
            sizes: sizes.into_iter(),
            taken,
        }
    }

    impl Body for Chunks {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            let next = self.sizes.next();
            Poll::Ready(next.map(|size| {
                self.taken.fetch_add(1, Ordering::SeqCst);
                Ok(Frame::data(Bytes::from(vec![b'x'; size])))
            }))
        }
    }

    #[tokio::test]
    async fn passes_a_body_below_the_limit() {
        let body = LimitBody::new(Full::new(Bytes::from(vec![b'x'; 10])), Some(1024));
        let exceeded = body.exceeded_flag();

        let bytes = body.collect().await.unwrap().to_bytes();

        assert_eq!(bytes.len(), 10);
        assert!(!exceeded.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn passes_a_body_of_exactly_the_limit() {
        let body = LimitBody::new(Full::new(Bytes::from(vec![b'x'; 1024])), Some(1024));
        let exceeded = body.exceeded_flag();

        let bytes = body.collect().await.unwrap().to_bytes();

        assert_eq!(bytes.len(), 1024);
        assert!(!exceeded.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fails_and_sets_the_flag_when_the_body_is_one_byte_too_large() {
        let body = LimitBody::new(Full::new(Bytes::from(vec![b'x'; 1025])), Some(1024));
        let exceeded = body.exceeded_flag();

        let err = body.collect().await.unwrap_err();

        let too_large = err.downcast_ref::<BodyTooLarge>().expect("wrong error");
        assert_eq!(too_large.limit, 1024);
        assert!(exceeded.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn counts_the_bytes_of_all_frames() {
        let taken = Arc::new(AtomicUsize::new(0));
        let body = LimitBody::new(chunks(vec![400, 400, 400], taken), Some(1024));
        let exceeded = body.exceeded_flag();

        let err = body.collect().await.unwrap_err();

        assert!(err.downcast_ref::<BodyTooLarge>().is_some());
        assert!(exceeded.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn does_not_read_more_frames_after_the_limit() {
        let taken = Arc::new(AtomicUsize::new(0));
        let mut body = LimitBody::new(chunks(vec![600, 600, 600, 600], taken.clone()), Some(1024));

        assert!(body.frame().await.unwrap().is_ok());
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.unwrap().is_err());

        assert_eq!(taken.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn never_fails_without_a_limit() {
        let body = LimitBody::new(Full::new(Bytes::from(vec![b'x'; 100_000])), None);
        let exceeded = body.exceeded_flag();

        let bytes = body.collect().await.unwrap().to_bytes();

        assert_eq!(bytes.len(), 100_000);
        assert!(!exceeded.load(Ordering::SeqCst));
    }
}
