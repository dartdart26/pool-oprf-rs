use pool_oprf::client::ClientError;
use pool_oprf::server::ServerError;

/// Errors from a PSI run.
#[derive(Debug, thiserror::Error)]
pub enum PsiError {
    #[error("the OPRF client failed")]
    Oprf(#[from] ClientError),
    #[error("the OPRF server failed")]
    OprfServer(#[from] ServerError),
    #[error("establishing a stream failed")]
    Connection(#[from] cryprot_net::ConnectionError),
    #[error("sending or receiving a message failed")]
    Io(#[from] std::io::Error),
    #[error("peer closed the stream unexpectedly")]
    UnexpectedClose,
    #[error("the client set must have at least one element")]
    EmptyClientSet,
    #[error("client set has {len} elements, the maximum is {max}")]
    ClientSetTooLarge { len: usize, max: usize },
    #[error("server set has {len} elements, the maximum is {max}")]
    ServerSetTooLarge { len: usize, max: usize },
    #[error("this session was prepared for {expected} elements, got {got}")]
    SetSizeMismatch { expected: usize, got: usize },
    #[error("peer sent a malformed message: {0}")]
    Malformed(&'static str),
}
