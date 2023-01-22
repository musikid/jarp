#[derive(Debug)]
pub enum ChannelError {
    Io(std::io::Error),
    Rayon(rayon::ThreadPoolBuildError),
    NoInterface,
    IpNet(ipnetwork::IpNetworkError),
    NeverReceived,
    NeverSent,
}

impl From<std::io::Error> for ChannelError {
    fn from(e: std::io::Error) -> Self {
        ChannelError::Io(e)
    }
}

impl From<ipnetwork::IpNetworkError> for ChannelError {
    fn from(e: ipnetwork::IpNetworkError) -> Self {
        ChannelError::IpNet(e)
    }
}

impl From<rayon::ThreadPoolBuildError> for ChannelError {
    fn from(e: rayon::ThreadPoolBuildError) -> Self {
        ChannelError::Rayon(e)
    }
}

pub type NetResult<T> = Result<T, ChannelError>;
