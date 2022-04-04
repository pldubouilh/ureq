use crate::Error;

pub trait CertCheck: Send + Sync + 'static {
    /// Handle of the CertCheck logic.
    fn handle(&self, cert: Option<Vec<Vec<u8>>>) -> Result<(), Error>;
}

impl<F> CertCheck for F
where
    F: Fn(Option<Vec<Vec<u8>>>) -> Result<(), Error> + Send + Sync + 'static,
{
    fn handle(&self, cert: Option<Vec<Vec<u8>>>) -> Result<(), Error> {
        (self)(cert)
    }
}
