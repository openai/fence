use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Resolution {
    pub addresses: Vec<IpAddr>,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResolveError {
    Failed,
    TimedOut,
}

pub trait Resolver {
    fn resolve(&self, hostname: &str, timeout: Duration) -> Result<Resolution, ResolveError>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

impl SystemResolver {
    fn resolve_with_lookup(
        &self,
        hostname: &str,
        timeout: Duration,
        lookup: Box<dyn FnOnce(String) -> std::io::Result<Vec<IpAddr>> + Send>,
    ) -> Result<Resolution, ResolveError> {
        let started = Instant::now();
        let hostname = hostname.to_owned();
        let (sender, receiver) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let result = lookup(hostname);
            let _ = sender.send(result);
        });

        match receiver.recv_timeout(timeout) {
            Ok(Ok(addresses)) => Ok(Resolution {
                addresses,
                elapsed: started.elapsed(),
            }),
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(ResolveError::Failed),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ResolveError::TimedOut),
        }
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, hostname: &str, timeout: Duration) -> Result<Resolution, ResolveError> {
        self.resolve_with_lookup(
            hostname,
            timeout,
            Box::new(|hostname| {
                (hostname.as_str(), 0)
                    .to_socket_addrs()
                    .map(|entries| entries.map(|entry| entry.ip()).collect::<Vec<_>>())
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_resolver_handles_literal_without_network() {
        let resolution = SystemResolver
            .resolve("127.0.0.1", Duration::from_secs(1))
            .unwrap();

        assert!(!resolution.addresses.is_empty());
        assert!(resolution.elapsed <= Duration::from_secs(1));
    }

    #[test]
    fn system_resolver_reports_invalid_local_input() {
        assert_eq!(
            SystemResolver.resolve("", Duration::from_secs(1)),
            Err(ResolveError::Failed)
        );
    }

    #[test]
    fn system_resolver_enforces_deadline_without_network() {
        let (release_sender, release_receiver) = mpsc::channel();
        let result = SystemResolver.resolve_with_lookup(
            "unused",
            Duration::ZERO,
            Box::new(move |_| {
                release_receiver.recv().unwrap();
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }),
        );

        assert_eq!(result, Err(ResolveError::TimedOut));
        release_sender.send(()).unwrap();
    }
}
