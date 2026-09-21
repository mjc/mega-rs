use std::time::Duration;

/// An HTTP builder with a fixed, certificate-validating TLS policy.
///
/// Uses RustCrypto when `rustls-tls` is enabled. Bundled roots are supplemented
/// by available system roots with `rustls-native-roots`. Client authentication
/// is disabled. HTTP/2 requires mega's `http2` feature; enabling it on reqwest
/// alone does not change this policy. No global crypto provider is installed.
///
/// Only supported transport settings are exposed: reqwest's TLS setters would
/// silently be ignored by its preconfigured-TLS path.
///
/// ```compile_fail
/// mega::http_client_builder().unwrap().tls_built_in_root_certs(false);
/// ```
pub struct HttpClientBuilder {
    inner: reqwest::ClientBuilder,
    #[cfg(feature = "rustls-tls")]
    tls: rustls::ClientConfig,
}

/// Creates a client-local HTTP builder with mega's TLS policy.
pub fn http_client_builder() -> crate::Result<HttpClientBuilder> {
    Ok(HttpClientBuilder {
        inner: reqwest::Client::builder(),
        #[cfg(feature = "rustls-tls")]
        tls: crate::tls::client_config()?,
    })
}

impl HttpClientBuilder {
    /// Restricts both HTTP negotiation and TLS ALPN to HTTP/1.1.
    #[must_use]
    pub fn http1_only(mut self) -> Self {
        self.inner = self.inner.http1_only();
        #[cfg(feature = "rustls-tls")]
        {
            self.tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        self
    }

    /// Disables proxy discovery.
    #[must_use]
    pub fn no_proxy(mut self) -> Self {
        self.inner = self.inner.no_proxy();
        self
    }

    /// Sets the total request timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Sets how long idle pooled connections are retained.
    #[must_use]
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.pool_idle_timeout(timeout);
        self
    }

    /// Sets the maximum idle connections per host.
    #[must_use]
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.inner = self.inner.pool_max_idle_per_host(max);
        self
    }

    /// Sets the TCP keepalive duration.
    #[must_use]
    pub fn tcp_keepalive(mut self, duration: Duration) -> Self {
        self.inner = self.inner.tcp_keepalive(duration);
        self
    }

    /// Sets the User-Agent header; invalid values fail at build time.
    #[must_use]
    pub fn user_agent(mut self, value: &str) -> Self {
        self.inner = self.inner.user_agent(value);
        self
    }

    /// Builds the client, returning configuration errors to the caller.
    pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
        #[cfg(feature = "rustls-tls")]
        let inner = self.inner.use_preconfigured_tls(self.tls);
        #[cfg(not(feature = "rustls-tls"))]
        let inner = self.inner;
        inner.build()
    }
}

#[cfg(all(test, feature = "rustls-tls"))]
mod tests {
    use super::*;

    #[test]
    fn http_policy_matches_alpn() {
        let builder = http_client_builder().unwrap();
        assert_eq!(
            builder.tls.alpn_protocols.contains(&b"h2".to_vec()),
            cfg!(feature = "http2")
        );
        let builder = builder.http1_only();
        assert_eq!(builder.tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
