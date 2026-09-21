use std::sync::Arc;

/// The provider is used only to verify remote identities. Never load private
/// signing keys: this also excludes the RSA private-operation timing advisory.
#[derive(Debug)]
struct NoPrivateKeys;

impl rustls::crypto::KeyProvider for NoPrivateKeys {
    fn load_private_key(
        &self,
        _: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Err(rustls::Error::General(
            "client authentication is unsupported".into(),
        ))
    }
}

pub(crate) fn client_config() -> crate::Result<rustls::ClientConfig> {
    let mut provider = rustls_rustcrypto::provider();
    provider.key_provider = &NoPrivateKeys;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[cfg(feature = "rustls-native-roots")]
    {
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Reqwest's preconfigured TLS path leaves ALPN to the caller.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    #[cfg(feature = "http2")]
    config.alpn_protocols.insert(0, b"h2".to_vec());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_rejects_private_keys() {
        let config = client_config().unwrap();
        assert!(!config.client_auth_cert_resolver.has_certs());
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(vec![0]).into();
        assert!(config
            .crypto_provider()
            .key_provider
            .load_private_key(key)
            .is_err());
    }

    #[tokio::test]
    async fn client_builds_without_global_provider() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        crate::http_client_builder().unwrap().build().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    }

    #[tokio::test]
    #[ignore = "requires public HTTPS access"]
    async fn rejects_invalid_server_certificates() {
        let client = crate::http_client_builder()
            .unwrap()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap();
        for url in [
            "https://expired.badssl.com/",
            "https://wrong.host.badssl.com/",
            "https://self-signed.badssl.com/",
        ] {
            let error = client.get(url).send().await.unwrap_err();
            // A timeout/DNS failure must not count as certificate validation.
            assert!(
                format!("{error:?}").contains("InvalidCertificate"),
                "{url}: {error:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires public HTTPS access"]
    async fn mega_https_handshake() {
        let response = crate::http_client_builder()
            .unwrap()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap()
            .post("https://g.api.mega.co.nz/cs")
            .json(&json::json!([{"a": "us0", "user": "tls-probe@example.invalid"}]))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body: json::Value = response.json().await.unwrap();
        assert!(body.is_array() || body.is_number());
    }
}
