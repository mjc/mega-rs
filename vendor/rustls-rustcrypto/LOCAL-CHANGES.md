# Vendored provider

Source: https://github.com/RustCrypto/rustls-rustcrypto
Revision: `70f76c039e587192688af18a80d5d6435dedaf22`

The published alpha retains the obsolete webpki 0.102 dependency. This newer
upstream revision removes it and updates the RustCrypto algorithms.

Local change: replace the unmaintained `paste` dependency with `pastey` 0.2.3,
retaining the `paste` import name. Cryptographic source files are unchanged.
The upstream MIT and Apache-2.0 licenses are included alongside the source.

This provider is experimental upstream. mega uses it with client authentication
disabled and a key provider that refuses all private keys. RSA is used only for
public-key certificate verification. RUSTSEC-2023-0071 remains unresolved for
RSA private operations; the application exception must not be generalized to
other consumers of this provider.
