<div align=center><h1>mega-rs</h1></div>
<div align=center><strong>An API client library for interacting with MEGA</strong></div>

<br />

<div align="center">
  <!-- crate version -->
  <a href="https://crates.io/crates/mega">
    <img src="https://img.shields.io/crates/v/mega" alt="crates.io version" />
  </a>
  <!-- crate downloads -->
  <a href="https://crates.io/crates/mega">
    <img src="https://img.shields.io/crates/d/mega" alt="crates.io download count" />
  </a>
  <!-- crate docs -->
  <a href="https://docs.rs/mega">
    <img src="https://img.shields.io/docsrs/mega" alt="docs.rs docs" />
  </a>
  <!-- crate license -->
  <a href="https://github.com/Hirevo/mega-rs#license">
    <img src="https://img.shields.io/crates/l/mega" alt="crate license" />
  </a>
</div>

About
-----

This is an (unofficial) API client library for interacting with MEGA's API using Rust.  

This library aims to implement most (if not all) interactions with MEGA's API in pure Rust.  

This allows Rust applications to access MEGA without needing to depend on the [MEGAcmd] command-line tool being installed on the host system.  

It can also allow for more fine-grained control over how the operations are carried-out, like downloading nodes concurrently.  

[MEGAcmd]: https://github.com/meganz/MEGAcmd

Development
-----------

Enter the reproducible development environment with:

```sh
devenv shell
```

Run the standard checks with:

```sh
devenv tasks run check:all
```

Features
--------

> All features marked as not yet implemented are ideas of things that could be done, and not necessarily an indication of it currently being worked on.

> These are also non-exhaustive, so if there is a feature that you'd like to see done, feel free to open an issue to show your interest in it, regardless of whether it is mentionned in this list or not.

> If you wish to contribute to this project, feel free to use this list to see if there is something you would be interested to either work on, or simply sharing some of your knowledge on how it could be achieved.

- [x] Login with MEGA
  - [x] MFA support
  - [x] Session resumption (deserialization)
  - [x] Session serialization
- [x] Get storage quotas
- [x] Listing nodes
- [x] Downloading nodes
- [x] Uploading nodes
- [x] Creating folders
- [x] Renaming, moving and deleting nodes
- [x] Timeout support
- [x] Retries (exponential-backoff) support
- [x] Downloading thumbnails and preview images
- [x] Uploading thumbnails and preview images
- [x] Listing and downloading from public shared links
- [x] Listing and downloading from password-protected shared links
- [ ] Creating public shared links to owned nodes
- [ ] Creating password-protected shared links to owned nodes
- [ ] Support for privately-shared nodes (direct shares between MEGA contacts)
- [x] Server-to-Client events support

Examples
--------

You can see examples of how to use this library by looking at [**the different examples available**](https://github.com/Hirevo/mega-rs/tree/main/examples).

TLS backend selection
---------------------

- The default feature set enables the `rustls-tls` feature, so reqwest uses Rustls with the RustCrypto cryptography provider and Mozilla's bundled root certificates. RustCrypto is experimental; see its upstream warning before using this backend for security-sensitive production deployments.
- Construct clients through the fallible helper below. It supplies a client-local RustCrypto configuration without installing a process-global provider. Direct `reqwest::Client::new()` requires the caller to configure its own provider.

  ```rust
  let http_client = mega::http_client_builder()?.build()?;
  ```

- To additionally trust certificates from the operating system's certificate store when they are available, enable `rustls-native-roots`. This keeps Rustls and RustCrypto as the TLS implementation and retains the bundled roots as a fallback:

  ```bash
  cargo build --features "rustls-native-roots"
  ```

  With `--no-default-features`, enable any additional crate features you need explicitly. For example, use `--features "rustls-native-roots,parallel"` to use system roots with parallel downloads. `reqwest` remains a transitive dependency of the TLS backend features.

The provider is vendored at upstream revision `70f76c039e587192688af18a80d5d6435dedaf22` because the published alpha still depends on the obsolete webpki 0.102 branch. Its unmaintained `paste` macro dependency is replaced with `pastey`; see [provenance and local changes](vendor/rustls-rustcrypto/LOCAL-CHANGES.md). The helper disables client authentication and rejects private-key loading. Its RSA dependency is used for public-key signature verification only; the RSA private-operation timing advisory remains unresolved upstream and is explicitly excepted in dependency checks for this usage. Do not reuse that exception for RSA signing or decryption. Transport and certificate validation failures are returned as errors.

The helper exposes only supported transport settings. TLS trust and protocol settings cannot be changed through reqwest setters that would silently be ignored. HTTP/2 requires mega's `http2` feature; `.http1_only()` restricts both HTTP negotiation and TLS ALPN.

License
-------

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (LICENSE-MIT or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
