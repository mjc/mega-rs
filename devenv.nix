{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    cargo-audit
    cargo-deny
    cargo-nextest
    gh
    openssl
    pkg-config
  ];

  tasks."check:fmt".exec = "cargo fmt --all -- --check";
  tasks."check:test".exec = "cargo test --all-features --locked";
  tasks."check:nextest".exec = "cargo nextest run --all-features --locked";
  tasks."check:dependencies".exec = "./scripts/check-dependencies.sh";
  tasks."check:all".exec = ''
    cargo fmt --all -- --check
    cargo test --all-features --locked
    ./scripts/check-dependencies.sh
  '';
}
