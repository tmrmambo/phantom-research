# phantom-research

Browser TLS/HTTP fingerprint research tool built on [phantom-http](https://github.com/bywayhq/phantom).

## What it does

Sends HTTPS requests using Chrome 156's exact TLS and HTTP/2 fingerprint (via BoringSSL), then dumps the fingerprint analysis from tls.peet.ws for inspection.

## Build

Requires: Rust 1.88+, CMake, Clang/LLVM, NASM, and a C++ toolchain. BoringSSL is compiled from source during the first build.

Alternatively, download prebuilt binaries from [GitHub Actions](../../actions) artifacts.

```bash
cargo build --release
```

## Run

```bash
cargo run --release
# or use the prebuilt binary directly
./phantom-research
```
