[![Build status](https://github.com/rgl/https-check/workflows/Build/badge.svg)](https://github.com/rgl/https-check/actions?query=workflow%3ABuild)

```bash
make
./target/x86_64-unknown-linux-musl/release/https-check --help
./target/x86_64-unknown-linux-musl/release/https-check \
    --print-failed \
    https://httpbin.org/status/400
```
