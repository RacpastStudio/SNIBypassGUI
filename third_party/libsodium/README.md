# libsodium

The build downloads and compiles libsodium 1.0.22 from its official source
archive. No precompiled library or copied headers are stored in this repository.
libsodium is distributed under the ISC license in `LICENSE`.

Upstream source:

- URL: `https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz`
- Source SHA-256: `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`

CMake verifies the source SHA-256 before invoking `build-mingw64.sh`. The output
is a static `x86_64-w64-mingw32` archive under the build tree. When
`SNIB_BUILD_TESTS=ON`, the external build also runs libsodium's upstream test
suite before the application is linked.

The Windows build environment needs the MinGW-w64 compiler on `PATH`, plus an
MSYS2 installation at `C:\msys64` with the MSYS `make` and `diffutils` packages:

```sh
pacman -S --needed make diffutils
```

Standard `HTTPS_PROXY` and `HTTP_PROXY` environment variables are honored by
CMake's download step.
