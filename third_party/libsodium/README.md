# libsodium

libsodium is a dependency of the main executable only, used for the update
channel's signature and key-derivation primitives.

Nothing from libsodium is stored in this repository — no precompiled archive and
no copied headers. The build downloads the official release and verifies it, so
what the application links against is always traceable to a published artifact.
libsodium is distributed under the ISC license in `LICENSE`.

## What the build fetches

Upstream publishes a MinGW tarball alongside its Autotools sources. The build
uses the prebuilt one:

- URL: `https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-stable-mingw.tar.gz`
- SHA-256: `2dbb9fdb0882ec44a328b1f6a8fccbfa0bb0d0f5b1034f135e15827acaf6dba7`

`CMakeLists.txt` declares this through `FetchContent` with `URL_HASH` set to the
value above, so a download that does not match is rejected at configure time.
The archive is a multi-architecture drop containing `libsodium-win32/` and
`libsodium-win64/`; only the x86_64 half is referenced, as
`snib_sodium`, a `STATIC IMPORTED` target pointing at `libsodium-win64/lib/libsodium.a`
and `libsodium-win64/include`.

Standard `HTTPS_PROXY` / `HTTP_PROXY` environment variables are honored by
CMake's download step. If `download.libsodium.org` is unreachable, point the
build at a local copy of the same tarball instead by setting
`FETCHCONTENT_SOURCE_DIR_LIBSODIUM_MINGW` to a directory containing the extracted
contents; the SHA-256 check still applies to whatever URL is configured.

Because the archive is fetched at build time and only its hash is committed, the
version stays visible in review and no binary is versioned in this repository.
Do not commit the `.a` or the headers to "make the build self-contained" — that
would bind the project to an ABI with no record of where it came from.

To move to a new libsodium release, change the version and the SHA-256 in
`CMakeLists.txt` together. Getting the hash from the vendored copy of an old
download is not enough: the tarball name carries `-stable`, and upstream has
reissued such files in place before, so the hash is what actually pins the bytes.

## Why the build no longer needs MSYS2

libsodium was previously compiled from its Autotools sources by
`build-mingw64.sh`, which needed `cygpath` and GNU `make`. That made an MSYS2
installation a hard requirement at configure time, on a project that needs
neither `configure` nor `make` for anything else. The script has been removed
along with the `find_program(bash)` call that gated it, and the build now
downloads a prebuilt archive instead. Only the MinGW-w64 compiler and CMake are
required.

## `src/compat/memset_explicit.c` is required — do not delete it

The prebuilt archive is built with an older GCC toolchain than the one used
here, and its objects reference `memset_explicit` without defining it. That
symbol is C23; libsodium uses it to erase secrets in a way the optimizer is not
allowed to remove. It is not present in the MinGW runtime this project links
against, so the reference would be left unresolved.

`src/compat/memset_explicit.c` supplies it. Without that file the link fails:

```
undefined reference to `memset_explicit'
    libsodium.a(libsodium_la-utils.o):utils.c
```

Do not delete it, and do not replace it with a plain `memset` or an alias to
one. `memset` on a buffer that is about to go out of scope is dead-store
eliminated, which would silently drop the erasure of key material — the exact
guarantee libsodium is using the function for. The compatibility layer exists to
preserve that guarantee, not merely to satisfy the linker.

A previous from-source build masked this: a current GCC happens to provide the
symbol itself, so the reference resolved by accident and the file looked like
defensive extra. It is not optional now that the archive is prebuilt.
