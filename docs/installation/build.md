---
title: Local build
parent: Installation
nav_order: 23
---

# Building slipstream locally

To build slipstream locally on debian-based distros, you need the following dependencies installed:

* cmake
* git
* pkg-config
* libssl-dev
* ninja-build
* clang

Clone the slipstream repo and its submodules recursively.
This fetches slipstream, [SPCDNS](https://github.com/spc476/SPCDNS), [lua-resty-base-encoding](https://github.com/spacewander/lua-resty-base-encoding), and our [picoquic fork](https://github.com/EndPositive/slipstream-picoquic/).

```shell
$ git clone --recurse-submodules https://github.com/EndPositive/slipstream.git
```

You can then configure slipstream by running the following command:

```shell
# Configure CMake
$ cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM=ninja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -G Ninja \
  -S . \
  -B build
# Build the client and server binaries
$ cmake \
  --build build \
  --target slipstream-client slipstream-server
```

This will place the client and server binaries in the `build/` directory.
These are dynamically linked binaries against OpenSSL and GNU C.
