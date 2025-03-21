FROM debian:bookworm-slim AS development

WORKDIR /usr/src/app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    ninja-build \
    clang

FROM development AS builder

COPY . .

RUN cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_MAKE_PROGRAM=ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -G Ninja \
    -S /usr/src/app \
    -B /usr/src/app/cmake-build-release

RUN cmake \
    --build /usr/src/app/cmake-build-release \
    --target slipstream \
    -j 18 && mv cmake-build-release/slipstream .

FROM debian:bookworm-slim

WORKDIR /usr/src/app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    libssl3

COPY ./certs/ ./certs/

RUN mkdir -p ./qlog/

COPY --from=builder /usr/src/app/slipstream .

ENTRYPOINT ["/usr/src/app/slipstream"]
