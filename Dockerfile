FROM debian:bookworm-slim AS development

WORKDIR /usr/src/app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    ninja-build \
    gdb-multiarch

FROM development AS builder

COPY . .

RUN --mount=type=cache,target=/usr/src/app/cmake-cache \
    cmake -Bcmake-cache -H. -DCMAKE_BUILD_TYPE=Release && \
    cmake --build cmake-cache --target slipstream && mv cmake-cache/slipstream .

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
