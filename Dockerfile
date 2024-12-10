FROM debian:bookworm-slim AS builder

WORKDIR /usr/src/app

# apt update without cache and install build-essential and cmake
RUN apt-get update && apt-get install -y build-essential cmake git pkg-config libssl-dev

COPY . .

RUN --mount=type=cache,target=/usr/src/app/cmake-cache \
    cmake -Bcmake-cache -H. && \
    cmake --build cmake-cache --target slipstream && mv cmake-cache/slipstream .

FROM debian:bookworm-slim

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y libssl3

COPY ./certs/ ./certs/

COPY --from=builder /usr/src/app/slipstream .

ENTRYPOINT ["/usr/src/app/slipstream"]
