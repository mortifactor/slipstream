# Slipstream
![GitHub Release](https://img.shields.io/github/v/release/EndPositive/slipstream?include_prereleases&sort=semver&display_name=tag)
![GitHub License](https://img.shields.io/github/license/EndPositive/slipstream)

A high-performance covert channel over DNS, powered by QUIC multipath.

<p align="center">
  <picture align="center">
    <source media="(prefers-color-scheme: dark)" srcset="docs/file_transfer_times_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/file_transfer_times_light.png">
    <img alt="Shows a bar chart with benchmark results." src="docs/file_transfer_times_light.png">
  </picture>
</p>

<p align="center">
  <i>Exfiltrating a 10 MB file over a single DNS resolver.</i>
</p>

## Highlights

* Adaptive congestion control for rate-limited resolvers
* Parallel routing over multiple multiple rate-limited resolvers
* 60% lower header overhead than DNSTT

## Installation

Get the latest binaries [GitHub releases](https://github.com/EndPositive/slipstream/releases/latest) or pull the latest version from the [GitHub Container Registry](https://github.com/users/EndPositive/packages?repo_name=slipstream).

## Usage

```
Usage: slipstream-server [OPTION...] 
slipstream-server - A high-performance covert channel over DNS (server)

  -a, --target-address=ADDRESS   Target server address (default:
                             127.0.0.1:5201)
  -c, --cert=CERT            Certificate file path (default: certs/cert.pem)
  -d, --domain=DOMAIN        Domain name this server is authoritative for
                             (Required)
  -k, --key=KEY              Private key file path (default: certs/key.pem)
  -l, --dns-listen-port=PORT DNS listen port (default: 53)
```
```
Usage: slipstream-client [OPTION...] 
slipstream-client - A high-performance covert channel over DNS (client)

  -c, --congestion-control=ALGO   Congestion control algorithm (bbr, dcubic)
                             (default: dcubic)
  -d, --domain=DOMAIN        Domain name used for the covert channel (Required)
                            
  -g, --gso[=BOOL]           GSO enabled (true/false) (default: false). Use
                             --gso or --gso=true to enable.
  -l, --tcp-listen-port=PORT Listen port (default: 5201)
  -r, --resolver=RESOLVER    Slipstream server resolver address (e.g., 1.1.1.1
                             or 8.8.8.8:53). Can be specified multiple times.
                             (Required)
```

## Quickstart

### Server setup

The server listens for DNS messages and attempts to decode QUIC message from them.
Any new QUIC streams opened will be forwarded to a specified TCP service.
For example, we can start a simple nc listener and configure the slipstream server to connect to it.

```shell
$ nc -l -p 5201
$ slipstream-server \
  --dns-listen-port=8853 \
  --cert=certs/cert.pem \
  --key=certs/key.pem \
  --target-address=127.0.0.1:5201 \
  --domain=test.com
```

### Client setup

The client listens on a TCP port for incoming connections.
It opens a QUIC connection through the resolver specified.
For every TCP connection it accepts, a new QUIC stream will be opened.
In this example, we connect to the slipstream server running on port 8853.

```shell
$ slipstream-client \
  --tcp-listen-port=7000 \
  --resolver=127.0.0.1:8853 \
  --domain=test.com
Adding 127.0.0.1:8853
Starting connection to 127.0.0.1
Initial connection ID: 54545454
Listening on port 7000...
Connection completed, almost ready.
Connection confirmed.
```

### Usage

You can then connect to the slipstream client on port 7000 as if you were connecting to the nc client on port 5201.

```shell
$ base64 /dev/urandom | head -c 5000000 | nc 127.0.0.1 7000

# slipstream client wakes up
[0:9] accept: connection
[0:9] wakeup
[0:9] activate: stream
[0:9] recv->quic_send: empty, disactivate
[0:9] wakeup
[0:9] activate: stream
[0:9] recv->quic_send: empty, disactivate
[0:9] wakeup
[0:9] activate: stream
[0:9] recv->quic_send: empty, disactivate
[0:9] recv: closed stream

# base64 data arrives on the server
S9w3u5up+c39u6vrkBtxKbSxOJA2UElczDgc3x4h3TtZtzvgMX05Ig4whEYDvY5MP8g4dJ1QsXX1
fSDm0y6mOlQ4fQhYchkyKt18fV0tpBkLrPwv6MkW+IaksKe7Qo61s3gxu2jrPBlC1yxML+rYZU93
MYNB7rFC6s3a0eHmfdsfbtBbFIF809X91fqd6gYiKPtWAHc0J5OsEyqMI3QcUGSDJd4Sw+iAC5X7
```

## Real network scenario

You can try this out on a real network (if you have permission).
First, you need to have a server outside of the network you want to escape.
For a domain name you own, setup the DNS records to point to your nameserver.
This ensures that queries for subdomains of `test.com` will be forwarded to your server.

```
test.com NS ns.test.com
ns.test.com A 12.23.34.45 
```

Then run the slipstream server on port 53 (requires elevated privileges) and instruct the client to use a real DNS resolver.

# Benchmarks

Comparison of slipstream and other existing DNS tunneling tools can be found in the [EndPositive/dns-tunneling-benchmark](https://github.com/EndPositive/dns-tunneling-benchmark) repository.

Main findings:

* 42x faster than dnstt for direct connections
* 23/19 Mbps upload/download speed for direction connections
* automatically maximizes query rate according to resolver rate-limit

# Acknowledgements

David Fifield's DNSTT and Turbo Tunnel concept has been a massive source of inspiration.
Although slipstream inherits no code, this work could not have been possible without his ideas.
