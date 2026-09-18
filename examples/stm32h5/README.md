# embedded-tls STM32H5 example

TLS 1.3 client running on a Nucleo-H563ZI devkit, using the on-board Ethernet
port with `embassy-net` and `embedded-tls` on top of a `TcpSocket`. 

The board acquires an address over DHCP and connects to `192.168.69.100:12345`,
the same host as the std example in [`examples/embassy`](../embassy). You can
run that example's ping-pong counterpart, or any TLS 1.3 server on that
address, e.g.:

```sh
openssl s_server -accept 12345 -tls1_3 -key key.pem -cert cert.pem
```

The example uses `NoVerify`, so any certificate is accepted.

## Running

With a [probe-rs](https://probe.rs) compatible probe attached (the on-board
ST-LINK works):

```sh
cargo run --release
```
