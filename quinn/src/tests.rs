use super::{
    ClientConfigBuilder, Config, Endpoint, EndpointBuilder, NewStream, ServerConfigBuilder,
};
use futures::{FutureExt, StreamExt, TryFutureExt};
use slog::{Drain, Logger, KV};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
};
use tokio;

#[test]
fn echo_v6() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    );
}

#[test]
fn echo_v4() {
    run_echo(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

#[test]
#[cfg(target_os = "linux")] // Dual-stack sockets aren't the default anywhere else.
fn echo_dualstack() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

fn run_echo(client_addr: SocketAddr, server_addr: SocketAddr) {
    let log = logger();
    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
    let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = crate::Certificate::from_der(&cert.serialize_der()).unwrap();
    let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.set_certificate(cert_chain, key).unwrap();

    let mut server = EndpointBuilder::new(Config {
        stream_window_bidi: 32,
        ..Config::default()
    });
    server.logger(log.clone());
    server.listen(server_config.build());
    let server_sock = UdpSocket::bind(server_addr).unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let (_, server_driver, mut server_incoming) = server.from_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    let mut client = Endpoint::new();
    client.logger(log.clone());
    client.default_client_config(client_config.build());
    let (client, client_driver, _) = client.bind(client_addr).unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(
        server_driver
            .map_err(|e| panic!("server driver failed: {}", e))
            .compat(),
    );
    runtime.spawn(
        client_driver
            .map_err(|e| panic!("client driver failed: {}", e))
            .compat(),
    );
    let slog = log.new(o!("side" => "Server"));
    runtime.spawn(
        Box::pin(
            async move {
                while let Some(hs) = await!(server_incoming.next()) {
                    info!(slog, "handshaking");
                    let (_, mut streams) = await!(hs.finish()).expect("server handshake failed");
                    info!(slog, "established");
                    let slog = slog.clone();
                    tokio_current_thread::spawn(
                        Box::pin(
                            async move {
                                while let Some(stream) = await!(streams.next()) {
                                    await!(echo(&slog, stream));
                                }
                            },
                        )
                        .map(|()| -> Result<(), ()> { Ok(()) })
                        .compat(),
                    );
                }
            },
        )
        .map(|()| -> Result<(), ()> { Ok(()) })
        .compat(),
    );

    let clog = log.new(o!("side" => "Client"));
    info!(clog, "connecting from {} to {}", client_addr, server_addr);
    runtime
        .block_on(
            Box::pin(
                async {
                    let hs = client.connect(&server_addr, "localhost").unwrap();
                    let (conn, _) = await!(hs.finish()).expect("client handshake failed");
                    info!(clog, "established");
                    let mut stream = await!(conn.open_bi()).expect("connection lost");
                    info!(clog, "stream opened");
                    await!(stream.send.write_all(b"foo")).expect("write error");
                    await!(stream.send.finish()).expect("connection lost");
                    info!(clog, "message sent");
                    let reply =
                        await!(stream.recv.read_to_end(usize::max_value())).expect("read error");
                    info!(clog, "message received");
                    assert_eq!(&reply[..], b"foo");
                    await!(conn.close(0, b"done"));
                },
            )
            .map(|()| -> Result<(), ()> { Ok(()) })
            .compat(),
        )
        .unwrap();
}

async fn echo(log: &Logger, stream: NewStream) {
    match stream {
        NewStream::Bi(mut stream) => {
            info!(log, "got stream");
            let data = await!(stream.recv.read_to_end(usize::max_value())).unwrap();
            info!(log, "read {} bytes", data.len());
            await!(stream.send.write_all(&data)).unwrap();
            await!(stream.send.finish()).unwrap();
            info!(log, "reply sent");
        }
        _ => panic!("only bidi streams allowed"),
    }
}

fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

struct TestDrain;

impl Drain for TestDrain {
    type Ok = ();
    type Err = io::Error;
    fn log(&self, record: &slog::Record<'_>, values: &slog::OwnedKVList) -> Result<(), io::Error> {
        let mut vals = Vec::new();
        values.serialize(&record, &mut TestSerializer(&mut vals))?;
        record
            .kv()
            .serialize(&record, &mut TestSerializer(&mut vals))?;
        println!(
            "{} {}{}",
            record.level(),
            record.msg(),
            str::from_utf8(&vals).unwrap()
        );
        Ok(())
    }
}

struct TestSerializer<'a, W>(&'a mut W);

impl<'a, W> slog::Serializer for TestSerializer<'a, W>
where
    W: io::Write + 'a,
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        write!(self.0, ", {}: {}", key, val).unwrap();
        Ok(())
    }
}
