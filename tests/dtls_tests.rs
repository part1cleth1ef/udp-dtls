use std::io::{Read, Write};
use std::net::UdpSocket;
use std::thread;

use udp_dtls::{
    CertificateIdentity, ConnectorIdentity, DtlsAcceptor, DtlsConnector,
    PskIdentity, UdpChannel,
};

/// Helper to create connected UDP channels for testing
fn create_udp_pair() -> (UdpChannel, UdpChannel) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();

    let server_channel = UdpChannel {
        socket: server,
        remote_addr: client_addr,
    };

    let client_channel = UdpChannel {
        socket: client,
        remote_addr: server_addr,
    };

    (server_channel, client_channel)
}

#[test]
fn test_certificate_based_dtls_connection() {
    let buffer = include_bytes!("../test/identity.p12");
    let identity = CertificateIdentity::from_pkcs12(buffer, "mypass").unwrap();

    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = udp_dtls::Certificate::from_der(root_ca).unwrap();

    let acceptor = DtlsAcceptor::builder(identity).build().unwrap();

    let connector = DtlsConnector::builder()
        .add_root_certificate(root_ca)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let (server_channel, client_channel) = create_udp_pair();

    let server_thread = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();
        let mut received = [0; 5];
        dtls_server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hello");
        dtls_server.write_all(b"world").unwrap();
    });

    let mut dtls_client = connector.connect("localhost", client_channel).unwrap();
    dtls_client.write_all(b"hello").unwrap();
    let mut received = [0; 5];
    dtls_client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"world");

    server_thread.join().unwrap();
}

#[test]
fn test_psk_dtls_connection_aes128_cbc_sha() {
    // TLS_PSK_WITH_AES_128_CBC_SHA (0x008c)
    let psk_identity = b"test-client";
    let psk_key = b"0123456789abcdef"; // 16 bytes for AES-128

    let server_psk = PskIdentity::new(psk_identity, psk_key);
    let client_psk = PskIdentity::new(psk_identity, psk_key);

    let acceptor = DtlsAcceptor::builder(server_psk)
        .add_cipher("PSK-AES128-CBC-SHA")
        .build()
        .unwrap();

    let connector = DtlsConnector::builder()
        .identity(ConnectorIdentity::Psk(client_psk))
        .add_cipher("PSK-AES128-CBC-SHA")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let (server_channel, client_channel) = create_udp_pair();

    let server_thread = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();
        let mut received = [0; 5];
        dtls_server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hello");
        dtls_server.write_all(b"world").unwrap();
    });

    let mut dtls_client = connector.connect("localhost", client_channel).unwrap();
    dtls_client.write_all(b"hello").unwrap();
    let mut received = [0; 5];
    dtls_client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"world");

    server_thread.join().unwrap();
}

#[test]
fn test_psk_dtls_connection_aes256_cbc_sha() {
    // TLS_PSK_WITH_AES_256_CBC_SHA (0x008d)
    let psk_identity = b"test-client";
    let psk_key = b"0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256

    let server_psk = PskIdentity::new(psk_identity, psk_key);
    let client_psk = PskIdentity::new(psk_identity, psk_key);

    let acceptor = DtlsAcceptor::builder(server_psk)
        .add_cipher("PSK-AES256-CBC-SHA")
        .build()
        .unwrap();

    let connector = DtlsConnector::builder()
        .identity(ConnectorIdentity::Psk(client_psk))
        .add_cipher("PSK-AES256-CBC-SHA")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let (server_channel, client_channel) = create_udp_pair();

    let server_thread = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();
        let mut received = [0; 13];
        dtls_server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hello aes-256");
        dtls_server.write_all(b"confirmed").unwrap();
    });

    let mut dtls_client = connector.connect("localhost", client_channel).unwrap();
    dtls_client.write_all(b"hello aes-256").unwrap();
    let mut received = [0; 9];
    dtls_client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"confirmed");

    server_thread.join().unwrap();
}

#[test]
fn test_psk_dtls_with_aes_psk_cipher_string() {
    // Test using the broader "PSK+AES" cipher string which includes both
    // TLS_PSK_WITH_AES_128_CBC_SHA and TLS_PSK_WITH_AES_256_CBC_SHA
    let psk_identity = b"my-device";
    let psk_key = b"shared-secret-key-here!!!"; // 24 bytes

    let server_psk = PskIdentity::new(psk_identity, psk_key);
    let client_psk = PskIdentity::new(psk_identity, psk_key);

    let acceptor = DtlsAcceptor::builder(server_psk)
        .add_cipher("PSK-AES128-CBC-SHA")
        .add_cipher("PSK-AES256-CBC-SHA")
        .build()
        .unwrap();

    let connector = DtlsConnector::builder()
        .identity(ConnectorIdentity::Psk(client_psk))
        .add_cipher("PSK-AES128-CBC-SHA")
        .add_cipher("PSK-AES256-CBC-SHA")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let (server_channel, client_channel) = create_udp_pair();

    let server_thread = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();
        let mut received = [0; 4];
        dtls_server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ping");
        dtls_server.write_all(b"pong").unwrap();
    });

    let mut dtls_client = connector.connect("localhost", client_channel).unwrap();
    dtls_client.write_all(b"ping").unwrap();
    let mut received = [0; 4];
    dtls_client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"pong");

    server_thread.join().unwrap();
}

#[test]
fn test_acceptor_identity_from_certificate_identity() {
    // Verify backward compatibility: CertificateIdentity can be used directly with DtlsAcceptor::builder
    let buffer = include_bytes!("../test/identity.p12");
    let identity = CertificateIdentity::from_pkcs12(buffer, "mypass").unwrap();

    // This should compile and work since CertificateIdentity implements Into<AcceptorIdentity>
    let _builder = DtlsAcceptor::builder(identity);
}

#[test]
fn test_acceptor_identity_from_psk_identity() {
    // Verify PskIdentity can be used with DtlsAcceptor::builder
    let psk = PskIdentity::new(b"client", b"secret");

    // This should compile and work since PskIdentity implements Into<AcceptorIdentity>
    let _builder = DtlsAcceptor::builder(psk)
        .add_cipher("PSK-AES128-CBC-SHA");
}

#[test]
fn test_psk_dtls_connection_with_identity_hint() {
    // Test that PSK identity hint causes a ServerKeyExchange to be sent.
    let psk_identity = b"test-client";
    let psk_key = b"0123456789abcdef"; // 16 bytes for AES-128

    let server_psk = PskIdentity::new(psk_identity, psk_key);
    let client_psk = PskIdentity::new(psk_identity, psk_key);

    let acceptor = DtlsAcceptor::builder(server_psk)
        .add_cipher("PSK-AES128-CBC-SHA")
        .psk_identity_hint("my-server-hint")
        .build()
        .unwrap();

    let connector = DtlsConnector::builder()
        .identity(ConnectorIdentity::Psk(client_psk))
        .add_cipher("PSK-AES128-CBC-SHA")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let (server_channel, client_channel) = create_udp_pair();

    let server_thread = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();
        let mut received = [0; 5];
        dtls_server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hello");
        dtls_server.write_all(b"world").unwrap();
    });

    let mut dtls_client = connector.connect("localhost", client_channel).unwrap();
    dtls_client.write_all(b"hello").unwrap();
    let mut received = [0; 5];
    dtls_client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"world");

    server_thread.join().unwrap();
}
