use std::net::SocketAddr;
use std::time::Duration;
use futures::future;
use hyper::body::HttpBody;
use log::info;
use tokio::io::{AsyncRead, AsyncWrite};
use vpn_libs_endpoint::core::Core;
use vpn_libs_endpoint::settings::{Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, Settings, TlsHostInfo, TlsHostsSettings};
use vpn_libs_endpoint::shutdown::Shutdown;

mod common;

async fn run_endpoint(listen_address: &SocketAddr) {
    let settings = Settings::builder()
        .listen_address(listen_address).unwrap()
        .add_listen_protocol(ListenProtocolSettings::Http1(Http1Settings::builder().build()))
        .add_listen_protocol(ListenProtocolSettings::Http2(Http2Settings::builder().build()))
        .add_listen_protocol(ListenProtocolSettings::Quic(QuicSettings::builder().build()))
        .allow_private_network_connections(true)
        .build().unwrap();

    let cert_key_file = common::make_cert_key_file();
    let cert_key_path = cert_key_file.path.to_str().unwrap();
    let hosts_settings = TlsHostsSettings::builder()
        .main_hosts(vec![TlsHostInfo {
            hostname: common::MAIN_DOMAIN_NAME.to_string(),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
        }])
        .speedtest_hosts(vec![TlsHostInfo {
            hostname: format!("speed.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
        }])
        .build().unwrap();

    let shutdown = Shutdown::new();

    let endpoint = Core::new(settings, hosts_settings, shutdown).unwrap();
    endpoint.listen().await.unwrap();
}

async fn do_get_request(io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, url: &str) -> (http::Response<hyper::Body>, usize) {
    let (mut request, conn) = hyper::client::conn::Builder::new()
        .handshake(io)
        .await.unwrap();

    let exchange = async {
        let mut response = request
            .send_request(hyper::Request::get(url).body(hyper::Body::empty()).unwrap())
            .await.unwrap();

        info!("Received response: {:?}", response);

        let mut body_length = 0;
        while let Some(chunk) = response.data().await {
            body_length += chunk.unwrap().len();
        }

        info!("Received body length: {body_length}");
        (response, body_length)
    };

    futures::pin_mut!(exchange);
    match future::select(conn, exchange).await {
        future::Either::Left((r, exchange)) => {
            info!("HTTP connection closed with result: {:?}", r);
            exchange.await
        }
        future::Either::Right((response, _)) => response,
    }
}

async fn do_post_request(io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, url: &str, content_length_mb: usize) -> http::Response<hyper::Body> {
    let (mut request, conn) = hyper::client::conn::Builder::new()
        .handshake(io)
        .await.unwrap();

    let exchange = async {
        let content_length = content_length_mb * 1024 * 1024;
        let req = hyper::Request::post(url)
            .body(hyper::Body::from(vec![0; content_length]))
            .unwrap();

        let response = request.send_request(req).await.unwrap();

        info!("Received response: {:?}", response);
        response
    };

    futures::pin_mut!(exchange);
    match future::select(conn, exchange).await {
        future::Either::Left((r, exchange)) => {
            info!("HTTP connection closed with result: {:?}", r);
            exchange.await
        }
        future::Either::Right((response, _)) => response,
    }
}

#[tokio::test]
async fn sni_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            &format!("speed.{}", common::MAIN_DOMAIN_NAME),
            &endpoint_address,
        ).await;

        const SIZE_MB: usize = 10;
        let (response, body_length) = do_get_request(
            stream,
            &format!("https://speed.{}:{}/{}mb.bin", common::MAIN_DOMAIN_NAME, endpoint_address.port(), SIZE_MB),
        ).await;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(body_length, SIZE_MB * 1024 * 1024);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn sni_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            &format!("speed.{}", common::MAIN_DOMAIN_NAME),
            &endpoint_address,
        ).await;

        const SIZE_MB: usize = 10;
        let response = do_post_request(
            stream,
            &format!("https://speed.{}:{}/upload.html", common::MAIN_DOMAIN_NAME, endpoint_address.port()),
            SIZE_MB,
        ).await;

        assert_eq!(response.status(), http::StatusCode::OK);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn path_download() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            common::MAIN_DOMAIN_NAME,
            &endpoint_address,
        ).await;

        const SIZE_MB: usize = 16;
        let (response, body_length) = do_get_request(
            stream,
            &format!("https://{}:{}/speed/{}mb.bin", common::MAIN_DOMAIN_NAME, endpoint_address.port(), SIZE_MB),
        ).await;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(body_length, SIZE_MB * 1024 * 1024);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn path_upload() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            common::MAIN_DOMAIN_NAME,
            &endpoint_address,
        ).await;

        const SIZE_MB: usize = 16;
        let response = do_post_request(
            stream,
            &format!("https://{}:{}/speed/upload.html", common::MAIN_DOMAIN_NAME, endpoint_address.port()),
            SIZE_MB,
        ).await;

        assert_eq!(response.status(), http::StatusCode::OK);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}
