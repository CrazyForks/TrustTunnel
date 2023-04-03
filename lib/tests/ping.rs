use std::net::SocketAddr;
use std::time::Duration;
use futures::future;
use log::info;
use tokio::io::{AsyncRead, AsyncWrite};
use vpn_libs_endpoint::core::Core;
use vpn_libs_endpoint::settings::{Http1Settings, Http2Settings, ListenProtocolSettings, Settings, TlsHostInfo, TlsHostsSettings};
use vpn_libs_endpoint::shutdown::Shutdown;

mod common;

async fn run_endpoint(listen_address: &SocketAddr) {
    let settings = Settings::builder()
        .listen_address(listen_address).unwrap()
        .add_listen_protocol(ListenProtocolSettings::Http1(Http1Settings::builder().build()))
        .add_listen_protocol(ListenProtocolSettings::Http2(Http2Settings::builder().build()))
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
        .ping_hosts(vec![TlsHostInfo {
            hostname: format!("ping.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
        }])
        .build().unwrap();

    let shutdown = Shutdown::new();

    let endpoint = Core::new(settings, hosts_settings, shutdown).unwrap();
    endpoint.listen().await.unwrap();
}

async fn do_get_request(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, url: &str, extra_headers: &[(&str, &str)],
) -> http::Response<hyper::Body> {
    let (mut request, conn) = hyper::client::conn::Builder::new()
        .handshake(io)
        .await.unwrap();

    let mut request_builder = hyper::Request::get(url);
    for (n, v) in extra_headers {
        request_builder = request_builder.header(*n, *v);
    }

    let exchange = async {
        let response = request
            .send_request(request_builder.body(hyper::Body::empty()).unwrap())
            .await.unwrap();

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
async fn sni() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            &format!("ping.{}", common::MAIN_DOMAIN_NAME),
            &endpoint_address,
        ).await;

        let response = do_get_request(
            stream,
            &format!("https://ping.{}:{}", common::MAIN_DOMAIN_NAME, endpoint_address.port()),
            &[],
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
async fn x_ping() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            common::MAIN_DOMAIN_NAME,
            &endpoint_address,
        ).await;

        let response = do_get_request(
            stream,
            &format!("https://{}:{}", common::MAIN_DOMAIN_NAME, endpoint_address.port()),
            &[("x-ping", "1")],
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
async fn navigate() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let stream = common::establish_tls_connection(
            common::MAIN_DOMAIN_NAME,
            &endpoint_address,
        ).await;

        let response = do_get_request(
            stream,
            &format!("https://{}:{}", common::MAIN_DOMAIN_NAME, endpoint_address.port()),
            &[("sec-fetch-mode", "navigate")],
        ).await;

        assert_eq!(response.status(), http::StatusCode::OK);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}
