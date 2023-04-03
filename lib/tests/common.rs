use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Once};
use std::time::SystemTime;
use log::LevelFilter;
use rustls::{Certificate, ServerName};
use rustls::client::ServerCertVerified;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vpn_libs_endpoint::log_utils;

pub const MAIN_DOMAIN_NAME: &str = "localhost";
pub const ENDPOINT_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub static NEXT_ENDPOINT_PORT: AtomicU16 = AtomicU16::new(9128);

pub fn set_up_logger() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        log::set_max_level(LevelFilter::Trace);
        log::set_logger(log_utils::make_stdout_logger()).unwrap();
    });
}

pub fn make_endpoint_address() -> SocketAddr {
    (ENDPOINT_IP, NEXT_ENDPOINT_PORT.fetch_add(1, Ordering::Relaxed)).into()
}

pub fn make_cert_key_file() -> File {
    let file = File::new(
        std::env::temp_dir()
            .join(format!("vle-{}.pem",
                          vpn_libs_endpoint::utils::hex_dump(
                              ring::rand::generate::<[u8; 16]>(&ring::rand::SystemRandom::new())
                                  .unwrap().expose().as_slice()
                          )
            ))
    );

    std::fs::File::create(&file.path).unwrap().write_all(CERT_KEY.as_bytes()).unwrap();

    file
}

pub async fn establish_tls_connection(server_name: &str, peer: &SocketAddr) -> impl AsyncRead + AsyncWrite + Unpin {
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoopVerifier {}))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from(server_name).unwrap(),
            TcpStream::connect(peer).await.unwrap(),
        )
        .await.unwrap()
}

pub struct File {
    pub path: PathBuf,
}

impl File {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}

pub struct NoopVerifier;

impl rustls::client::ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self, _: &Certificate, _: &[Certificate], _: &ServerName, _: &mut dyn Iterator<Item=&[u8]>, _: &[u8], _: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

/// CN = [`MAIN_DOMAIN_NAME`]
const CERT_KEY: &str = "
-----BEGIN CERTIFICATE-----
MIIEYzCCA0ugAwIBAgIJAPoYqB3toabPMA0GCSqGSIb3DQEBCwUAMIGOMQswCQYD
VQQGEwJNQzERMA8GA1UECAwITXkgU3RhdGUxFDASBgNVBAcMC015IExvY2FsaXR5
MSAwHgYDVQQKDBdNeSBPcmdhbml6YXRpb24gTGltaXRlZDESMBAGA1UEAwwJbG9j
YWxob3N0MSAwHgYJKoZIhvcNAQkBFhFzdXBwb3J0QGVtYWlsLmNvbTAeFw0yMzAz
MDMxMzQ0MDVaFw0yNTExMjcxMzQ0MDVaMIGOMQswCQYDVQQGEwJNQzERMA8GA1UE
CAwITXkgU3RhdGUxFDASBgNVBAcMC015IExvY2FsaXR5MSAwHgYDVQQKDBdNeSBP
cmdhbml6YXRpb24gTGltaXRlZDESMBAGA1UEAwwJbG9jYWxob3N0MSAwHgYJKoZI
hvcNAQkBFhFzdXBwb3J0QGVtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAN109RwtqlimLcptek+vtoulGtQi7XQ8H846gpMYdNXMSmdkk/vN
Gf3t+43GEehryzQLGINZgyNmWZX+j8K3lvPuXKvbRUKa3tISj2h73+DEwfzR4/Lg
szrKdlDRi/ej9H8mo/9kdTMrK2s2Zzg4JBQmAFepR57jKVoNsj4bRL6pv1+yQcdP
U0GjS6yp+ebAeJpI8n6cNndKG+yovpAHLgwvRyF91Ds+OPco5hznSQrU71qHb0fD
XkLrlOeLrgMGrIv7Rb8APRAC2dmAkj3dNeYlggOcc1Gy2tR7eXt1maFCF7ebsxNU
WNN1lbTzLShTfv3wqghajjKpVU9/m7lQ/2sCAwEAAaOBwTCBvjAdBgNVHQ4EFgQU
zz3RamEP0LRqB/+mqrYWiSyilogwHwYDVR0jBBgwFoAUzz3RamEP0LRqB/+mqrYW
iSyilogwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwNgYDVR0RBC8wLYIJbG9jYWxo
b3N0ghVsb2NhbGhvc3QubG9jYWxkb21haW6CCTEyNy4wLjAuMTAsBglghkgBhvhC
AQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwDQYJKoZIhvcNAQEL
BQADggEBAFvQdL2bMg5OL83B6QqGlPN9qjGl/PjTlyeIliekSQpfbQe+Q0Sqq8Qc
+a8T0dxiIVIPmfhwZ3rxb6OCWAnGf1HN3Mfm8eTd2Vjn/PgoTb6n7uZVr8P2pbfO
X5mmFdG1V34sMh52GB1mhqEDxuLEDD6Y6NJaMn6TyUBcKtgU8UZGJPUy8mD3EB3u
IVt+sB6OIia5xPpDI+lZkFjY3HuqfMX6lEgV7mdkUJetkqtwLAqyDcut3oH4TVKh
dMbkIyCElsl8NJpRZSbvoCKCKRhuaxlHW4Rf5HuLcKHL0wvk/cwZa4dD9qKSLyBc
vOUVSnFoxGwBMhsbDovY1UExeGYuNTs=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDddPUcLapYpi3K
bXpPr7aLpRrUIu10PB/OOoKTGHTVzEpnZJP7zRn97fuNxhHoa8s0CxiDWYMjZlmV
/o/Ct5bz7lyr20VCmt7SEo9oe9/gxMH80ePy4LM6ynZQ0Yv3o/R/JqP/ZHUzKytr
Nmc4OCQUJgBXqUee4ylaDbI+G0S+qb9fskHHT1NBo0usqfnmwHiaSPJ+nDZ3Shvs
qL6QBy4ML0chfdQ7Pjj3KOYc50kK1O9ah29Hw15C65Tni64DBqyL+0W/AD0QAtnZ
gJI93TXmJYIDnHNRstrUe3l7dZmhQhe3m7MTVFjTdZW08y0oU3798KoIWo4yqVVP
f5u5UP9rAgMBAAECggEBALlHtBbaQe4fQqpdA/sNiM222gZoHoCkGPwiycIlsQJ7
BDkS1hjSlY90/4SzFaJ+JSmqqtyiFGyWohczPrXrgfkeERybvIuoJQpfCuqg0UMt
ext5w5wd0PY8E9c0KkWLP/DttEHlm4Su9omhn6RSnCTbUmgFMe3GIn+8e8coa1CU
CA+e2yc5XrC2Y/yiPVsyDwwvoitXLk27Cnyva04dvJKPa/ZeQWe7GQ3PD4SYzx4s
+tuy3+2MuHvKx/LkPKVBJfk7cNTtJKBmZfwlq1stK+RA+DNolhzX8d2FmMyNRDvu
OOaxBgfHhSXdtKIz8c9wCxJg1YslQ30OeiAbJ4S5IaECgYEA8v0K7nQ048pULDfa
vR3Cxkd+KOYMYFnuxVn3OaeOI2VJ6h4gboJ8Ay/vtvHhv9ir7AuvQ/Ceuexe5B4Q
GTfeMH2IoaRQeWgsjaYBFYbgSirpUMhcCeVhVf8HXyMg2MFE+WTJIchWZ19i0OAl
CYnXy+mB1IeQFbqGdF6bQoW4DPECgYEA6VDA44N9PSiKMfHqhJAIg2UuAlUapOoQ
D4S4SgMfZnzWrpDO0d4IYAvPEXKOjiK9B9fNjJ/GKE1KOISWc+5/eW0TMdAPI0gE
bxDe1Tp2JMO7sDNAB/xrOPUccpiCZJC8oeva6rUyhRiRgh4u+f+wsZkKDAf6xG4/
aM/2AzqpwhsCgYBEmz2i5hyo1E+/zGVuUCDWawkr8wg7jCjmf+hV1wFC7S5Zc/gk
O6NYIwjD1reuuzaPhx0NSbsHM733GqXg+O07M7aILSSrosYxmFVmBpb9WfBWZrvV
73X0GfWy3vA/QxJ+d/5yE2aR+VSlNSQ/9TOA14VYxI3iFLAx2yRrO+YjgQKBgQDW
belZMFfCBag9DuFCxD2OxUbrzduXBaeNG6VkIEqTntiPx3bNWwrHexLsLiTmbPbe
Zm/7djxgfehg2TqNgfyWVLD3bwj6nA23JgImZnx+fYXaAsAulsbUqjFjANeWJY+4
IVQpsi6kNFhHBgaWrXBvSP/63rqSHeEZK0gm35t1UQKBgQC/gmaQpb3w8UvQZG4p
8vrvqrZxvF0OOvnggsgpP71191naiEO3+pby/efFgutqJdXWJXuyWeg1W7loMejL
tBkmxjMw8cFLCP9o7W7QSb9XIqfCyg4dX4Fl9l1fDNX/xK2c3dlDJv6Spi1IMdFY
0GPe2vRXo0vDDFbEyL6MqgsH0w==
-----END PRIVATE KEY-----
";
