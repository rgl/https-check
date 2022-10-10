use std::{time::{SystemTime, Duration}, sync::Arc, io::{self, BufReader, ErrorKind}, path::{PathBuf, Path}, fs::File, net::{ToSocketAddrs, SocketAddr, IpAddr}};

use rustls::{client::{ServerCertVerifier, ServerCertVerified}, Certificate, ServerName, PrivateKey};

struct InsecureServerCertVerifier {}

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn main() {
  let flags = xflags::parse_or_exit! {
    /// Client certificate path.
    optional --certificate certificate: PathBuf
    /// Client key path.
    optional --key key: PathBuf
    /// Server CA certificates path.
    optional --ca-certificates ca_certificates: PathBuf
    /// Do not verify the server certificate.
    optional --insecure
    /// Print response headers.
    optional --print-headers
    /// Print response body.
    optional --print-body
    /// Print response headers and body when the request fails.
    optional --print-failed
    /// Resolve the url host to the given IP address.
    optional --ip ip:IpAddr
    /// HTTP URL to test.
    required url: String
  };

  let agent = build_agent(flags.ip, flags.insecure, flags.key, flags.certificate, flags.ca_certificates);

  match agent.get(&flags.url).call() {
    Ok(response) => handle_response(response, flags.print_headers, flags.print_body, flags.print_failed),
    Err(ureq::Error::Status(_status_code, response)) => handle_response(response, flags.print_headers, flags.print_body, flags.print_failed),
    Err(err) => {
      eprintln!("ERROR {}", err);
      std::process::exit(1);
    }
  }
}

fn handle_response(response: ureq::Response, print_headers: bool, print_body: bool, print_failed: bool) {
  let status_code = response.status();
  let failed = !(200..300).contains(&status_code);

  if print_headers || (failed && print_failed) {
    println!(
      "{} {} {}",
      response.http_version(),
      response.status(),
      response.status_text());
    for h in response.headers_names() {
      println!("{}: {}", h, response.header(&h).unwrap_or_default());
    }
    println!();
  }

  let mut reader = response.into_reader();

  if print_body || (failed && print_failed) {
    io::copy(&mut reader, &mut io::stdout()).unwrap();
  } else {
    io::copy(&mut reader, &mut io::sink()).unwrap();
  }

  if failed {
    std::process::exit(1);
  }
}

fn build_agent(ip: Option<IpAddr>, insecure: bool, key: Option<PathBuf>, certificate: Option<PathBuf>, ca_certificates: Option<PathBuf>) -> ureq::Agent {
  let mut tls_config;

  if certificate.is_some() {
    let client_certificate = load_certificates(certificate.unwrap().as_path()).expect("could not load client certificate");
    let client_key = load_key(key.unwrap().as_path()).expect("could not load client key from file");
    tls_config = rustls::ClientConfig::builder()
      .with_safe_defaults()
      .with_root_certificates(load_ca_certificates(insecure, ca_certificates))
      .with_single_cert(client_certificate, client_key).expect("could not load client key");
  } else {
    tls_config = rustls::ClientConfig::builder()
      .with_safe_defaults()
      .with_root_certificates(load_ca_certificates(insecure, ca_certificates))
      .with_no_client_auth();
  }

  if insecure {
    tls_config
      .dangerous()
      .set_certificate_verifier(Arc::new(InsecureServerCertVerifier {}));
  }

  let agent = ureq::AgentBuilder::new()
    .tls_config(Arc::new(tls_config))
    .timeout_connect(Duration::from_secs(30))
    .timeout(Duration::from_secs(300))
    .redirects(0)
    .resolver(move |netloc: &str| {
      if ip.is_some() {
        match netloc.split_once(':') {
          Some((_host_s, port_s)) => {
            let addr = SocketAddr::new(
              ip.unwrap(),
              port_s.parse().expect("failed to parse netloc port"));
            Ok(vec![addr])
          }
          None => Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to parse netloc {:?}", netloc),
          ))
        }
      } else {
        netloc.to_socket_addrs().map(Iterator::collect)
      }
    })
    .build();

  return agent;
}

fn load_ca_certificates(insecure: bool, ca_certificates: Option<PathBuf>) -> rustls::RootCertStore {
  let mut root_store = rustls::RootCertStore::empty();
  if !insecure {
    if ca_certificates.is_some() {
      for cert in load_certificates(ca_certificates.unwrap().as_path()).expect("could not load ca certificates") {
        root_store.add(&cert).unwrap();
      }
    } else {
      // see https://github.com/rustls/rustls-native-certs
      for cert in rustls_native_certs::load_native_certs().expect("could not load platform certificates") {
        root_store.add(&rustls::Certificate(cert.0)).unwrap();
      }
    }
  }
  return root_store;
}

fn load_certificates(path: &Path) -> Result<Vec<Certificate>, std::io::Error> {
  let f = File::open(&path)?;
  let mut reader = BufReader::new(f);

  match rustls_pemfile::certs(&mut reader) {
    Ok(contents) => Ok(contents
      .into_iter()
      .map(Certificate)
      .collect()),
    Err(_) => Err(std::io::Error::new(
      ErrorKind::InvalidData,
      format!("Could not load certificate from file {:?}", path),
    )),
  }
}

fn load_key(path: &Path) -> Result<PrivateKey, std::io::Error> {
  let f = File::open(&path)?;
  let mut reader = BufReader::new(f);

  loop {
    match rustls_pemfile::read_one(&mut reader)? {
      Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)),
      Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
      Some(_) => {},
      None => return Err(std::io::Error::new(
        ErrorKind::InvalidData,
        format!("Could not load key from file {:?}", path),
      )),
    }
  }
}

mod built_info {
  include!(concat!(env!("OUT_DIR"), "/built.rs"));
}