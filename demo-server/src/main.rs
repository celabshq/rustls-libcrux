use std::net::SocketAddr;
use std::{any::Any, sync::Arc};

use actix_web::get;
use actix_web::{
    dev::Extensions, http::header::ContentType, middleware, web, App, HttpRequest, HttpResponse,
    HttpServer,
};
use rustls::NamedGroup;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig, DEFAULT_VERSIONS,
};

static INDEX_TPL: &str = include_str!("../templates/index.html");

static SILICON_CSS: &str = include_str!("../assets/silicon.min.css");

type TlsSession = actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>;

macro_rules! static_file {
    ($content_type:literal, $body:expr) => {{
        async fn handle(_req: HttpRequest) -> HttpResponse {
            HttpResponse::Ok().content_type($content_type).body($body)
        }

        handle
    }};
}

#[get("/index.html")]
async fn index(hbs: web::Data<handlebars::Handlebars<'_>>, req: HttpRequest) -> HttpResponse {
    let named = req.conn_data::<NamedGroup>().unwrap();
    let group_name = named_group_string(named);

    let is_pq = *named == NamedGroup::X25519MLKEM768;

    #[derive(serde::Serialize)]
    struct Data {
        group_name: String,
        is_pq: bool,
    }

    match hbs.render("index", &Data { group_name, is_pq }) {
        Ok(body) => HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(body),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if let Err(err) = real_main().await {
        println!("error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

async fn real_main() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let args: Vec<String> = std::env::args().collect();
    let args: [String; 4] = args
        .try_into()
        .map_err(|args: Vec<_>| Error::WrongArgumentCount(args.len()))?;

    let [_, bind_addrs, cert_file_path, key_file_path] = args;

    let bind_addrs: Vec<_> = bind_addrs
        .split(',')
        .map(str::parse::<SocketAddr>)
        .collect::<Result<_, _>>()
        .unwrap();

    let config = load_rustls_config(&key_file_path, &cert_file_path)?;

    let mut hbs = handlebars::Handlebars::new();
    hbs.register_template_string("index", INDEX_TPL).unwrap();

    let hbs_ref = web::Data::new(hbs);

    log::info!("starting HTTPS server.");
    for bind_addr in &bind_addrs {
        log::info!("  binding on {bind_addr:?}");
    }

    HttpServer::new(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_data(hbs_ref.clone())
            // register simple handler, handle all methods
            .service(web::resource("/silicon.min.css").to(static_file!("text/css", SILICON_CSS)))
            .service(web::redirect("/", "/index.html"))
            .service(index)
    })
    .on_connect(extract_kx_group)
    .bind_rustls_0_23(bind_addrs.as_slice(), config)
    .map_err(Error::RustlsBind)?
    .run()
    .await
    .map_err(Error::RustlsRun)
}

/// Extracts the named group used to connect and stored it in the extensions of the _connection_
/// (not the request!)
fn extract_kx_group(session: &dyn Any, extensions: &mut Extensions) {
    let (_, conn) = session.downcast_ref::<TlsSession>().unwrap().get_ref();
    let group = conn.negotiated_key_exchange_group().unwrap();
    extensions.insert(group.name());
}

fn load_rustls_config(key_file_path: &str, cert_file_path: &str) -> Result<ServerConfig, Error> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(cert_file_path)
        .map_err(Error::LoadCertFile)?
        .collect();
    let certs = certs.map_err(Error::LoadCertFile)?;

    let private_key = PrivateKeyDer::from_pem_file(key_file_path).map_err(Error::LoadKeyFile)?;

    ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .map_err(Error::BuildServerConfig)?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(Error::BuildServerConfig)
}

#[derive(Debug)]
enum Error {
    WrongArgumentCount(usize),
    LoadCertFile(rustls::pki_types::pem::Error),
    LoadKeyFile(rustls::pki_types::pem::Error),
    BuildServerConfig(rustls::Error),
    RustlsBind(std::io::Error),
    RustlsRun(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrongArgumentCount(argc) => {
                write!(f, "expected 3 arguments (incl arg 0), got {argc}")
            }
            Error::LoadCertFile(e) => write!(f, "error loading cert file: {e}"),
            Error::LoadKeyFile(e) => write!(f, "error loading key file: {e}"),
            Error::BuildServerConfig(e) => write!(f, "error building server config: {e}"),
            Error::RustlsBind(e) => write!(f, "failed binding: {e}"),
            Error::RustlsRun(e) => write!(f, "server aborted: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::WrongArgumentCount(_) => None,
            Error::LoadCertFile(e) => Some(e),
            Error::LoadKeyFile(e) => Some(e),
            Error::BuildServerConfig(e) => Some(e),
            Error::RustlsBind(e) => Some(e),
            Error::RustlsRun(e) => Some(e),
        }
    }
}

fn named_group_string(group: &NamedGroup) -> String {
    match group {
        NamedGroup::X25519MLKEM768 => "Hybrid_ML-KEM_X25519".to_string(),
        other => format!("{other:?}"),
    }
}
