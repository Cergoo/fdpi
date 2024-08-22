use bytes::BytesMut;
use log;
use structured_logger::{async_json::new_writer, Builder};
use std::borrow::Borrow;
use std::net::SocketAddr;
use std::error::{Error};
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use hickory_resolver::{TokioAsyncResolver};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_proto;
use hickory_proto::rr::rdata::a::A as dns_A;
use webpki_roots;
use rustls::ClientConfig;

//mod util;

const CONN_ESTABL: &[u8; 31] = b" 200 Connection Established\r\n\r\n";

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Debug, Default)]
struct HttpHead<'a> {
    command:&'a[u8], 
    domain: &'a str,
    port:   u16,
    method: &'a[u8],
} 

type Responder = (String, oneshot::Sender<Option<hickory_proto::rr::rdata::a::A>>);

fn error_handling(x: Result<()>) {
    if x.is_err() {
        log::error!("err {:?}", x); 
    }
}

async fn dns_resolver(mut rx: mpsc::Receiver<Responder>) -> Result<()> {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),);
        let client_config = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut resolver_config = ResolverConfig::cloudflare_https();
        resolver_config.set_tls_client_config(Arc::new(client_config));
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.cache_size = 1024;
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

        while let Some(domain) = rx.recv().await {
            let response = resolver.ipv4_lookup(domain.0).await?;
            let ip = response.iter().next();
            let _ = domain.1.send(ip.copied());
        }

        Ok(())
}

async fn tcp_server(tx: mpsc::Sender<Responder>) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;
    log::info!("sever start");

    loop {
        let (socket, _) = listener.accept().await?;
        let tx_new = tx.clone();
        tokio::spawn(async move {
            let e = process(socket, tx_new).await;
            error_handling(e);
        });
    }
}



fn main() {
    //Builder::with_level("info")
    //    .with_target_writer("*", new_writer(tokio::io::stdout()))
    //    .init();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let (tx, rx) = mpsc::channel::<Responder>(32);
    
    rt.spawn(async{
        let e = dns_resolver(rx).await;
        error_handling(e);

    });
    
    rt.block_on(async{ 
        let e = tcp_server(tx).await;
        error_handling(e); 
    });
}

async fn process(mut socket: TcpStream, tx: mpsc::Sender<Responder>) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let n = socket.read_buf(&mut buffer).await?;
    log::info!("read {} bytes", n);
    
    if n == 0 { 
        if !buffer.is_empty() {
            log::info!("connection reset by peer");
        }
        return Ok(());
    }
    
    let addr = parse_http_head(buffer.borrow()).map_err(|e| { log::info!("error parse http head {}", e); e})?;
    if addr.command != b"CONNECT" {
        log::error!("http command {}", std::str::from_utf8(addr.command)?); 
        return Ok(()); 
    }
    
    let (resp_tx, resp_rx) = oneshot::channel::<Option<dns_A>>();
    tx.send((addr.domain.to_string(), resp_tx)).await?;
    let ip: dns_A = resp_rx.await?.ok_or("not resolve dns to ip").map_err(|e| { log::error!("{}", e); e})? ;
    
    if ip.is_loopback() {     
        log::info!("loopback connection close");
        return Ok(()); 
    }

    let mut server_con = TcpStream::connect(SocketAddr::from((ip.octets(), addr.port))).await?;
    socket.write_all(&[addr.method,CONN_ESTABL].concat()).await?;
    split_hello_phrase(&mut socket, &mut server_con).await?;
    copy_bidirectional_with_sizes(&mut server_con, &mut socket, 128, 128).await?;
    log::info!("socket close: {:?}", server_con.peer_addr());
    
    Ok(())
}

fn parse_http_head(input: &[u8]) -> Result<HttpHead> {

        log::info!("http head: {:?}", input);

        let mut r: HttpHead = Default::default();
        let first_string = input.split(|x| *x==b'\r').next().ok_or("err")?;
        let mut it = first_string.split(|x| *x==b' ');
        r.command = it.next().ok_or("err")?;
        r.domain = std::str::from_utf8(it.next().ok_or("err")?)?;
        let addr_port = r.domain.split_once(':').unwrap_or((r.domain,"443"));
        (r.domain, r.port) = (addr_port.0, addr_port.1.parse::<u16>()?);
        r.method = it.next().ok_or("err")?;

        Ok(r)
}  

async fn split_hello_phrase(reader: &mut TcpStream, writer: &mut TcpStream) -> Result<()>{
    let mut hello_buf = [0; 16];
    let _ = reader.read(&mut hello_buf).await?;
    log::info!("[hello] {:?}", &hello_buf);
    writer.set_nodelay(true)?;
    writer.write(&hello_buf[0..1]).await?;
    writer.write(&hello_buf[1..]).await?;
    writer.set_nodelay(false)?;

    Ok(())
}