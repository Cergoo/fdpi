use bytes::BytesMut;
use log;
//use structured_logger::{async_json::new_writer, Builder};
use std::{
    borrow::Borrow,
    net::{SocketAddr, IpAddr, AddrParseError},
    error::{Error},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot}
};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use hickory_proto;
use hickory_proto::rr::rdata::a::A as dns_A;
use webpki_roots;
use rustls::ClientConfig;
use clap::Parser;
use pretty_env_logger;

//mod util;

#[derive(Parser)]
#[command(name = "fdpi")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Listen address
    #[arg(short, long, default_value_t = [127,0,0,1].into(), value_parser =  str_to_ip)]
    addr: IpAddr,
    /// Network port to use
    #[arg(short, long, default_value_t = 8080, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Log mode disable
    #[arg(short, long, default_value_t = false,)]
    nolog: bool,
    /// fuckdpi split pos [example: -s1 -s4] range 0..64
    #[arg(short, long, value_parser = clap::value_parser!(u8).range(0..64))]
    split: Vec<u8>,
    /// fuckdpi disorder pos [example: -d9 -d14] range 0..64
    #[arg(short, long, value_parser = clap::value_parser!(u8).range(0..64))]
    disorder: Vec<u8>,
}


fn str_to_ip(i: &str) -> std::result::Result<IpAddr, AddrParseError> {
    i.parse()
}


const CONN_ESTABL: &[u8; 31] = b" 200 Connection Established\r\n\r\n";
const CONN_CLOSE: &[u8; 38]  = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Default)]
struct HttpHead<'a> {
    command:&'a[u8], 
    domain: &'a str,
    port:   u16,
    method: &'a[u8],
} 

type Responder = (String, oneshot::Sender<Option<hickory_proto::rr::rdata::a::A>>);

#[derive(Debug, Clone, Copy)]
enum FdpiMethod {
    Split(u8),
    Disorder(u8),
}

/*
impl std::ops::Sub for FdpiMethod {
    type Output = Self;
    fn sub(self, other: Self) -> Self::Output {
        let (x1, x2) = (unboxing(*self), unboxing(*other))
        let r:u8 =
        math self {
            FdpiMethod::Split(x) => x - unboxing(other)
        } 
    }
}
*/



fn unboxing(i: FdpiMethod) -> u8 {
     match i  { FdpiMethod::Split(x) | FdpiMethod::Disorder(x) => x }
}

impl PartialEq for FdpiMethod {
    fn eq(&self, other: &Self) -> bool {
        let (x1, x2) = (unboxing(*self), unboxing(*other));
        x1==x2
    }
}
impl Eq for FdpiMethod {}

impl Ord for FdpiMethod {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let (x1, x2) = (unboxing(*self), unboxing(*other));
        x1.cmp(&x2)
    }
}
impl PartialOrd for FdpiMethod {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn prepar_fdpi_command(split: &[u8], disorder: &[u8]) -> Vec<FdpiMethod>{
    let len = std::cmp::max(split.len(), disorder.len());
    let mut v = Vec::<FdpiMethod>::with_capacity(len+1); 

    split.iter().copied().for_each(|x| { 
            let x = FdpiMethod::Split(x);
            if !v.contains(&x) { v.push(x); };
            });  

    disorder.iter().copied().for_each(|x| { 
            let x = FdpiMethod::Disorder(x);
            if !v.contains(&x) { v.push(x); };
            });
    v.sort();

    let mut l = 0;
    //v.iter().copied().for_each(move|x| { (x, l) = (x-l, x); x}).collect()
    v 
}

fn error_handling(x: Result<()>) {
    if x.is_err() {
        log::trace!("err {:?}", x); 
    }
}

async fn dns_resolver(mut rx: mpsc::Receiver<Responder>) -> Result<()> {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),);
        let client_config = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut resolver_config = ResolverConfig::cloudflare_https();
        //resolver_config.set_tls_client_config(Arc::new(client_config));
        resolver_config.set_tls_client_config(Arc::new(client_config));
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.cache_size = 1024;
        resolver_opts.edns0 = true;
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

        while let Some(domain) = rx.recv().await {
            let response = resolver.ipv4_lookup(domain.0).await?;
            let ip = response.iter().next();
            let _ = domain.1.send(ip.copied());
        }

        Ok(())
}

async fn tcp_server(tx: mpsc::Sender<Responder>, addr: SocketAddr, fdpi_methods: Vec<FdpiMethod>) -> Result<()> {
    // counter
    let num_conns: Arc<AtomicU64> = Default::default();
    let listener = TcpListener::bind(addr).await?;
    log::trace!("sever start");
    
    loop {
        let (mut socket, _) = listener.accept().await?;
        let tx_new = tx.clone();
        num_conns.fetch_add(1, Ordering::SeqCst);
        let num_conns = num_conns.clone();
        let fdpi_methods = fdpi_methods.clone();
        tokio::spawn(async move {
            let e = process(&mut socket, tx_new, fdpi_methods).await;
            error_handling(e);
            let _ = socket.write(CONN_CLOSE).await;
            //let _ = socket.shutdown().await;
            num_conns.fetch_sub(1, Ordering::SeqCst);
            log::info!("count opened sockets: {}", num_conns.load(Ordering::SeqCst));
        });
    }
}

fn main() {
    let cli = Cli::parse();
    let fdm = prepar_fdpi_command(&cli.split, &cli.disorder); 
    let log_level = if cli.nolog { "off" } else { "DEBUG" };

    println!("{:?}", fdm);

    log::set_max_level(log::LevelFilter::Trace);
    
    //Builder::with_level("5")
    //    .with_target_writer("*", new_writer(tokio::io::stdout()))
    //    .init();
    
    pretty_env_logger::init();
    log::error!("error");
    log::warn!("warn");
    log::info!("info");
    log::debug!("debug");
    log::trace!("trace");
    log::info!("such information");
    log::warn!("o_O");
    log::error!("much error");
    log::trace!("much error1");


    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let (tx, rx) = mpsc::channel::<Responder>(16);
    let addr = SocketAddr::from((cli.addr, cli.port));
    
    rt.spawn(async{
        let e = dns_resolver(rx).await;
        error_handling(e);

    });
    
    rt.block_on(async{ 
        let e = tcp_server(tx, addr, fdm).await;
        error_handling(e); 
    });
}

async fn process(mut socket: &mut TcpStream, tx: mpsc::Sender<Responder>, fdpi_methods: Vec<FdpiMethod>) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let n = socket.read_buf(&mut buffer).await?;
    log::trace!("read {} bytes", n);
    
    if n == 0 { 
        if !buffer.is_empty() {
            log::trace!("connection reset by peer");
        }
        return Ok(());
    }
    
    let addr = parse_http_head(buffer.borrow()).map_err(|e| { log::info!("error parse http head {}", e); e })?;
    let (resp_tx, resp_rx) = oneshot::channel::<Option<dns_A>>();
    tx.send((addr.domain.to_string(), resp_tx)).await?;
    let ip: dns_A = resp_rx.await?.ok_or("not resolve dns to ip").map_err(|e| { log::error!("{}", e); e})? ;
    
    if ip.is_loopback() {     
        log::info!("loopback connection close");
        return Ok(()); 
    }

    let mut server_con = TcpStream::connect(SocketAddr::from((ip.octets(), addr.port))).await?;

    log::trace!("create tunnel");
    socket.write_all(&[addr.method,CONN_ESTABL].concat()).await?;
    //split_hello_phrase(&mut socket, &mut server_con, fdpi_methods).await?;
    copy_bidirectional_with_sizes(&mut server_con, &mut socket, 128, 128).await?;
    log::info!("socket close: {}", addr.domain);
    
    Ok(())
}

fn parse_http_head(input: &[u8]) -> Result<HttpHead> {
        let mut r: HttpHead = Default::default();
        let first_string = input.split(|x| *x==b'\r').next().ok_or("err")?;
        log::trace!("http head: {:?}", std::str::from_utf8(first_string)?);
        let mut it = first_string.split(|x| *x==b' ');
        r.command = it.next().ok_or("err")?;
        if r.command!= b"CONNECT" { return Err("err command".into()); }
        r.domain = std::str::from_utf8(it.next().ok_or("err")?)?;
        let addr_port = r.domain.split_once(':').unwrap_or((r.domain,"443"));
        (r.domain, r.port) = (addr_port.0, addr_port.1.parse::<u16>()?);
        r.method = it.next().ok_or("err")?;

        Ok(r)
}  

async fn split_hello_phrase(reader: &mut TcpStream, writer: &mut TcpStream, fdpi_methods: Vec<FdpiMethod>) -> Result<()>{
    let mut hello_buf = [0; 64];
    let _ = reader.read(&mut hello_buf).await?;
    log::trace!("[hello] {:?}", std::str::from_utf8(&hello_buf)?);
    writer.set_nodelay(true)?;
    for i in fdpi_methods {

    } 

    writer.write(&hello_buf[0..1]).await?;
    writer.write(&hello_buf[1..]).await?;
    writer.set_nodelay(false)?;

    Ok(())
}


/*

fn multi_split<T>(idx: &[u64], v: &[T]) -> Vec<&[T]> {
    let v = Vec::with_capacity(idx.len()+1);
    for i in idx {
        v.push(v[])
    }
}

*/