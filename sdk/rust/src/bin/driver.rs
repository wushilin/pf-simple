//! The conformance driver of the Rust SDK: the program the pf-simple
//! conformance suite runs to put the SDK through its cases. It uses only the
//! public listen/accept/dial API. See conformance/README.md.

use std::collections::HashMap;
use std::io::Write;
use std::process::exit;
use std::time::Duration;

use pfrelay::{Client, Conn, Error};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USAGE: &str = "usage:
  driver serve   --server URL --ca FILE --word WORD --target HOST:PORT [--serve-token T] [--client-token T] [--name NAME]
  driver connect --server URL --ca FILE --word WORD --listen HOST:PORT [--client-token T]
  driver check   --server URL --ca FILE --word WORD [--client-token T]
  driver version --server URL --ca FILE --serve-token T";

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    exit(code)
}

/// Exits with the code the conformance suite expects for `err`.
fn exit_for(err: &Error) -> ! {
    let code = match err {
        Error::Proto(_) => 3,
        Error::AccessDenied => 4,
        Error::Config(_) => 2,
        _ => 1,
    };
    fail(code, &err.to_string())
}

fn parse_flags(args: &[String]) -> HashMap<String, String> {
    const KNOWN: &[&str] = &["server", "ca", "word", "target", "listen", "serve-token", "client-token", "name"];
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(flag) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')) else {
            fail(2, &format!("unexpected argument {a:?}\n{USAGE}"));
        };
        let (name, value) = match flag.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => {
                let v = it.next().unwrap_or_else(|| fail(2, &format!("--{flag} needs a value\n{USAGE}")));
                (flag.to_string(), v.clone())
            }
        };
        if !KNOWN.contains(&name.as_str()) {
            fail(2, &format!("unknown flag --{name}\n{USAGE}"));
        }
        out.insert(name, value);
    }
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else { fail(2, USAGE) };
    if !matches!(cmd.as_str(), "serve" | "connect" | "check" | "version") {
        fail(2, &format!("unknown command {cmd:?}\n{USAGE}"));
    }
    let flags = parse_flags(&args[1..]);
    let get = |k: &str| flags.get(k).cloned().unwrap_or_default();
    let server = get("server");
    if server.is_empty() {
        fail(2, &format!("--server is required\n{USAGE}"));
    }
    let mut word = get("word");
    if word.is_empty() {
        word = "aaaa-bbbb-cccc".into(); // version needs none, but a client is made with one
    }
    let target = get("target");
    let mut b = Client::builder(server, word)
        .serve_token(get("serve-token"))
        .client_token(get("client-token"))
        .name(flags.get("name").cloned().unwrap_or_else(|| "conformance".into()))
        .target(target.clone())
        .agent(format!("{} conformance", pfrelay::DEFAULT_AGENT))
        .logger(|msg| eprintln!("{msg}"));
    if let Some(ca) = flags.get("ca") {
        b = b.ca_file(ca);
    }
    let client = b.build().unwrap_or_else(|e| fail(2, &e.to_string()));

    let work = async {
        match cmd.as_str() {
            "version" => {
                let info = client.probe().await.unwrap_or_else(|e| exit_for(&e));
                println!("{}", serde_json::to_string(&info).unwrap());
            }
            "check" => client.check().await.unwrap_or_else(|e| exit_for(&e)),
            "serve" => serve(&client, &target).await,
            "connect" => connect(&client, &get("listen")).await,
            _ => unreachable!(),
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap_or_else(|e| fail(1, &e.to_string()));
    tokio::select! {
        _ = work => {}
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    let _ = std::io::stdout().flush();
    exit(0);
}

fn ready(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

async fn serve(client: &Client, target: &str) {
    if target.is_empty() {
        fail(2, &format!("--target is required\n{USAGE}"));
    }
    let listener = client.listen().await.unwrap_or_else(|e| exit_for(&e));
    ready("ready");
    loop {
        let conn = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept: {e}");
                return;
            }
        };
        let target = target.to_string();
        tokio::spawn(async move {
            let tcp = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target)).await {
                Ok(Ok(t)) => t,
                _ => {
                    conn.fail("the serving side could not reach its target").await;
                    return;
                }
            };
            pipe(tcp, conn).await;
        });
    }
}

async fn connect(client: &Client, listen: &str) {
    if listen.is_empty() {
        fail(2, &format!("--listen is required\n{USAGE}"));
    }
    let ln = TcpListener::bind(listen).await.unwrap_or_else(|e| fail(1, &format!("listen: {e}")));
    let addr = ln.local_addr().unwrap_or_else(|e| fail(1, &e.to_string()));
    ready(&format!("listening {addr}"));
    loop {
        let (tcp, _) = match ln.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let client = client.clone();
        tokio::spawn(async move {
            match client.dial().await {
                Ok(conn) => pipe(tcp, conn).await,
                Err(e) => eprintln!("dial: {e}"), // dropping tcp closes it
            }
        });
    }
}

/// Copies until the source ends; the error says what failed.
async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W) -> Result<(), String> {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
    }
}

/// Copies both ways, passing on half-closes, until both directions are done
/// or one fails.
async fn pipe(tcp: TcpStream, conn: Conn) {
    let _ = tcp.set_nodelay(true);
    let (mut tr, mut tw) = tcp.into_split();
    let c = &conn;
    let up = async {
        let mut w = c;
        copy(&mut tr, &mut w).await?;
        w.shutdown().await.map_err(|e| e.to_string())
    };
    let down = async {
        let mut r = c;
        copy(&mut r, &mut tw).await?;
        tw.shutdown().await.map_err(|e| e.to_string())
    };
    tokio::pin!(up, down);
    let (mut up_done, mut down_done) = (false, false);
    let mut failure = None;
    while !(up_done && down_done) {
        let r = tokio::select! {
            r = &mut up, if !up_done => { up_done = true; r }
            r = &mut down, if !down_done => { down_done = true; r }
        };
        if let Err(e) = r {
            failure = Some(e);
            break;
        }
    }
    match failure {
        Some(e) => conn.fail(&e).await,
        None => {
            let _ = conn.close().await;
        }
    }
}
