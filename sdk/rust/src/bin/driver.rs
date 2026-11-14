//! The conformance driver of the Rust SDK: the program the pf-simple
//! conformance suite runs to put the SDK through its cases. It uses only the
//! SDK's public API, as an application would. See conformance/README.md.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pfrelay::{Client, Conn, ConnInfo, Error, Events, Side};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USAGE: &str = "usage:
  driver serve   --server URL --ca FILE --word WORD --target HOST:PORT [--serve-token T] [--client-token T] [--name NAME] [--mode listen|forward] [--no-accept]
  driver connect --server URL --ca FILE --word WORD --listen HOST:PORT [--client-token T] [--mode listen|forward]
  driver check   --server URL --ca FILE --word WORD [--client-token T]
  driver version --server URL --ca FILE --serve-token T";

/// Defines a closed set of words: an enum that prints and parses as them.
macro_rules! words {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        enum $name { $($(#[$vm])* $variant),+ }

        impl $name {
            const ALL: &'static [$name] = &[$($name::$variant),+];
            fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
        }

        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, String> {
                Self::ALL.iter().copied().find(|w| w.as_str() == s)
                    .ok_or_else(|| format!("unknown {} {s:?}", stringify!($name).to_lowercase()))
            }
        }
    };
}

words!(
    /// What the suite asks the driver to do.
    Command { Serve = "serve", Connect = "connect", Check = "check", Version = "version" }
);
words!(
    /// How the driver uses the SDK.
    Mode {
        /// The listen/accept and dial API, with the driver's own copy loop.
        Listen = "listen",
        /// The SDK's forwarders: serve_tcp(target) and connect_tcp(listener).
        Forward = "forward",
    }
);
words!(
    /// A question on stdin while serve or connect runs.
    Query { Stats = "stats", Conns = "conns", Drop = "drop" }
);
words!(
    /// The command-line flags.
    Flag {
        Server = "server",
        Ca = "ca",
        Word = "word",
        Target = "target",
        Listen = "listen",
        ServeToken = "serve-token",
        ClientToken = "client-token",
        Name = "name",
        Mode = "mode",
        NoAccept = "no-accept",
    }
);
words!(
    /// How a closed connection ended.
    Outcome { Ok = "ok", Failed = "failed" }
);

/// A line the driver prints when the SDK reports an event.
enum Event<'a> {
    Ready,
    Listening(std::net::SocketAddr),
    Opened(&'a ConnInfo),
    Closed(&'a ConnInfo, Outcome),
    Refused(&'a pfrelay::ConnId),
    TunnelUp,
    TunnelDown,
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Ready => write!(f, "ready"),
            Event::Listening(addr) => write!(f, "listening {addr}"),
            Event::Opened(ci) => write!(f, "opened {} {}", ci.id, ci.side),
            Event::Closed(ci, outcome) => write!(f, "closed {} {} {} {outcome}", ci.id, ci.sent, ci.received),
            Event::Refused(id) => write!(f, "refused {id}"),
            Event::TunnelUp => write!(f, "tunnel up"),
            Event::TunnelDown => write!(f, "tunnel down"),
        }
    }
}

/// The answer to `stats`.
#[derive(Serialize)]
struct StatsAnswer {
    opened: u64,
    active: u64,
    failed: u64,
    sent: i64,
    received: i64,
}

/// One entry of the answer to `conns`.
#[derive(Serialize)]
struct ConnAnswer {
    id: String,
    side: Side,
    sent: i64,
    received: i64,
}

const DROP_REASON: &str = "dropped by the conformance suite";
const TARGET_UNREACHABLE: &str = "the serving side could not reach its target";
const NO_WORD: &str = "aaaa-bbbb-cccc"; // version needs none, but a client is made with one
const DEFAULT_NAME: &str = "conformance";

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("{msg}");
    exit(code)
}

fn usage(msg: &str) -> ! {
    fail(2, &format!("{msg}\n{USAGE}"))
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

/// Prints one line on stdout, whole, and flushes it.
fn say(line: impl fmt::Display) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

struct Flags(HashMap<Flag, String>);

impl Flags {
    fn parse(args: &[String]) -> Flags {
        let mut out = HashMap::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Some(text) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')) else {
                usage(&format!("unexpected argument {a:?}"));
            };
            let (name, inline) = match text.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (text, None),
            };
            let flag: Flag = name.parse().unwrap_or_else(|e: String| usage(&e));
            let value = match (flag, inline) {
                (_, Some(v)) => v,
                (Flag::NoAccept, None) => "true".into(),
                (_, None) => it.next().cloned().unwrap_or_else(|| usage(&format!("--{flag} needs a value"))),
            };
            out.insert(flag, value);
        }
        Flags(out)
    }

    fn get(&self, f: Flag) -> String {
        self.0.get(&f).cloned().unwrap_or_default()
    }

    fn required(&self, f: Flag) -> String {
        self.0.get(&f).cloned().filter(|v| !v.is_empty()).unwrap_or_else(|| usage(&format!("--{f} is required")))
    }

    fn on(&self, f: Flag) -> bool {
        self.0.get(&f).is_some_and(|v| v != "false")
    }
}

fn events(cmd: Command) -> Events {
    let ready = Arc::new(AtomicBool::new(false));
    let mut ev = Events::new()
        .on_open(|ci| say(Event::Opened(ci)))
        .on_close(|ci, err| {
            let outcome = if err.is_some() { Outcome::Failed } else { Outcome::Ok };
            say(Event::Closed(ci, outcome))
        })
        .on_refuse(|id, _| say(Event::Refused(id)));
    if cmd == Command::Serve {
        ev = ev.on_serving(move |up| {
            if up && !ready.swap(true, Ordering::AcqRel) {
                say(Event::Ready);
            }
        });
    }
    if cmd == Command::Connect {
        ev = ev.on_tunnel(|up, _| say(if up { Event::TunnelUp } else { Event::TunnelDown }));
    }
    ev
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd: Command = args.first().unwrap_or_else(|| usage("no command")).parse().unwrap_or_else(|e: String| usage(&e));
    let flags = Flags::parse(&args[1..]);
    let mode: Mode = match flags.get(Flag::Mode) {
        m if m.is_empty() => Mode::Listen,
        m => m.parse().unwrap_or_else(|e: String| usage(&e)),
    };
    let mut word = flags.get(Flag::Word);
    if word.is_empty() {
        word = NO_WORD.into();
    }
    let target = flags.get(Flag::Target);
    let name = flags.0.get(&Flag::Name).cloned().unwrap_or_else(|| DEFAULT_NAME.into());
    let mut b = Client::builder(flags.required(Flag::Server), word)
        .serve_token(flags.get(Flag::ServeToken))
        .client_token(flags.get(Flag::ClientToken))
        .name(name)
        .target(target.clone())
        .agent(format!("{} conformance", pfrelay::DEFAULT_AGENT))
        .logger(|msg| eprintln!("{msg}"))
        .events(events(cmd));
    if let Some(ca) = flags.0.get(&Flag::Ca) {
        b = b.ca_file(ca);
    }
    let client = b.build().unwrap_or_else(|e| fail(2, &e.to_string()));
    if matches!(cmd, Command::Serve | Command::Connect) {
        tokio::spawn(queries(client.clone()));
    }

    let work = async {
        match cmd {
            Command::Version => {
                let info = client.probe().await.unwrap_or_else(|e| exit_for(&e));
                say(serde_json::to_string(&info).unwrap());
            }
            Command::Check => client.check().await.unwrap_or_else(|e| exit_for(&e)),
            Command::Serve => {
                let target = flags.required(Flag::Target);
                match mode {
                    Mode::Forward => client.serve_tcp(target).await.unwrap_or_else(|e| exit_for(&e)),
                    Mode::Listen => serve(&client, &target, flags.on(Flag::NoAccept)).await,
                }
            }
            Command::Connect => {
                let ln = TcpListener::bind(flags.required(Flag::Listen))
                    .await
                    .unwrap_or_else(|e| fail(1, &format!("listen: {e}")));
                say(Event::Listening(ln.local_addr().unwrap_or_else(|e| fail(1, &e.to_string()))));
                let watcher = client.clone();
                tokio::spawn(async move { watcher.watch().await });
                match mode {
                    Mode::Forward => client.connect_tcp(ln).await.unwrap_or_else(|e| exit_for(&e)),
                    Mode::Listen => connect(&client, ln).await,
                }
            }
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap_or_else(|e| fail(1, &e.to_string()));
    tokio::select! {
        _ = work => {}
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    exit(0);
}

/// Answers the suite's queries on stdin, one line each.
async fn queries(c: Client) {
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        let (word, arg) = line.split_once(' ').unwrap_or((line, ""));
        let Ok(q) = word.parse::<Query>() else { continue };
        let answer = match q {
            Query::Stats => {
                let st = c.stats();
                serde_json::to_string(&StatsAnswer {
                    opened: st.opened,
                    active: st.active,
                    failed: st.failed,
                    sent: st.sent,
                    received: st.received,
                })
            }
            Query::Conns => {
                let list: Vec<ConnAnswer> = c
                    .conns()
                    .into_iter()
                    .map(|ci| ConnAnswer { id: ci.id.to_string(), side: ci.side, sent: ci.sent, received: ci.received })
                    .collect();
                serde_json::to_string(&list)
            }
            Query::Drop => {
                let id = c.conns().into_iter().map(|ci| ci.id).find(|id| id.to_string() == arg.trim());
                serde_json::to_string(&id.is_some_and(|id| c.drop_conn(&id, DROP_REASON)))
            }
        };
        say(format!("{q} {}", answer.unwrap()));
    }
}

async fn serve(client: &Client, target: &str, no_accept: bool) {
    let listener = client.listen().await.unwrap_or_else(|e| exit_for(&e)); // its registration says ready
    if no_accept {
        std::future::pending::<()>().await;
    }
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
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target)).await {
                Ok(Ok(tcp)) => pipe(tcp, conn).await,
                _ => conn.fail(TARGET_UNREACHABLE).await,
            }
        });
    }
}

async fn connect(client: &Client, ln: TcpListener) {
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
