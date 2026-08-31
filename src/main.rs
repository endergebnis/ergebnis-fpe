//! ErgebnisFPE CLI: duenner Wrapper um die Bibliothek `ergebnis_fpe`.
//!
//! Die gesamte FPE-/Key-Ring-Logik liegt in src/lib.rs und kann auch
//! in-process in einen Server eingebettet werden (siehe README).

use std::env;
use std::io::Read;
use std::process::exit;

use chrono::{Datelike, NaiveDateTime, Timelike};

use ergebnis_fpe::{make_token, validate_token, Timestamp, DEFAULT_WINDOW_MINUTES};

// ---------- .env ----------

// .env einmal laden und beide Werte rauslesen (statt zweimal dotenv aufzurufen).
fn load_config() -> (u64, i64) {
    dotenvy::dotenv().ok();
    let secret = match env::var("SERVER_SECRET") {
        Ok(s) => s.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("SERVER_SECRET muss eine 64-Bit-Zahl sein");
            exit(1);
        }),
        Err(_) => {
            eprintln!("SERVER_SECRET fehlt. Zuerst: ergebnis-fpe init");
            exit(1);
        }
    };
    let window = match env::var("WINDOW_MINUTES") {
        Ok(s) => s.parse::<i64>().unwrap_or_else(|_| {
            eprintln!("WINDOW_MINUTES muss eine Ganzzahl sein");
            exit(1);
        }),
        Err(_) => DEFAULT_WINDOW_MINUTES,
    };
    (secret, window)
}

fn generate_secret() -> u64 {
    let mut buf = [0u8; 8];
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom nicht lesbar");
    f.read_exact(&mut buf).expect("urandom lesen fehlgeschlagen");
    u64::from_le_bytes(buf)
}

fn parse_timestamp(arg: Option<&str>) -> Timestamp {
    match arg {
        None => Timestamp::now(),
        Some(s) => {
            let dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap_or_else(|e| {
                    eprintln!("Zeitstempel nicht geparst ({e}). Erwartet: 2026-08-31T14:07:23.456");
                    exit(1);
                });
            Timestamp {
                year: dt.year() as i64,
                month: dt.month(),
                day: dt.day(),
                hour: dt.hour(),
                minute: dt.minute(),
                second: dt.second(),
                millis: dt.and_utc().timestamp_subsec_millis(),
            }
        }
    }
}

// ---------- Befehle ----------

fn cmd_init(force: bool) {
    let path = ".env";
    if std::path::Path::new(path).exists() && !force {
        eprintln!(".env existiert bereits. Mit --force ueberschreiben.");
        exit(1);
    }
    let secret = generate_secret();
    std::fs::write(path, format!("SERVER_SECRET={secret}\nWINDOW_MINUTES={DEFAULT_WINDOW_MINUTES}\n"))
        .expect(".env schreiben");
    println!("SERVER_SECRET={secret} -> {path} geschrieben (geheim halten!)");
}

fn cmd_make(arg: Option<&str>) {
    let (secret, window) = load_config();
    let ts = parse_timestamp(arg);
    let token = make_token(&ts, secret, window);
    println!("Zeitpunkt:  {}", ts.display());
    println!("Generation: {} (Fenster: {window} min)", ts.generation(window));
    println!("Token:      {token}");
}

fn cmd_validate(token: &str) {
    let (secret, window) = load_config();
    match validate_token(token, secret, window) {
        Ok(v) => {
            println!("Ergebnis:    GUELTIG ({})", v.tier);
            println!("Ausgestellt: {}", v.issued_at.display());
            println!("Alter:       {} min", v.age_minutes);
            if let Some(fresh) = v.fresh_token {
                println!("Neuer Token: {fresh}  <- up-leveled auf Main Key");
            }
        }
        Err(msg) => {
            println!("Ergebnis: {msg}");
            exit(1);
        }
    }
}

fn cmd_bench(n: usize) {
    use std::time::Instant;
    use ergebnis_fpe::{make_fingerprint, recover_values};

    let secret = load_config().0;
    let ts = parse_timestamp(None);
    let values = ts.values();
    let fp = make_fingerprint(&values, secret);

    // Warm-up, damit die Messung nicht von der ersten Allokation verfaelscht wird.
    for _ in 0..100_000 {
        let _ = make_fingerprint(&values, secret);
    }

    let t = Instant::now();
    for _ in 0..n {
        let _ = make_fingerprint(&values, secret);
    }
    let enc = t.elapsed();

    let t = Instant::now();
    for _ in 0..n {
        let _ = recover_values(&fp, secret).unwrap();
    }
    let dec = t.elapsed();

    println!("FPE-Kern (in-process, n={n}):");
    println!(
        "  make_fingerprint: {:>10.1} ns/op  ({:.2} M ops/s)",
        enc.as_nanos() as f64 / n as f64,
        n as f64 / enc.as_secs_f64() / 1e6
    );
    println!(
        "  recover_values:   {:>10.1} ns/op  ({:.2} M ops/s)",
        dec.as_nanos() as f64 / n as f64,
        n as f64 / dec.as_secs_f64() / 1e6
    );
}

fn cmd_benchreq(n: usize) {
    use std::time::Instant;

    let (secret, window) = load_config();
    let token = make_token(&Timestamp::now(), secret, window);

    // Warm-up, damit die Messung nicht von den ersten Allokationen verfaelscht wird.
    for _ in 0..100_000 {
        let _ = validate_token(&token, secret, window);
    }

    let t = Instant::now();
    let mut ok = 0usize;
    for _ in 0..n {
        if validate_token(&token, secret, window).is_ok() {
            ok += 1;
        }
    }
    let el = t.elapsed();

    println!("Request-Simulation (in-process validate_token, n={n}):");
    println!(
        "  durchschnittlich: {:>10.1} ns/request  ({:.2} M requests/s)",
        el.as_nanos() as f64 / n as f64,
        n as f64 / el.as_secs_f64() / 1e6
    );
    println!("  gesamt: {el:?}  (gueltig: {ok}/{n})");
}

fn cmd_benchpar(n: usize, threads: usize) {
    use std::time::Instant;

    let (secret, window) = load_config();
    let token = make_token(&Timestamp::now(), secret, window);

    // Warm-up (single thread, wie bei benchreq).
    for _ in 0..100_000 {
        let _ = validate_token(&token, secret, window);
    }

    // Referenz: ein Thread.
    let t = Instant::now();
    let mut ok = 0usize;
    for _ in 0..n {
        if validate_token(&token, secret, window).is_ok() {
            ok += 1;
        }
    }
    let single = t.elapsed();
    let single_rate = n as f64 / single.as_secs_f64();

    // Parallel: n total, auf `threads` aufgeteilt, jeder validiert unabhaengig.
    let per = n / threads;
    let t = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let token = token.clone();
            std::thread::spawn(move || {
                let mut c = 0usize;
                for _ in 0..per {
                    if validate_token(&token, secret, window).is_ok() {
                        c += 1;
                    }
                }
                c
            })
        })
        .collect();
    let par_ok: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let par = t.elapsed();
    let par_rate = n as f64 / par.as_secs_f64();

    println!("Parallel-Simulation (in-process validate_token, {threads} Threads, n={n}):");
    println!(
        "  1 Thread:       {:>10.1} ns/req  ({:.2} M req/s)",
        single.as_nanos() as f64 / n as f64,
        single_rate / 1e6
    );
    println!(
        "  {threads} Threads:     {:>10.1} ns/req  ({:.2} M req/s)",
        par.as_nanos() as f64 / n as f64,
        par_rate / 1e6
    );
    println!(
        "  Speedup:        {:.2}x  (linear waere {threads:.0}x)",
        par_rate / single_rate
    );
    println!("  gesamt: {single:?} (1 Thread) / {par:?} ({threads} Threads)  gueltig: {ok}/{n} bzw. {par_ok}/{n}");
}

fn help() {
    let text = "ErgebnisFPE: Besucher-Token mit rotierendem Key-Ring (stateless, kein Blacklist-Flag)

Aufruf:
  ergebnis-fpe init [--force]  SERVER_SECRET erzeugen & in .env schreiben
  ergebnis-fpe make [ISO]      Token erzeugen (Default: jetzt)
  ergebnis-fpe validate <TOKEN>  Token pruefen; alter Token -> neuer Main-Key-Token
  ergebnis-fpe bench [N]       FPE-Kern in-process messen (ns/op), Default N=1000000
  ergebnis-fpe benchreq [N]    volle Request-Validierung simulieren, Default N=10000000
  ergebnis-fpe benchpar [N] [T]  parallel: N Requests auf T Threads, Default T=CPU-Kerne

ISO-Zeitstempel: 2026-08-31T14:07:23.456
Fenster: WINDOW_MINUTES in .env (Default 15). Token gilt 3 Fenster:
MAIN (0-15 min) -> SECONDARY (15-30) -> TERTIARY (30-45) -> abgelaufen.
";
    print!("{text}");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (cmd, rest): (&str, &[String]) = match args.first() {
        Some(c) => (c.as_str(), &args[1..]),
        None => {
            help();
            exit(0);
        }
    };

    match cmd {
        "init" => cmd_init(rest.iter().any(|a| a == "--force")),
        "make" => cmd_make(rest.first().map(|s| s.as_str())),
        "validate" => {
            if rest.is_empty() {
                eprintln!("validate braucht einen Token");
                help();
                exit(1);
            }
            cmd_validate(&rest[0]);
        }
        "bench" => cmd_bench(rest.first().and_then(|s| s.parse().ok()).unwrap_or(1_000_000)),
        "benchreq" => cmd_benchreq(rest.first().and_then(|s| s.parse().ok()).unwrap_or(10_000_000)),
        "benchpar" => {
            let threads = rest
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
            cmd_benchpar(
                rest.first().and_then(|s| s.parse().ok()).unwrap_or(5_000_000),
                threads,
            )
        }
        "-h" | "--help" | "help" => help(),
        _ => {
            eprintln!("unbekannter Befehl: {cmd}");
            help();
            exit(1);
        }
    }
}
