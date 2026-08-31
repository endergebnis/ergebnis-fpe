//! ErgebnisFPE: Besucher-Token mit rotierendem Key-Ring (sliding window).
//!
//! Kern = FPE (Feistel + JDN + Maya + base62) wie in `fingerprint`, plus
//! Generationen-Tracking: ein Token gehoert zu einem 15-Minuten-Fenster, der
//! zugehoerige Key rotiert mit dem Fenster. Validierung ist komplett stateless:
//! kein Blacklist-Flag, keine DB. Ein alter Token (SECONDARY/TERTIARY) wird beim
//! Validieren automatisch auf den aktuellen Main Key "up-gelevelt" (neuer Token).

use std::env;
use std::io::Read;
use std::process::exit;

use chrono::{Datelike, Local, NaiveDateTime, Timelike};

const BASE: i64 = 24;
const N_ROUNDS: usize = 8;
const N_VALUES: usize = 24;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const DEFAULT_WINDOW_MINUTES: i64 = 15;

// ---------- FPE-Kern (identisch zu fingerprint) ----------

fn resolve(state: i64, operand: i64) -> i64 {
    12 + (state - operand).abs() % 12
}

fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xFF51AFD7ED558CCD);
    k ^= k >> 33;
    k = k.wrapping_mul(0xC4CEB9FE1A85EC53);
    k ^= k >> 33;
    k
}

fn julian_day_number(year: i64, month: u32, day: u32) -> i64 {
    let a = (14 - month as i64) / 12;
    let y = year + 4800 - a;
    let m = month as i64 + 12 * a - 3;
    day as i64 + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045
}

fn jdn_to_gregorian(jdn: i64) -> (i64, i64, i64) {
    let a = jdn + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let day = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year = 100 * b + d - 4800 + (m / 10);
    (year, month, day)
}

fn maya_long_count(jdn: i64) -> [i64; 5] {
    let days = jdn - 584283;
    let (baktun, r) = (days / 144000, days % 144000);
    let (katun, r) = (r / 7200, r % 7200);
    let (tun, r) = (r / 360, r % 360);
    let (uinal, kin) = (r / 20, r % 20);
    [baktun, katun, tun, uinal, kin]
}

fn collect_message_values(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millisecond: u32,
) -> Vec<i64> {
    let jdn = julian_day_number(year, month, day);
    let maya = maya_long_count(jdn);

    // Zeit verlustfrei: Stunde 0-23 (1 Ziffer), Minute/Sekunde 0-59 (2 Ziffern),
    // Millisekunde 0-999 (3 Ziffern) statt %24-Kollisionen.
    let mut values = vec![
        hour as i64,
        (minute / 24) as i64,
        (minute % 24) as i64,
        (second / 24) as i64,
        (second % 24) as i64,
        (millisecond / 576) as i64,
        ((millisecond / 24) % 24) as i64,
        (millisecond % 24) as i64,
        (month as i64) % 24,
        (day as i64) % 24,
        (year / 100) % 24,
        (year % 100) % 24,
    ];
    for c in jdn.to_string().bytes() {
        values.push((c - b'0') as i64); // JDN-Ziffern OHNE Modulo -> verlustfrei
    }
    for v in maya {
        values.push(v % 24);
    }
    values
}

fn key_schedule_from_secret(secret: u64, n_rounds: usize) -> Vec<i64> {
    let mut state = fmix64(secret);
    let mut keys = Vec::with_capacity(n_rounds);
    for _ in 0..n_rounds {
        state = state.wrapping_add(GOLDEN);
        state = fmix64(state);
        keys.push((state % 24) as i64);
    }
    keys
}

fn feistel_encrypt(plain: &[i64], round_keys: &[i64]) -> (Vec<i64>, Vec<i64>) {
    let half = plain.len() / 2;
    let mut l = plain[..half].to_vec();
    let mut r = plain[half..].to_vec();
    for &k in round_keys {
        let new_r: Vec<i64> = l
            .iter()
            .zip(&r)
            .map(|(&a, &b)| (a + resolve(b, k)) % BASE)
            .collect();
        l = r;
        r = new_r;
    }
    (l, r)
}

fn feistel_decrypt(l: &[i64], r: &[i64], round_keys: &[i64]) -> Vec<i64> {
    let mut l = l.to_vec();
    let mut r = r.to_vec();
    for &k in round_keys.iter().rev() {
        let prev_r = l.clone();
        let prev_l: Vec<i64> = l
            .iter()
            .zip(&r)
            .map(|(&a, &b)| (b - resolve(a, k)).rem_euclid(BASE))
            .collect();
        l = prev_l;
        r = prev_r;
    }
    l.extend(&r);
    l
}

fn encode(vector: &[i64]) -> u128 {
    let mut fp: u128 = 0;
    let mut place: u128 = 1;
    for &v in vector {
        fp += (v as u128) * place;
        place *= BASE as u128;
    }
    fp
}

fn decode(mut fp: u128, length: usize) -> Vec<i64> {
    let mut v = Vec::with_capacity(length);
    for _ in 0..length {
        v.push((fp % BASE as u128) as i64);
        fp /= BASE as u128;
    }
    v
}

fn to_base62(mut n: u128) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(B62[(n % 62) as usize] as char);
        n /= 62;
    }
    out.reverse();
    out.into_iter().collect()
}

fn from_base62(s: &str) -> u128 {
    let mut n: u128 = 0;
    for ch in s.bytes() {
        let idx = B62.iter().position(|&c| c == ch).unwrap_or_else(|| {
            eprintln!("ungueltiges base62-Zeichen: {}", ch as char);
            exit(2);
        });
        n = n * 62 + idx as u128;
    }
    n
}

fn make_fingerprint(values: &[i64], secret: u64) -> String {
    let round_keys = key_schedule_from_secret(secret, N_ROUNDS);
    let (l, r) = feistel_encrypt(values, &round_keys);
    let mut cipher = l;
    cipher.extend(&r);
    to_base62(encode(&cipher))
}

fn recover_values(fp: &str, secret: u64) -> Vec<i64> {
    let round_keys = key_schedule_from_secret(secret, N_ROUNDS);
    let cipher = decode(from_base62(fp), N_VALUES);
    let half = cipher.len() / 2;
    feistel_decrypt(&cipher[..half], &cipher[half..], &round_keys)
}

// ---------- Zeitstempel ----------

struct Timestamp {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
}

impl Timestamp {
    fn now() -> Timestamp {
        let n = Local::now();
        Timestamp {
            year: n.year() as i64,
            month: n.month(),
            day: n.day(),
            hour: n.hour(),
            minute: n.minute(),
            second: n.second(),
            millis: n.timestamp_subsec_millis(),
        }
    }

    fn jdn(&self) -> i64 {
        julian_day_number(self.year, self.month, self.day)
    }

    // Minuten seit Jahr 0 (fuer Alter + Generation). Zeit-frei von Zeitzonen,
    // da direkt aus JDN + Uhrzeit gerechnet.
    fn total_minutes(&self) -> i64 {
        self.jdn() * 1440 + self.hour as i64 * 60 + self.minute as i64
    }

    // Welchem Token-Fenster gehoert dieser Zeitpunkt an? -> Key-Ring-Index.
    fn generation(&self, window_minutes: i64) -> i64 {
        self.total_minutes() / window_minutes
    }

    fn values(&self) -> Vec<i64> {
        collect_message_values(
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis,
        )
    }

    fn display(&self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }
}

fn timestamp_from_values(v: &[i64]) -> Timestamp {
    let hour = v[0];
    let minute = v[1] * 24 + v[2];
    let second = v[3] * 24 + v[4];
    let millis = v[5] * 576 + v[6] * 24 + v[7];
    let jdn: i64 = v[12..19].iter().fold(0, |acc, &d| acc * 10 + d);
    let (y, m, d) = jdn_to_gregorian(jdn);
    Timestamp {
        year: y,
        month: m as u32,
        day: d as u32,
        hour: hour as u32,
        minute: minute as u32,
        second: second as u32,
        millis: millis as u32,
    }
}

// ---------- Key-Ring / Generationen-Tracking ----------

// Pro Fenster ein eigener Key -> der "Ring" sind die letzten 3 Fenster.
fn generation_key(secret: u64, generation: i64) -> u64 {
    fmix64(secret ^ (generation as u64))
}

// Token = "<generation>.<fingerprint>". Generation ist Klartext (nur Fenster-
// Index, keine Nutzdaten) und sagt dem Server, welchen Key er probieren soll.
fn make_token(ts: &Timestamp, secret: u64, window_minutes: i64) -> String {
    let g = ts.generation(window_minutes);
    let fp = make_fingerprint(&ts.values(), generation_key(secret, g));
    format!("{g}.{fp}")
}

fn tier_name(delta: i64) -> Option<&'static str> {
    match delta {
        0 => Some("MAIN (frisch)"),
        1 => Some("SECONDARY (veraltet)"),
        2 => Some("TERTIARY (stark veraltet)"),
        _ => None,
    }
}

fn validate_token(token: &str, secret: u64, window_minutes: i64) {
    let (g_str, fp) = token.split_once('.').unwrap_or_else(|| {
        eprintln!("Token muss die Form <generation>.<fingerprint> haben");
        exit(1);
    });
    let g: i64 = g_str.parse().unwrap_or_else(|_| {
        eprintln!("ungueltige Generation im Token");
        exit(1);
    });

    let now = Timestamp::now();
    let delta = now.generation(window_minutes) - g;

    let tier = match tier_name(delta) {
        Some(t) => t,
        None => {
            println!("Ergebnis: ABGELAUFEN / UNGUELTIG (Fenster ausserhalb des Key-Rings)");
            exit(1);
        }
    };

    let v = recover_values(fp, generation_key(secret, g));
    let ts = timestamp_from_values(&v);

    // Forgery-Check: ein gueltiger Token muss zur angegebenen Generation
    // passen (sonst hat jemand einen Random-String eingereicht).
    if ts.generation(window_minutes) != g || ts.year < 1900 || ts.year > 2100 {
        println!("Ergebnis: UNGUELTIG (Signatur passt nicht zur Generation)");
        exit(1);
    }

    let age = now.total_minutes() - ts.total_minutes();

    println!("Ergebnis:    GUELTIG ({tier})");
    println!("Ausgestellt: {}", ts.display());
    println!("Alter:       {age} min");

    if delta > 0 {
        // Sliding Window: alter Token -> frischen Token auf dem Main Key ausgeben.
        let fresh = make_token(&now, secret, window_minutes);
        println!("Neuer Token: {fresh}  <- up-leveled auf Main Key");
    }
}

// ---------- .env ----------

fn load_secret() -> u64 {
    dotenvy::dotenv().ok();
    match env::var("SERVER_SECRET") {
        Ok(s) => s.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("SERVER_SECRET muss eine 64-Bit-Zahl sein");
            exit(1);
        }),
        Err(_) => {
            eprintln!("SERVER_SECRET fehlt. Zuerst: ergebnis-fpe init");
            exit(1);
        }
    }
}

fn load_window() -> i64 {
    dotenvy::dotenv().ok();
    match env::var("WINDOW_MINUTES") {
        Ok(s) => s.parse::<i64>().unwrap_or_else(|_| {
            eprintln!("WINDOW_MINUTES muss eine Ganzzahl sein");
            exit(1);
        }),
        Err(_) => DEFAULT_WINDOW_MINUTES,
    }
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
    let secret = load_secret();
    let window = load_window();
    let ts = parse_timestamp(arg);
    let token = make_token(&ts, secret, window);
    println!("Zeitpunkt:  {}", ts.display());
    println!("Generation: {} (Fenster: {window} min)", ts.generation(window));
    println!("Token:      {token}");
}

fn cmd_validate(token: &str) {
    let secret = load_secret();
    let window = load_window();
    validate_token(token, secret, window);
}

fn help() {
    let text = "ErgebnisFPE: Besucher-Token mit rotierendem Key-Ring (stateless, kein Blacklist-Flag)

Aufruf:
  ergebnis-fpe init [--force]  SERVER_SECRET erzeugen & in .env schreiben
  ergebnis-fpe make [ISO]      Token erzeugen (Default: jetzt)
  ergebnis-fpe validate <TOKEN>  Token pruefen; alter Token -> neuer Main-Key-Token

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
        "-h" | "--help" | "help" => help(),
        _ => {
            eprintln!("unbekannter Befehl: {cmd}");
            help();
            exit(1);
        }
    }
}
