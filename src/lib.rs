//! ErgebnisFPE: Besucher-Token mit rotierendem Key-Ring (sliding window).
//!
//! Kern = FPE (Feistel + JDN + Maya + base62) wie in `fingerprint`, plus
//! Generationen-Tracking: ein Token gehoert zu einem 15-Minuten-Fenster, der
//! zugehoerige Key rotiert mit dem Fenster. Validierung ist komplett stateless:
//! kein Blacklist-Flag, keine DB. Ein alter Token (SECONDARY/TERTIARY) wird beim
//! Validieren automatisch auf den aktuellen Main Key "up-gelevelt" (neuer Token).
//!
//! Einbettung in einen Server (Request-Path): statt pro Request das Binary zu
//! starten, [`make_token`]/[`validate_token`] direkt im Prozess aufrufen.
//!
//! Der Hot Path (Feistel-Runden, KDF, Kodierung) ist alloc-frei: feste Arrays
//! statt Vec, keine String-Allokation fuer die JDN-Ziffern.

use chrono::{Datelike, Timelike, Utc};

const BASE: i64 = 24;
const N_ROUNDS: usize = 8;
const N_VALUES: usize = 24;
const HALF: usize = N_VALUES / 2;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// O(1) ASCII-Byte -> base62-Wert; -1 = ungueltig.
const B62_DECODE: [i8; 256] = {
    let mut table = [-1i8; 256];
    let mut i = 0;
    while i < B62.len() {
        table[B62[i] as usize] = i as i8;
        i += 1;
    }
    table
};

/// Default-Fenstergroesse in Minuten.
pub const DEFAULT_WINDOW_MINUTES: i64 = 15;

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
) -> [i64; N_VALUES] {
    let jdn = julian_day_number(year, month, day);
    let maya = maya_long_count(jdn);

    // Zeit verlustfrei: Stunde 0-23 (1 Ziffer), Minute/Sekunde 0-59 (2 Ziffern),
    // Millisekunde 0-999 (3 Ziffern) statt %24-Kollisionen.
    let mut values = [0i64; N_VALUES];
    values[0] = hour as i64;
    values[1] = (minute / 24) as i64;
    values[2] = (minute % 24) as i64;
    values[3] = (second / 24) as i64;
    values[4] = (second % 24) as i64;
    values[5] = (millisecond / 576) as i64;
    values[6] = ((millisecond / 24) % 24) as i64;
    values[7] = (millisecond % 24) as i64;
    values[8] = (month as i64) % 24;
    values[9] = (day as i64) % 24;
    values[10] = (year / 100) % 24;
    values[11] = (year % 100) % 24;

    // JDN-Ziffern OHNE Modulo -> verlustfrei. Feste Breite 7 (passt zu
    // Timestamp::from_values, das v[12..19] liest); gueltig bis JDN < 10^7.
    let mut n = jdn;
    for i in (0..7).rev() {
        values[12 + i] = n % 10;
        n /= 10;
    }
    for (i, v) in maya.iter().enumerate() {
        values[19 + i] = v % 24;
    }
    values
}

fn key_schedule_from_secret(secret: u64) -> [i64; N_ROUNDS] {
    let mut state = fmix64(secret);
    let mut keys = [0i64; N_ROUNDS];
    for k in keys.iter_mut() {
        state = state.wrapping_add(GOLDEN);
        state = fmix64(state);
        *k = (state % 24) as i64;
    }
    keys
}

fn feistel_encrypt(plain: &[i64; N_VALUES], round_keys: &[i64; N_ROUNDS]) -> [i64; N_VALUES] {
    let mut l = [0i64; HALF];
    let mut r = [0i64; HALF];
    l.copy_from_slice(&plain[..HALF]);
    r.copy_from_slice(&plain[HALF..]);
    for &k in round_keys {
        let mut new_r = [0i64; HALF];
        for i in 0..HALF {
            new_r[i] = (l[i] + resolve(r[i], k)) % BASE;
        }
        l = r;
        r = new_r;
    }
    let mut out = [0i64; N_VALUES];
    out[..HALF].copy_from_slice(&l);
    out[HALF..].copy_from_slice(&r);
    out
}

fn feistel_decrypt(cipher: &[i64; N_VALUES], round_keys: &[i64; N_ROUNDS]) -> [i64; N_VALUES] {
    let mut l = [0i64; HALF];
    let mut r = [0i64; HALF];
    l.copy_from_slice(&cipher[..HALF]);
    r.copy_from_slice(&cipher[HALF..]);
    for &k in round_keys.iter().rev() {
        let prev_r = l;
        let mut prev_l = [0i64; HALF];
        for i in 0..HALF {
            // x in [-23, 23]; rem_euclid(24) == x + 24 bei x<0.
            let x = r[i] - resolve(l[i], k);
            prev_l[i] = if x < 0 { x + BASE } else { x };
        }
        l = prev_l;
        r = prev_r;
    }
    let mut out = [0i64; N_VALUES];
    out[..HALF].copy_from_slice(&l);
    out[HALF..].copy_from_slice(&r);
    out
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

fn decode(mut fp: u128) -> [i64; N_VALUES] {
    let mut v = [0i64; N_VALUES];
    for i in 0..N_VALUES {
        v[i] = (fp % BASE as u128) as i64;
        fp /= BASE as u128;
    }
    v
}

fn to_base62(mut n: u128) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut out = Vec::with_capacity(22);
    while n > 0 {
        out.push(B62[(n % 62) as usize] as char);
        n /= 62;
    }
    out.reverse();
    out.into_iter().collect()
}

fn from_base62(s: &str) -> Result<u128, String> {
    let mut n: u128 = 0;
    for ch in s.bytes() {
        let idx = B62_DECODE[ch as usize];
        if idx < 0 {
            return Err(format!("ungueltiges base62-Zeichen: {}", ch as char));
        }
        n = n * 62 + idx as u128;
    }
    Ok(n)
}

/// FPE-Kern: Werte-Vektor verschluesseln -> base62-String.
pub fn make_fingerprint(values: &[i64; N_VALUES], secret: u64) -> String {
    let round_keys = key_schedule_from_secret(secret);
    let cipher = feistel_encrypt(values, &round_keys);
    to_base62(encode(&cipher))
}

/// FPE-Kern: base62-String entschluesseln -> Werte-Vektor.
pub fn recover_values(fp: &str, secret: u64) -> Result<[i64; N_VALUES], String> {
    let round_keys = key_schedule_from_secret(secret);
    let cipher = decode(from_base62(fp)?);
    Ok(feistel_decrypt(&cipher, &round_keys))
}

/// Zeitstempel mit allen verlustfreien Komponenten (bis Millisekunde).
/// Zeiten werden in UTC erfasst; nur Differenzen zaehlen, die Zeitzone ist egal.
#[derive(Debug, Clone)]
pub struct Timestamp {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millis: u32,
}

impl Timestamp {
    pub fn now() -> Timestamp {
        let n = Utc::now();
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

    pub fn jdn(&self) -> i64 {
        julian_day_number(self.year, self.month, self.day)
    }

    /// Minuten seit Jahr 0 (fuer Alter + Generation), zeitzonenfrei.
    pub fn total_minutes(&self) -> i64 {
        self.jdn() * 1440 + self.hour as i64 * 60 + self.minute as i64
    }

    /// Welchem Token-Fenster gehoert dieser Zeitpunkt an? -> Key-Ring-Index.
    pub fn generation(&self, window_minutes: i64) -> i64 {
        self.total_minutes() / window_minutes
    }

    pub fn values(&self) -> [i64; N_VALUES] {
        collect_message_values(
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis,
        )
    }

    pub fn display(&self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }

    /// Rekonstruktion aus einem 24er-Werte-Vektor (Gegenstueck zu [`Timestamp::values`]).
    pub fn from_values(v: &[i64]) -> Timestamp {
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
}

// ---------- Key-Ring / Generationen-Tracking ----------

// Pro Fenster ein eigener Key -> der "Ring" sind die letzten 3 Fenster.
fn generation_key(secret: u64, generation: i64) -> u64 {
    fmix64(secret ^ (generation as u64))
}

/// Token = "<generation>.<fingerprint>". Generation ist Klartext (nur Fenster-
/// Index, keine Nutzdaten) und sagt dem Server, welchen Key er probieren soll.
pub fn make_token(ts: &Timestamp, secret: u64, window_minutes: i64) -> String {
    make_token_with_generation(ts, secret, ts.generation(window_minutes))
}

fn make_token_with_generation(ts: &Timestamp, secret: u64, generation: i64) -> String {
    let fp = make_fingerprint(&ts.values(), generation_key(secret, generation));
    format!("{generation}.{fp}")
}

fn tier_name(delta: i64) -> Option<&'static str> {
    match delta {
        0 => Some("MAIN"),
        1 => Some("SECONDARY"),
        2 => Some("TERTIARY"),
        _ => None,
    }
}

/// Ergebnis einer erfolgreichen Validierung.
pub struct Validation {
    /// "MAIN" | "SECONDARY" | "TERTIARY".
    pub tier: &'static str,
    /// Der im Token kodierte Zeitstempel.
    pub issued_at: Timestamp,
    /// Alter in Minuten (jetzt - Ausstellung).
    pub age_minutes: i64,
    /// Bei SECONDARY/TERTIARY: neuer, auf den Main Key up-gelevelter Token.
    pub fresh_token: Option<String>,
}

/// Validierung ohne State/DB. `Err` = abgelaufen, ungueltige Signatur oder
/// ungueltiges Format (nur `Err(String)`, kein Prozess-Abbruch).
pub fn validate_token(token: &str, secret: u64, window_minutes: i64) -> Result<Validation, String> {
    let (g_str, fp) = token
        .split_once('.')
        .ok_or("Token muss die Form <generation>.<fingerprint> haben")?;
    let g: i64 = g_str.parse().map_err(|_| "ungueltige Generation im Token")?;

    let now = Timestamp::now();
    let now_minutes = now.total_minutes();
    let delta = now_minutes / window_minutes - g;

    let tier = tier_name(delta).ok_or("ABGELAUFEN / UNGUELTIG (Fenster ausserhalb des Key-Rings)")?;

    let v = recover_values(fp, generation_key(secret, g))?;
    let ts = Timestamp::from_values(&v);

    // Forgery-Check: ein gueltiger Token muss zur angegebenen Generation passen.
    if ts.generation(window_minutes) != g || ts.year < 1900 || ts.year > 2100 {
        return Err("UNGUELTIG (Signatur passt nicht zur Generation)".to_string());
    }

    let age_minutes = now_minutes - ts.total_minutes();

    let fresh_token = if delta > 0 {
        Some(make_token_with_generation(&now, secret, g + delta))
    } else {
        None
    };

    Ok(Validation {
        tier,
        issued_at: ts,
        age_minutes,
        fresh_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let secret = 7411156633014379033;
        let ts = Timestamp {
            year: 2026,
            month: 8,
            day: 31,
            hour: 5,
            minute: 9,
            second: 35,
            millis: 638,
        };
        let v = ts.values();
        let fp = make_fingerprint(&v, secret);
        let back = recover_values(&fp, secret).unwrap();
        assert_eq!(v, back);
        assert_eq!(ts.display(), Timestamp::from_values(&back).display());
    }
}
