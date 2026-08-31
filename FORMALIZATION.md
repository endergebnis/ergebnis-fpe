# ErgebnisFPE — Formale Definition als eine zusammenhängende Formel

> Diese Fassung ersetzt die frühere `n=20`-Variante (verlustbehaftete
> `ρ(mi)/ρ(se)/ρ(ms)`-Erfassung) und entspricht exakt dem Code
> (`src/main.rs`): `n=24`, verlustfreie Zeitziffern, chained KDF.

## Gesamtformel

Für Zeitstempel `t` und Secret `s ∈ Z_{2^64}`:

$$
C = \text{base62}\left(\text{Enc}\left(E_{K(s)}(\Phi(t))\right)\right)
$$

Die vollständige Konstruktion ist definiert durch

$$
\begin{aligned}
t &= (y, mo, da, hr, mi, se, ms),\\
\mathbb{Z}_{24} &= \{0, 1, \ldots, 23\},\qquad \rho(x) = x \bmod 24,\\
\Phi(t) &= \left(x_1, \ldots, x_{12}, j_1, \ldots, j_7, m_1, \ldots, m_5\right) \in \mathbb{Z}_{24}^{24},\\
x_1 &= hr,\quad x_2 = \left\lfloor\frac{mi}{24}\right\rfloor,\quad x_3 = mi \bmod 24,\\
x_4 &= \left\lfloor\frac{se}{24}\right\rfloor,\quad x_5 = se \bmod 24,\\
x_6 &= \left\lfloor\frac{ms}{576}\right\rfloor,\quad x_7 = \left\lfloor\frac{ms}{24}\right\rfloor \bmod 24,\quad x_8 = ms \bmod 24,\\
x_9 &= \rho(mo),\quad x_{10} = \rho(da),\\
x_{11} &= \rho\left(\left\lfloor\frac{y}{100}\right\rfloor\right),\quad x_{12} = \rho\left(y \bmod 100\right),\\
(j_1, \ldots, j_7) &= \text{Dezimalziffern von } \text{JDN}(y, mo, da),\\
(m_1, \ldots, m_5) &= \rho\left(\text{baktun}, \text{katun}, \text{tun}, \text{uinal}, \text{kin}\right),\\
S_0 &= H(s),\\
S_i &= H(S_{i-1} + \gamma) \bmod 2^{64},\qquad i = 1, \ldots, 8,\\
K_i &= S_i \bmod 24,\qquad K = (K_1, \ldots, K_8) \in \mathbb{Z}_{24}^{8},\\
\Psi_i(L, R) &= \left(R, \left(L + F(R, K_i)\right) \bmod 24\right),\\
E_K &= \Psi_8 \circ \Psi_7 \circ \cdots \circ \Psi_1,\\
C &= \text{base62}\left(\text{Enc}(E_K(\Phi(t)))\right).
\end{aligned}
$$

---

## Die drei Schichten

```text
T  --Φ-->  Z_24^24  --E_K-->  Z_24^24  --Enc-->  {0 .. 24^24-1}  --base62-->  Token
```

1. **Erfassung** `Φ` — verlustfrei für die Uhrzeit, Kalender via JDN-Ziffern, Maya mod 24.
2. **Permutation** `E_K` — 8 Feistel-Runden, bijektiv.
3. **Kodierung** `Enc` + `base62` — Basis-24-Zahl, dann Zeichenkette.

---

## Julianische Tageszahl

$$
\text{JDN}(y, m, d)
=
d + \left\lfloor\frac{153m'+2}{5}\right\rfloor
+ 365y' + \left\lfloor\frac{y'}{4}\right\rfloor
- \left\lfloor\frac{y'}{100}\right\rfloor
+ \left\lfloor\frac{y'}{400}\right\rfloor
- 32045,
$$

mit

$$
a = \left\lfloor\frac{14-m}{12}\right\rfloor,\quad
y' = y + 4800 - a,\quad
m' = m + 12a - 3.
$$

Die JDN wird **nicht** modulo 24 reduziert, sondern ihre Dezimalziffern werden
übernommen. Für die aktuelle Größenordnung gilt `k=7` Ziffern (gültig bis
`JDN < 10^7`, weit jenseits des Jahres 22600).

## Maya-Long-Count

$$
\begin{aligned}
\text{days} &= \text{JDN}(y, mo, da) - 584283,\\
\text{baktun} &= \left\lfloor\frac{\text{days}}{144000}\right\rfloor,\quad
\text{katun} = \left\lfloor\frac{\text{days} \bmod 144000}{7200}\right\rfloor,\\
\text{tun} &= \left\lfloor\frac{\text{days} \bmod 7200}{360}\right\rfloor,\quad
\text{uinal} = \left\lfloor\frac{\text{days} \bmod 360}{20}\right\rfloor,\quad
\text{kin} = \text{days} \bmod 20.
\end{aligned}
$$

---

## Schlüsselableitung (chained KDF)

`H` ist der Murmur3-64-Finalizer (`fmix64`):

$$
\begin{aligned}
k_1 &= k \oplus (k \gg 33),\\
k_2 &= (k_1 \cdot c_1) \bmod 2^{64},\\
k_3 &= k_2 \oplus (k_2 \gg 33),\\
k_4 &= (k_3 \cdot c_2) \bmod 2^{64},\\
H(k) &= k_4 \oplus (k_4 \gg 33),
\end{aligned}
$$

mit

$$
c_1 = \text{0xFF51AFD7ED558CCD},\qquad
c_2 = \text{0xC4CEB9FE1A85EC53}.
$$

Die Rundenschlüssel entstehen durch **verkettete** Anwendung (nicht
`H(s+iγ)`, wie in der alten Fassung beschrieben):

$$
S_0 = H(s),\qquad
S_i = H(S_{i-1} + \gamma) \bmod 2^{64},\qquad
K_i = S_i \bmod 24,
$$

mit der ungeraden Weyl-Konstante

$$
\gamma = \text{0x9E3779B97F4A7C15}.
$$

---

## Feistel-Netzwerk

Die Rundenfunktion ist elementweise definiert:

$$
F(R,K)_j
=
\text{resolve}(R_j, K)
=
12 + \left(|R_j - K| \bmod 12\right).
$$

Das Bild von `resolve` liegt in `{12,…,23}`; die Funktion ist **nicht**
injektiv. Die Bijektivität des Netzwerks folgt dennoch aus der
Feistel-Struktur:

$$
\Psi_i(L,R) = \left(R, \left(L + F(R,K_i)\right) \bmod 24\right),\qquad
\Psi_i^{-1}(L',R') = \left(\left(R' - F(L',K_i)\right) \bmod 24, L'\right).
$$

Der Klartextvektor wird in Hälften geteilt, `L_0=(x_1,…,x_12)`,
`R_0=(j_1,…,m_5)`, und

$$
E_K = \Psi_8 \circ \cdots \circ \Psi_1.
$$

---

## Kodierung

$$
\text{Enc}(c) = \sum_{i=0}^{23} c_i \cdot 24^{i},
$$

d. h. `c` wird als Zahl im Stellenwertsystem zur Basis 24 interpretiert.
Anschließend wird diese Ganzzahl in Basis 62 mit dem Alphabet `0-9A-Za-z`
umgewandelt (`base62`). Da `Enc` und jede Feistel-Runde bijektiv sind, ist die
gesamte Kette bei bekanntem Secret exakt umkehrbar.
