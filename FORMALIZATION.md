# ErgebnisFPE — Formale Definition als eine zusammenhängende Formel

> Ersetzt die ältere `formalisierung_zeitstempel_fingerprint.md` (dort war noch
> `n=20` mit verlustbehafteter `ρ(mi)/ρ(se)/ρ(ms)`-Erfassung). Diese Fassung
> entspricht exakt dem Code (`fingerprint/src/main.rs`, `ergebnis-fpe/src/main.rs`):
> `n=24`, verlustfreie Zeitziffern, chained KDF.

## Gesamtformel

Für Zeitstempel `t` und Secret `s ∈ Z_{2^64}`:

$$
\boxed{
C \;=\; \operatorname{base62}\left(\operatorname{Enc}\left(E_{K(s)}(\Phi(t))\right)\right)
}
$$

Die vollständige Konstruktion ist definiert durch

$$
\boxed{
\begin{aligned}
&t=(y,mo,da,hr,mi,se,ms),\\[1mm]
&\mathbb Z_{24}=\{0,1,\ldots,23\},\qquad
\rho(x)=x\bmod 24,\\[2mm]
&\Phi(t)=
\bigl(x_1,\ldots,x_{12},\;j_1,\ldots,j_7,\;m_1,\ldots,m_5\bigr)
\in\mathbb Z_{24}^{\,24},\\[2mm]
&x_1=hr,
&x_2=\left\lfloor\tfrac{mi}{24}\right\rfloor,&x_3=mi\bmod 24,\\
&x_4=\left\lfloor\tfrac{se}{24}\right\rfloor,&x_5=se\bmod 24,\\
&x_6=\left\lfloor\tfrac{ms}{576}\right\rfloor,&x_7=\left\lfloor\tfrac{ms}{24}\right\rfloor\bmod 24,&x_8=ms\bmod 24,\\
&x_9=\rho(mo),&x_{10}=\rho(da),\\
&x_{11}=\rho\!\left(\left\lfloor\tfrac{y}{100}\right\rfloor\right),&x_{12}=\rho\!\left(y\bmod 100\right),\\[2mm]
&(j_1,\ldots,j_7)=\text{Dezimalziffern von }\operatorname{JDN}(y,mo,da),\\[1mm]
&(m_1,\ldots,m_5)=\rho\!\left(\text{baktun},\text{katun},\text{tun},\text{uinal},\text{kin}\right),\\[3mm]
&S_0=H(s),\\[1mm]
&S_i=H(S_{i-1}+\gamma)\bmod 2^{64},\qquad i=1,\ldots,8,\\[1mm]
&K_i=S_i\bmod 24,\qquad K=(K_1,\ldots,K_8)\in\mathbb Z_{24}^{\,8},\\[3mm]
&\Psi_i(L,R)=\Bigl(R,\;\bigl(L+F(R,K_i)\bigr)\bmod 24\Bigr),\\[1mm]
&E_K=\Psi_8\circ\Psi_7\circ\cdots\circ\Psi_1,\\[1mm]
&C=\operatorname{base62}\!\bigl(\operatorname{Enc}(E_K(\Phi(t)))\bigr).
\end{aligned}
}
$$

---

## Die drei Schichten

$$
\mathcal T
\xrightarrow{\;\Phi\;}
\mathbb Z_{24}^{24}
\xrightarrow{\;E_K\;}
\mathbb Z_{24}^{24}
\xrightarrow{\;\operatorname{Enc}\;}\{0,\dots,24^{24}-1\}
\xrightarrow{\;\operatorname{base62}\;}\{0\!-\!9\mathrm{A\!-\!Za\!-\!z}\}^*
$$

1. **Erfassung** `Φ` — verlustfrei für die Uhrzeit, Kalender via JDN-Ziffern, Maya mod 24.
2. **Permutation** `E_K` — 8 Feistel-Runden, bijektiv.
3. **Kodierung** `Enc` + `base62` — Basis-24-Zahl, dann Zeichenkette.

---

## Julianische Tageszahl

$$
\operatorname{JDN}(y,m,d)
=
d+\left\lfloor\frac{153m'+2}{5}\right\rfloor
+365y'+\left\lfloor\frac{y'}{4}\right\rfloor
-\left\lfloor\frac{y'}{100}\right\rfloor
+\left\lfloor\frac{y'}{400}\right\rfloor
-32045,
$$

mit

$$
a=\left\lfloor\frac{14-m}{12}\right\rfloor,\quad
y'=y+4800-a,\quad
m'=m+12a-3.
$$

Die JDN wird **nicht** modulo 24 reduziert, sondern ihre Dezimalziffern werden
übernommen. Für die aktuelle Größenordnung gilt `k=7` Ziffern (gültig bis
`JDN < 10^7`, weit jenseits des Jahres 22600).

## Maya-Long-Count

$$
\begin{aligned}
\text{days}&=\operatorname{JDN}(y,mo,da)-584283,\\
\text{baktun}&=\left\lfloor\tfrac{\text{days}}{144000}\right\rfloor,\quad
\text{katun}=\left\lfloor\tfrac{\text{days}\bmod 144000}{7200}\right\rfloor,\\
\text{tun}&=\left\lfloor\tfrac{\text{days}\bmod 7200}{360}\right\rfloor,\quad
\text{uinal}=\left\lfloor\tfrac{\text{days}\bmod 360}{20}\right\rfloor,\quad
\text{kin}=\text{days}\bmod 20.
\end{aligned}
$$

---

## Schlüsselableitung (chained KDF)

`H` ist der Murmur3-64-Finalizer (`fmix64`):

$$
H(k)
=
\bigl(\bigl(\bigl(k\oplus(k\gg33)\bigr)\cdot c_1\bmod 2^{64}\bigr)\oplus\ldots\bigr),
\qquad
c_1=\texttt{0xFF51AFD7ED558CCD},\;
c_2=\texttt{0xC4CEB9FE1A85EC53}.
$$

Ausgeschrieben:

$$
\begin{aligned}
k_1&=k\oplus(k\gg33),\\
k_2&=k_1\cdot c_1\bmod 2^{64},\\
k_3&=k_2\oplus(k_2\gg33),\\
k_4&=k_3\cdot c_2\bmod 2^{64},\\
H(k)&=k_4\oplus(k_4\gg33).
\end{aligned}
$$

Die Rundenschlüssel entstehen durch **verkettete** Anwendung (nicht
`H(s+iγ)`, wie in der alten Fassung beschrieben):

$$
S_0=H(s),\qquad
S_i=H(S_{i-1}+\gamma)\bmod 2^{64},\qquad
K_i=S_i\bmod 24,
$$

mit der ungeraden Weyl-Konstante

$$
\gamma=\texttt{0x9E3779B97F4A7C15}.
$$

---

## Feistel-Netzwerk

Die Rundenfunktion ist elementweise definiert:

$$
F(R,K)_j
=
\operatorname{resolve}(R_j,K)
=
12+\bigl(|R_j-K|\bmod 12\bigr).
$$

Das Bild von `resolve` liegt in `{12,…,23}`; die Funktion ist **nicht**
injektiv. Die Bijektivität des Netzwerks folgt dennoch aus der
Feistel-Struktur:

$$
\Psi_i(L,R)=\Bigl(R,\;\bigl(L+F(R,K_i)\bigr)\bmod 24\Bigr),
\qquad
\Psi_i^{-1}(L',R')=\Bigl(\bigl(R'-F(L',K_i)\bigr)\bmod 24,\;L'\Bigr).
$$

Der Klartextvektor wird in Hälften geteilt, `L_0=(x_1,\ldots,x_{12})`,
`R_0=(j_1,\ldots,m_5)`, und

$$
E_K=\Psi_8\circ\cdots\circ\Psi_1.
$$

---

## Kodierung

$$
\operatorname{Enc}(c)=\sum_{i=0}^{23}c_i\,24^{i},
$$

d. h. `c` wird als Zahl im Stellenwertsystem zur Basis 24 interpretiert.
Anschließend wird diese Ganzzahl in Basis 62 mit dem Alphabet
`0-9A-Za-z` umgewandelt (`base62`). Da `Enc` und jede Feistel-Runde bijektiv
sind, ist die gesamte Kette bei bekanntem Secret exakt umkehrbar.
