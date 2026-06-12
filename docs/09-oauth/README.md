# Napad #9 - OAuth 2.0 propusti

## Šta je to 

**OAuth 2.0** je "prijavi se preko Google/Facebook" tok. Pojednostavljeno:
1. korisnik ode na server za autorizaciju,
2. server vrati privremeni **`code`** na adresu **`redirect_uri`**,
3. aplikacija taj `code` zameni za pristupni token.

Dve klasične greške:
1. **`redirect_uri` se ne proverava**: napadač podmetne svoj `redirect_uri`, pa `code`
   (a time i nalog žrtve) ode **napadaču** (account takeover).
2. **Nema `state` parametra**: nedostaje zaštita od CSRF na sam tok prijave.

## Dve grane

- **Ranjiva**: prihvata bilo koji `redirect_uri`, ne traži `state`.
- **Bezbedna**: `redirect_uri` mora **tačno** da bude na listi registrovanih; `state` obavezan.

## Kako demonstrirati

UI: izaberi "9. OAuth 2.0", ostavi napadački `redirect_uri`, klikni obe grane.
Pogledaj `redirectTo`, na ranjivoj grani `code` ide na `evil.attacker.com`.


# Napad, code ode napadaču
curl "http://localhost:5080/api/oauth/vulnerable/authorize?redirect_uri=https://evil.attacker.com/callback"

# Bezbedna, odbijen neregistrovan redirect_uri
curl "http://localhost:5080/api/oauth/secure/authorize?redirect_uri=https://evil.attacker.com/callback&state=abc"
```

## Kako se brani

- **Tačno poklapanje** `redirect_uri` sa unapred registrovanim (bez wildcard/"startsWith").
- Obavezan i proveren **`state`** (CSRF), idealno i **PKCE** za javne klijente.
- Kratko trajanje `code`-a, jednokratna upotreba, vezivanje za klijenta.

Kod: [`OAuthModule.cs`](../../src/SecurityLab.Api/Attacks/OAuth/OAuthModule.cs)
