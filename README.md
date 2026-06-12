# Security Lab - Demonstracija Web Napada

Projekat koji na jednom mestu demonstrira tipične web napade.
**Svaki napad ima dve grane:**

- **RANJIVA grana** (`/vulnerable`): napad uspeva.
- **BEZBEDNA grana** (`/secure`): isti napad je zaustavljen (WAF, validacija, bezbedan API...).

U web interfejsu biraš napad iz **select liste**, pokreneš ga na obe grane i vidiš razliku.

> Napomena: sve ranjivosti su **namerne** i izolovane za učenje. Ne koristiti ništa od ovoga van ovog laba.

---

## Tehnologija

| Sloj | Tehnologija |
|------|-------------|
| Backend | ASP.NET Core **.NET 10** (Minimal API) |
| Frontend | HTML + **Tailwind** (CDN), jednostavan UI sa select listom |
| Pakovanje | Docker (jedan kontejner) |

Arhitektura je **modularna**: jedan napad = jedan modul koji se sam registruje
(`IAttackModule`). Dodavanje novog napada = jedan novi fajl + jedan red u `Program.cs`.

---

## Pokretanje (lokalno)

Potreban je **.NET 10 SDK**.


cd src/SecurityLab.Api
dotnet run
```

Zatim otvori adresu koju ispiše (npr. `http://localhost:5080`) u browseru.

### U VS Code (F5)

Otvori folder u VS Code, instaliraj preporučene ekstenzije (**C# Dev Kit**, VS Code ga ponudi
sam), pa pritisni **F5** i konfiguracija "Security Lab (.NET)" build-uje, pokrene server na
`http://localhost:5080` i otvori browser. Alternativno: `Terminal > Run Task > run`.

### Preko Dockera


docker compose up --build
# otvori http://localhost:8080
```

---

## Kako se demonstrira

1. Otvori web stranicu.
2. Iz **select liste** izaberi napad.
3. Pročitaj kratko objašnjenje na vrhu panela.
4. Klikni **"Pokreni na RANJIVOJ grani"** i vidiš da napad uspeva (crveno).
5. Klikni **"Pokreni na BEZBEDNOJ grani"** i vidiš da je napad blokiran (zeleno).
6. Uporedi "Zahtev" i "Odgovor servera" za obe grane.

Svaki napad ima i detaljan README u folderu [`docs/`](docs/).

---

## Spisak napada

| # | Napad | Status | README |
|---|-------|--------|--------|
| 1 | Path Traversal (+ WAF) | Gotovo | [docs/01-path-traversal](docs/01-path-traversal/README.md) |
| 2 | Command Injection (+ WAF) | Gotovo | [docs/02-command-injection](docs/02-command-injection/README.md) |
| 3 | File Upload (+ WAF) | Gotovo | [docs/03-file-upload](docs/03-file-upload/README.md) |
| 4 | JWT eksploatacija (alat) | Gotovo | [docs/04-jwt](docs/04-jwt/README.md) |
| 5 | TOCTOU / Race Condition | Gotovo | [docs/05-toctou](docs/05-toctou/README.md) |
| 6 | Host Header Injection | Gotovo | [docs/06-host-header](docs/06-host-header/README.md) |
| 7 | Prototype Pollution | Gotovo | [docs/07-prototype-pollution](docs/07-prototype-pollution/README.md) |
| 8 | GraphQL Injection | Gotovo | [docs/08-graphql](docs/08-graphql/README.md) |
| 9 | OAuth 2.0 propusti | Gotovo | [docs/09-oauth](docs/09-oauth/README.md) |
| 10 | Supply Chain (Axios) | Gotovo | [docs/10-supply-chain](docs/10-supply-chain/README.md) |
| 11 | Heartbleed (OpenSSL) | Gotovo | [docs/11-heartbleed](docs/11-heartbleed/README.md) |

Svih 11 napada je implementirano. Svaki ima ranjivu i bezbednu granu + README.

---

## Struktura projekta

```
src/SecurityLab.Api/
  Program.cs                      # registar napada + serviranje UI-ja
  Infrastructure/
    IAttackModule.cs              # interfejs koji svaki napad implementira
    Waf/Waf.cs                    # mini Web Application Firewall (pravila)
  Attacks/
    PathTraversal/                # napad #1
    CommandInjection/             # napad #2
    FileUpload/                   # napad #3
  wwwroot/
    index.html                    # UI sa select listom
    app.js                        # logika fronta (jedan unos po napadu)
docs/                             # README po napadu
Dockerfile, docker-compose.yml    # deploy
```

## Deploy na besplatan hosting

Projekat je jedan Docker kontejner, pa radi na Render / Railway / Fly.io (free tier).
Detalji su u [docs/DEPLOY.md](docs/DEPLOY.md).
