# Napad #3 - Nesiguran Upload Fajla (+ WAF)

## Šta je to 

Aplikacija dozvoljava upload (npr. profilna slika) i posle taj fajl **servira** na nekom
URL-u, npr. `/uploads/slika.png`.

Problem nastaje ako server prima **bilo koji** fajl i servira ga **pod originalnim imenom
i tipom**. Tada mogu da pošaljem fajl koji nije slika nego **kod**:

- `evil.html` sa `<script>...</script>`: kad ga neko otvori, izvrši se moj JavaScript
  (stored XSS) jer ga server servira kao `text/html`.
- `shell.php.png`: **dvostruka ekstenzija**, na pogrešno podešenom serveru izvrši se kao PHP.
- `slika.png` ali je sadržaj zapravo skripta, pa oslanjanje samo na ekstenziju vara.

To je **Unrestricted / Insecure File Upload**.

---

## Dve grane

### Ranjiva grana
Prima bilo koji fajl, čuva ga pod **originalnim imenom** i servira.

```
POST /api/file-upload/vulnerable   (multipart, polje "file" = evil.html)
-> { "url": "/uploads/evil.html" }
```

Otvoriš taj URL i skripta se izvrši. **Napad uspeva.**

### Bezbedna grana
**WAF** pregleda upload pre čuvanja i blokira ako:
- ekstenzija nije na **beloj listi** (`.png .jpg .pdf .txt .csv`) ili je opasna (`.html .php .aspx` ...),
- **magic bytes** (pravi potpis sadržaja) ne odgovaraju ekstenziji,
- ime fajla ima putanju (`../`), null bajt ili **dvostruku ekstenziju**,
- fajl je prevelik,
- sadržaj "miriše" na kod (`<script`, `<?php`, `<%`).

Ako prođe, čuva se pod **nasumičnim bezbednim imenom** (`guid.png`).

```
POST /api/file-upload/secure   (evil.html)  -> HTTP 403 (WAF)
POST /api/file-upload/secure   (prava .png) -> sačuvano kao guid.png
```

---

## Kako demonstrirati

**Preko UI-ja:** izaberi "3. File Upload", iz padajuće liste izaberi "evil.html sa `<script>`",
pa klikni obe grane. Na ranjivoj grani dobiješ link "Otvori sačuvani fajl", klikni i vidi da se
HTML izvršava. Probaj i "dvostruka ekstenzija" i "čist PNG".

**Preko terminala:**

# Napravi zlonameran HTML
printf '<script>alert(1)</script>' > evil.html

# Napad na ranjivu granu, fajl se sačuva i servira
curl -F "file=@evil.html;type=text/html" http://localhost:5080/api/file-upload/vulnerable

# Isti fajl na bezbednu granu, WAF blokira
curl -F "file=@evil.html;type=text/html" http://localhost:5080/api/file-upload/secure
```

---

## Zašto se dešava i kako se brani

| Uzrok | Odbrana |
|-------|---------|
| Prima se bilo koja ekstenzija | **Bela lista** dozvoljenih ekstenzija |
| Veruje se Content-Type / imenu | Proveri **magic bytes** (pravi sadržaj) |
| Čuva se originalno ime | Generiši **nasumično ime**, ukloni putanju |
| Upload folder je izvršiv / servira HTML | Čuvaj van web root-a ili serviraj kao download (`Content-Disposition`) |
| Nema provere sadržaja | "Sniff", odbij fajl koji sadrži `<script>`, `<?php` ... |

**Pravilo:** ne veruj ni imenu ni tipu koji je poslao klijent, proveri sam sadržaj,
i nikad ne serviraj upload kao izvršni/HTML sadržaj.

Kod: [`FileUploadModule.cs`](../../src/SecurityLab.Api/Attacks/FileUpload/FileUploadModule.cs) ·
WAF pravila: [`Waf.cs`](../../src/SecurityLab.Api/Infrastructure/Waf/Waf.cs) (`InspectUpload`)
