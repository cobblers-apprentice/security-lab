# Napad #1 - Path Traversal (+ WAF)

## Šta je to 

Aplikacija ti da fajl po imenu, npr. fakturu `invoice-1001.txt`.
Ona to ime **zalepi** na folder u kojem drži fakture i pročita fajl:

```
folder sa fakturama  +  ime fajla  =  fajl koji se čita
App_Data/sales-docs  +  invoice-1001.txt
```

Problem: ako u ime fajla ubacim `../` (što znači "idi jedan folder gore"),
mogu da **izađem iz foldera sa fakturama** i pročitam bilo koji fajl na serveru:

```
App_Data/sales-docs  +  ../secret/credentials.txt
= App_Data/secret/credentials.txt   (tajni fajl koji ne smem da vidim!)
```

To je **Path Traversal** (ili "directory traversal").

---

## Dve grane

### Ranjiva grana
Ime fajla se direktno spaja sa folderom, bez ikakve provere.

```
GET /api/path-traversal/vulnerable?file=../secret/credentials.txt
```

Rezultat: server vrati sadržaj tajnog fajla (DB lozinka, JWT ključ...). **Napad uspeva.**

### Bezbedna grana
Pre čitanja, **WAF** (Web Application Firewall) pregleda ulaz i traži obrasce napada:
`../`, `..\`, enkodovane varijante (`%2e%2e`), apsolutne putanje, null bajt.
Ako nešto od toga nađe, **blokira (HTTP 403)**.

Dodatno (pojas i tregeri): i kad bi WAF nešto propustio, proverava se da finalna
putanja i dalje pripada dozvoljenom folderu.

```
GET /api/path-traversal/secure?file=../secret/credentials.txt
-> HTTP 403, WAF našao "../"
```

---

## Kako demonstrirati

**Preko UI-ja:** izaberi "1. Path Traversal" iz liste, ostavi `../secret/credentials.txt`,
pa klikni redom obe grane.

**Preko terminala:**

# Napad na ranjivu granu, procuri tajni fajl
curl "http://localhost:5080/api/path-traversal/vulnerable?file=../secret/credentials.txt"

# Isti napad na bezbednu granu, blokiran
curl "http://localhost:5080/api/path-traversal/secure?file=../secret/credentials.txt"

# Normalan zahtev, radi na obe grane
curl "http://localhost:5080/api/path-traversal/vulnerable?file=invoice-1001.txt"
```

---

## Zašto se dešava i kako se brani

| Uzrok | Odbrana |
|-------|---------|
| Korisnički ulaz se koristi kao deo putanje | Nikad ne lepi sirov ulaz na putanju |
| Nema provere `../` | WAF / filter koji prepoznaje obrasce putanje |
| Ne proverava se finalna putanja | Kanonizuj putanju (`Path.GetFullPath`) i proveri da je unutar dozvoljenog foldera |
| Oslanjanje samo na ekstenziju | Bela lista dozvoljenih fajlova umesto slobodnog imena |

**Pravilo:** korisnik bira *šta* (npr. ID fakture), a server odlučuje *gde* je to na disku.

Kod: [`PathTraversalModule.cs`](../../src/SecurityLab.Api/Attacks/PathTraversal/PathTraversalModule.cs) ·
WAF pravila: [`Waf.cs`](../../src/SecurityLab.Api/Infrastructure/Waf/Waf.cs) (`InspectPath`)
