# Napad #2 - Command Injection (+ WAF)

## Šta je to 

Aplikacija ponekad poziva **sistemsku komandu** (kao kad ti u terminalu kucaš `ping`).
Recimo, alatka "proveri da li je host partnera dostupan":

```
echo Provera host-a: {host}
```

Ako aplikacija to ime host-a **zalepi u komandu i pošalje shell-u**, a ja umesto host-a
ukucam nešto sa specijalnim znakom (`&&`, `;`, `|`), mogu da **dopišem svoju komandu**:

```
host = x && whoami
postaje:  echo Provera host-a: x && whoami
```

Shell prvo odradi `echo`, pa onda **izvrši `whoami`**, moju komandu! Mogao bih i da
pročitam fajlove, povučem podatke, ili preuzmem server. To je **Command Injection**.

---

## Dve grane

### Ranjiva grana
Ulaz se lepi u komandu i izvršava kroz shell (`/bin/sh -c` ili `cmd.exe /c`).

```
GET /api/command-injection/vulnerable?host=x && whoami
```

Odgovor sadrži izlaz `whoami` (ime naloga pod kojim radi server). **Napad uspeva.**

### Bezbedna grana
Tri sloja odbrane:
1. **WAF** odbija shell meta-karaktere (`; & | $ ( )` ...) i sumnjive reči (`whoami`, `curl`...).
2. **Validacija**: host mora da odgovara obrascu validnog imena host-a (regex).
3. **Bez shell-a**: provera se radi bezbednim .NET API-jem `Dns.GetHostAddresses(host)`.
   Nema komandne linije, pa nema šta da se "injektuje".

```
GET /api/command-injection/secure?host=x && whoami   -> HTTP 403 (WAF)
GET /api/command-injection/secure?host=example.com    -> razrešene IP adrese
```

---

## Kako demonstrirati

**Preko UI-ja:** izaberi "2. Command Injection", ostavi `x && whoami`, klikni obe grane.

**Preko terminala:**

# Napad, izvrši se 'whoami'
curl "http://localhost:5080/api/command-injection/vulnerable?host=x%20%26%26%20whoami"

# Isti napad na bezbednu granu, blokiran
curl "http://localhost:5080/api/command-injection/secure?host=x%20%26%26%20whoami"

# Normalan host, bezbedna grana ga razreši bez shell-a
curl "http://localhost:5080/api/command-injection/secure?host=example.com"
```

> Napomena: `&&` radi i na Linux-u i na Windows-u. Na Linux-u radi i `;`, na Windows-u `&`.

---

## Zašto se dešava i kako se brani

| Uzrok | Odbrana |
|-------|---------|
| Ulaz se lepi u shell komandu | **Ne pozivaj shell** sa korisničkim ulazom |
| Koristi se string komanda | Ako baš moraš proces, koristi listu argumenata, ne string |
| Nema provere ulaza | Stroga validacija (bela lista / regex) |
| Eksterni proces bez potrebe | Najbolje: koristi ugrađeni API umesto eksternog procesa |

**Pravilo:** podaci nikad ne smeju da postanu deo komande. `whoami` u poznatom obliku
je crvena zastava da nešto izvršavaš što ne bi smeo.

Kod: [`CommandInjectionModule.cs`](../../src/SecurityLab.Api/Attacks/CommandInjection/CommandInjectionModule.cs) ·
WAF pravila: [`Waf.cs`](../../src/SecurityLab.Api/Infrastructure/Waf/Waf.cs) (`InspectCommandArg`)
