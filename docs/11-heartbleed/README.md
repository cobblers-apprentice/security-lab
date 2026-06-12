# Napad #11 - Heartbleed (OpenSSL CVE-2014-0160)

## Šta je to 

Heartbleed je čuveni bug iz 2014. u OpenSSL-u (kriptografska biblioteka iza HTTPS-a).

TLS ima "heartbeat" (otkucaj srca): klijent pošalje poruku i **kaže koliko je dugačka**, a
server vrati tu istu poruku nazad. Bug: server je **verovao prijavljenoj dužini** i nije je
proverio. Pošalješ poruku `"hi"` (2 bajta) ali kažeš "dužina = 500", a server pročita 500
bajtova iz svoje memorije i pošalje ih nazad. Tih dodatnih ~498 bajtova je **susedna memorija**
servera, gde se zateknu lozinke, sesije, čak i **privatni TLS ključ**.

Pogubno jer: ne ostavlja trag, ne treba autentikacija, curi najosetljivije podatke.

## Dve grane

- **Ranjiva**: vrati `length` bajtova iz bafera bez provere, pa over-read u susednu memoriju.
- **Bezbedna**: vrati najviše onoliko koliko je payload **zaista** dugačak (provera dužine,
  upravo ono što je prava zakrpa uradila).

## Kako demonstrirati

UI: izaberi "11. Heartbleed", payload `hi`, dužina `200`, klikni obe grane. Pogledaj `returned`.


# Ranjiva, procuri "hi" + susedne tajne (ključ, sesija, lozinka)
curl "http://localhost:5080/api/heartbleed/vulnerable/heartbeat?payload=hi&length=200"

# Bezbedna, vrati samo "hi"
curl "http://localhost:5080/api/heartbleed/secure/heartbeat?payload=hi&length=200"
```

## Kako se brani

- **Proveri prijavljenu dužinu** protiv stvarne dužine primljenih podataka (granična provera).
- Ažuriraj OpenSSL (zakrpa iz 2014.); generalno, drži kripto biblioteke ažurnim.
- Posle ovakvog incidenta: **rotiraj ključeve i sertifikate** (mogli su iscuriti).
- Jezici/alati sa bezbednim baferima (bounds-checking) sprečavaju celu klasu over-read bagova.

Kod: [`HeartbleedModule.cs`](../../src/SecurityLab.Api/Attacks/Heartbleed/HeartbleedModule.cs)
