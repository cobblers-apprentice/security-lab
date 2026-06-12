# Napad #4 - JWT eksploatacija (automatizovani alat)

## Šta je to 

**JWT** (JSON Web Token) je "propusnica" koju server da korisniku posle prijave. Sastoji se
iz tri dela odvojena tačkom: `header.payload.potpis`. U `payload`-u piše npr. `role: user`.
**Potpis** služi da niko ne može da menja sadržaj, ali samo ako ga server pravilno proverava.

Dve klasične greške servera:
1. **`alg: none`**: token kaže "nemam potpis", a server mu ipak veruje.
2. **Slab ključ**: token je potpisan, ali ključem koji se lako pogodi (`secret`, `123456`...).

Ako postoji bilo koja od ove dve greške, napadač sam napravi token sa `role: admin` i postaje admin.

## Dve grane

| | Ranjiva | Bezbedna |
|---|---|---|
| `alg: none` | prihvata (bez potpisa!) | odbija (samo HS256) |
| Ključ | slab `secret` | jak, dugačak, tajan |
| Potpis | ne proverava se pravilno | obavezno validan |

Endpoint `/attack` je **alat** koji automatski iskuje admin tokene obema tehnikama i proba ih.

## Kako demonstrirati

UI: izaberi "4. JWT eksploatacija", klikni obe grane. Pogledaj `steps`, vidiš iskovane tokene
i da li su prihvaćeni.


curl "http://localhost:5080/api/jwt/vulnerable/attack"   # adminAccessGranted: true
curl "http://localhost:5080/api/jwt/secure/attack"       # adminAccessGranted: false
```

## Kako se brani

- Nikad ne prihvataj `alg: none`; fiksiraj očekivani algoritam (npr. samo `HS256` ili `RS256`).
- Jak, nasumičan, tajan ključ (bar 32 bajta), nikad u kodu/repou.
- Uvek proveri potpis, `exp` (isticanje), `iss`/`aud`.
- Koristi proverenu biblioteku, ne ručnu validaciju.

Kod: [`JwtModule.cs`](../../src/SecurityLab.Api/Attacks/Jwt/JwtModule.cs) · [`Jwt.cs`](../../src/SecurityLab.Api/Attacks/Jwt/Jwt.cs)
