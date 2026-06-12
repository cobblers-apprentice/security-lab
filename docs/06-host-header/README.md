# Napad #6 - Host Header Injection

## Šta je to 

Kad klikneš "zaboravljena lozinka", server ti pošalje mejl sa linkom za reset:
`https://DOMEN/reset?token=...`. Pitanje je, odakle server uzima `DOMEN`?

Loša praksa: uzme ga iz **HTTP headera** zahteva (`Host` ili `X-Forwarded-Host`), kome veruje.
Ali taj header kontroliše onaj ko šalje zahtev. Napadač pošalje zahtev za reset tuđeg naloga,
ali podmetne `X-Forwarded-Host: evil.attacker.com`. Žrtva dobije mejl sa linkom koji pokazuje
na napadačev domen, pa kad klikne, **reset-token ode napadaču** i on preuzima nalog.

## Dve grane

- **Ranjiva**: domen u linku = vrednost iz headera. Napadač ga slobodno menja.
- **Bezbedna**: domen se uzima iz **bele liste** poznatih domena; nepoznat header se odbija/ignoriše.

## Kako demonstrirati

UI: izaberi "6. Host Header Injection", unesi `evil.attacker.com`, klikni obe grane.
Pogledaj `resetLink`.


# Ranjiva, link pokazuje na napadača
curl -H "X-Forwarded-Host: evil.attacker.com" "http://localhost:5080/api/host-header/vulnerable/reset-link"

# Bezbedna, odbijen nepoznat host
curl -H "X-Forwarded-Host: evil.attacker.com" "http://localhost:5080/api/host-header/secure/reset-link"
```

## Kako se brani

- Koristi **konfigurisan (fiksni) bazni URL** za generisanje linkova, ne header iz zahteva.
- Ako baš moraš da čitaš Host, proveri ga protiv **bele liste** dozvoljenih domena.
- Podesi reverse-proxy da postavi ispravan `Host` i odbaci neproverene `X-Forwarded-*`.

Kod: [`HostHeaderModule.cs`](../../src/SecurityLab.Api/Attacks/HostHeader/HostHeaderModule.cs)
