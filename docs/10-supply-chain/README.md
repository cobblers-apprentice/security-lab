# Napad #10 - Supply Chain (kompromitovana zavisnost, npr. Axios)

## Šta je to 

Ne napada se **tvoj** kod, nego **biblioteka** koju koristiš. Moderne aplikacije povuku stotine
paketa (`npm install`, NuGet...). Ako napadač objavi zlonamernu verziju popularnog paketa
(preuzme nalog autora, typosquatting - `axioss` umesto `axios`, itd.), njegov kod se izvrši
**unutar tvoje aplikacije** čim je instaliraš, npr. ukrade env tajne (`JWT_SIGNING_KEY`,
`DB_PASSWORD`, `STRIPE_KEY`).

Ovo se stvarno dešavalo (event-stream, ua-parser-js, razni npm paketi...).

## Dve grane

- **Ranjiva**: aplikacija slepo koristi instaliranu verziju (`^1.0.0` povuče backdoor `1.0.1`).
  Backdoor pri pokretanju iscuri tajne napadaču.
- **Bezbedna**: pre upotrebe proverava **integritet** paketa, hash iz lockfile-a
  (`package-lock.json` "integrity" / Subresource Integrity). Ako se hash ne poklapa sa
  poznatim-dobrim, odbija da učita paket.

## Kako demonstrirati

UI: izaberi "10. Supply Chain", klikni obe grane.


# Ranjiva, backdoor ukrao 3 tajne
curl "http://localhost:5080/api/supply-chain/vulnerable/install-and-run"

# Bezbedna, integritet se ne poklapa, instalacija odbijena
curl "http://localhost:5080/api/supply-chain/secure/install-and-run"
```

## Kako se brani

- **Lockfile + integrity hash** (`npm ci`, ne `npm install`); ne dozvoli "plutajuće" verzije.
- **Piniraj verzije** i revizije; automatski SCA skeneri (Dependabot, `npm audit`, Snyk).
- Verifikuj potpise/proveniens (Sigstore, npm provenance).
- Minimizuj broj zavisnosti; pregledaj nove i velike skokove verzija.

Kod: [`SupplyChainModule.cs`](../../src/SecurityLab.Api/Attacks/SupplyChain/SupplyChainModule.cs)
