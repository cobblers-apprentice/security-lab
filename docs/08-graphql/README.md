# Napad #8 - GraphQL Injection / Curenje podataka

## Šta je to 

**GraphQL** je način da klijent traži tačno koja polja hoće, jednim upitom:
`{ users { id name } }`. Moćno, ali ume da iscuri podatke ako server nije pažljiv.

Dve česte greške:
1. **Introspekcija uključena u produkciji**: postoji ugrađeni upit `__schema` koji vrati
   celu šemu (sva polja, tipove). Napadač tako otkrije "skrivena" polja kao `passwordHash`.
2. **Nema autorizacije po polju**: napadač jednostavno doda `passwordHash role` u upit i
   server ih vrati, jer proverava pristup tipu ali ne i pojedinačnim poljima.

## Dve grane

- **Ranjiva**: introspekcija dozvoljena; vraća bilo koje traženo polje (i `passwordHash`).
- **Bezbedna**: introspekcija isključena; osetljiva polja blokirana; limit veličine upita.

## Kako demonstrirati

UI: izaberi "8. GraphQL Injection", probaj sva tri upita iz liste na obe grane.


# Napad, izvuci passwordHash
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name passwordHash role } }"}' \
  http://localhost:5080/api/graphql/vulnerable

# Isti upit na bezbednu granu, blokiran
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name passwordHash role } }"}' \
  http://localhost:5080/api/graphql/secure
```

> Napomena: ovo je namerno **pojednostavljen** GraphQL (dovoljan da prikaže oba propusta),
> nije pun GraphQL engine.

## Kako se brani

- **Isključi introspekciju** u produkciji.
- **Autorizacija po polju** (field-level): osetljiva polja samo za ovlašćene.
- **Limit dubine i složenosti** upita (zaštita od DoS-a ugnežđenim upitima).
- Parametrizovani resolveri (nikad konkatenacija ulaza u bazni upit).
- Rate-limiting i isključen batching ako nije potreban.

Kod: [`GraphQLModule.cs`](../../src/SecurityLab.Api/Attacks/GraphQL/GraphQLModule.cs)
