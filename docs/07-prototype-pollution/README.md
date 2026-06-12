# Napad #7 - Prototype Pollution (JavaScript)

## Šta je to 

Ovo je ranjivost **JavaScript jezika**. U JS-u svaki objekat "nasleđuje" osobine od
zajedničkog `Object.prototype`. Ako uspeš da promeniš `Object.prototype`, promenio si
**sve objekte odjednom**.

Mnoge funkcije za "spajanje" objekata (deep merge) naivno kopiraju ključeve iz korisničkog
JSON-a. Ako pošalješ JSON sa specijalnim ključem `__proto__`:

```json
{ "__proto__": { "isAdmin": true } }
```

naivni merge upiše `isAdmin: true` u `Object.prototype`. Posle toga **bilo koji** objekat u
aplikaciji (čak i prazan `{}`) ima `isAdmin === true`, što znači zaobilaženje provera i eskalaciju prava.

> Pošto je vuln vezan za JS, ova demonstracija se izvršava **u browseru** (vidi `app.js`).

## Dve grane

- **Ranjivi merge**: kopira i ključ `__proto__`, pa zagadi `Object.prototype`.
- **Bezbedni merge**: preskače `__proto__`, `constructor`, `prototype`.

## Kako demonstrirati

UI: izaberi "7. Prototype Pollution", ostavi payload, klikni obe grane. Posle "napada" se pravi
prazan objekat `{}` i proverava da li je "postao" admin.

- Ranjiva grana: `fresh.isAdmin === true` (zagađeno!).
- Bezbedna grana: `fresh.isAdmin === undefined` (čisto).

## Kako se brani

- U merge-u **preskoči** `__proto__`/`constructor`/`prototype`.
- Koristi `Object.create(null)` (objekat bez prototipa) ili `Map` za korisničke podatke.
- `Object.freeze(Object.prototype)`.
- Validiraj ulaz šemom (npr. Zod/Ajv) i ne radi slepi deep-merge nepoznatog JSON-a.

Kod (server meta): [`PrototypePollutionModule.cs`](../../src/SecurityLab.Api/Attacks/PrototypePollution/PrototypePollutionModule.cs) ·
demo (JS): `wwwroot/app.js`, funkcija `runPrototypePollution`
