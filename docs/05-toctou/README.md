# Napad #5 - TOCTOU / Race Condition

## Šta je to 

**TOCTOU** = "Time Of Check To Time Of Use" (vreme provere nije isto kad i vreme upotrebe).

Kartica ima 100 RSD. Kupovina radi u dva koraka:
1. **provera**: "ima li 100?" -> da
2. **oduzimanje**: skini 100

Ako između ta dva koraka prođe i delić sekunde, a stigne **više zahteva istovremeno**,
svi prođu korak 1 (svi vide 100) pre nego što iko stigne do koraka 2. Rezultat: 10 kupovina
od po 100 sa kartice koja ima samo 100, pa balans ode u minus. To je **race condition**.

## Dve grane

- **Ranjiva**: provera i oduzimanje su odvojeni, bez zaključavanja, pa imaš duplo trošenje.
- **Bezbedna**: provera i oduzimanje su **atomični** (`lock`), jedan po jedan, pa samo jedna kupovina prođe.

## Kako demonstrirati

UI: izaberi "5. TOCTOU", postavi npr. 10 istovremenih zahteva, klikni obe grane.
Uporedi `successfulPurchases` i `finalBalance`.


curl "http://localhost:5080/api/toctou/vulnerable/run?concurrency=10"  # ~10 prošlo, balans negativan
curl "http://localhost:5080/api/toctou/secure/run?concurrency=10"      # 1 prošlo, balans 0
```

## Kako se brani

- **Atomične operacije**: `lock`, DB transakcija sa odgovarajućim nivoom izolacije,
  ili `UPDATE ... WHERE balance >= 100` (uslov i izmena u jednom koraku).
- **Optimističko zaključavanje** (verzija reda / rowversion).
- Jedinstveni constraint / idempotentni ključ da se isti zahtev ne obradi dvaput.

Kod: [`ToctouModule.cs`](../../src/SecurityLab.Api/Attacks/Toctou/ToctouModule.cs)
