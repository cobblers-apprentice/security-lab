using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.Toctou;

/// <summary>
/// NAPAD #5: TOCTOU (Time-Of-Check To Time-Of-Use), tj. race condition.
///
/// Scenario: poklon-kartica ima 100 RSD. Endpoint "potroši 100" prvo PROVERI da li
/// ima dovoljno (check), pa onda ODUZME (use). Ako između provere i oduzimanja prođe
/// makar trenutak, više istovremenih zahteva svi vide 100 i svi potroše, pa imaš duplo trošenje.
///
/// Ranjiva grana proverava, napravi mali async razmak, pa oduzme, i to BEZ zaključavanja.
/// Bezbedna grana je atomična: lock obuhvata i proveru i oduzimanje.
///
/// /run?concurrency=N pokreće N istovremenih zahteva nad svežom karticom i meri ishod.
/// </summary>
public sealed class ToctouModule : IAttackModule
{
    private const int StartBalance = 100;
    private const int Cost = 100;

    public AttackMeta Meta => new(
        Id: "toctou",
        Number: 5,
        Title: "TOCTOU / Race Condition",
        Category: "Logika",
        Summary: "Duplo trošenje istog balansa kroz istovremene zahteve. Bezbedna grana koristi atomično zaključavanje.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable/run", (int? concurrency) => Run(concurrency ?? 10, useLock: false));
        group.MapGet("/secure/run", (int? concurrency) => Run(concurrency ?? 10, useLock: true));
    }

    private static async Task<IResult> Run(int concurrency, bool useLock)
    {
        concurrency = Math.Clamp(concurrency, 2, 50);
        var account = new Account { Balance = StartBalance };
        var gate = new object();

        var tasks = Enumerable.Range(0, concurrency).Select(async _ =>
        {
            if (useLock)
            {
                // Bezbedno: provera i oduzimanje su nedeljivi, ide jedan po jedan.
                lock (gate)
                {
                    if (account.Balance >= Cost) { account.Balance -= Cost; return true; }
                    return false;
                }
            }
            else
            {
                // Ranjivo: provera, pa razmak, pa oduzimanje. Svi vide isti balans.
                if (account.Balance >= Cost)
                {
                    await Task.Delay(15);          // realan razmak (DB poziv, mreža...)
                    account.Balance -= Cost;
                    return true;
                }
                return false;
            }
        });

        var results = await Task.WhenAll(tasks);
        var successful = results.Count(x => x);

        return Results.Json(new
        {
            mode = useLock ? "secure" : "vulnerable",
            concurrency,
            startBalance = StartBalance,
            cost = Cost,
            successfulPurchases = successful,
            finalBalance = account.Balance,
            blocked = useLock && successful <= 1,
            message = successful > 1
                ? $"USPEO NAPAD: {successful} kupovina po {Cost} iako kartica ima samo {StartBalance}! Balans: {account.Balance}."
                : "Samo jedna kupovina je prošla, race condition je sprečen."
        });
    }

    private sealed class Account { public int Balance; }
}
