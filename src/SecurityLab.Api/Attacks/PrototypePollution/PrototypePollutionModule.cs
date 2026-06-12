using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.PrototypePollution;

/// <summary>
/// NAPAD #7: Prototype Pollution (specifičan za JavaScript).
///
/// Ovo je ranjivost JS jezika: ako nesigurna "deep merge" funkcija spoji korisnički
/// JSON sa ključem "__proto__", može da promeni Object.prototype, pa SVI objekti
/// odjednom dobiju npr. isAdmin=true.
///
/// Pošto je sve vezano za JS, sama demonstracija se izvršava u browseru (vidi app.js),
/// a ovaj modul postoji da se napad pojavi u listi i da poveže README.
/// /demo vraća kratko objašnjenje i primer payload-a.
/// </summary>
public sealed class PrototypePollutionModule : IAttackModule
{
    public AttackMeta Meta => new(
        Id: "prototype-pollution",
        Number: 7,
        Title: "Prototype Pollution (JS)",
        Category: "JavaScript",
        Summary: "Nesiguran merge sa '__proto__' menja Object.prototype. Demo se izvršava u browseru.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/demo", () => Results.Json(new
        {
            note = "Demonstracija je client-side (JavaScript). Pokreni je iz UI-ja.",
            maliciousPayload = "{ \"__proto__\": { \"isAdmin\": true } }",
            vulnerableMerge = "rekurzivni merge koji kopira i ključ __proto__",
            secureMerge = "merge koji preskače __proto__/constructor/prototype (ili Map/Object.create(null))"
        }));
    }
}
