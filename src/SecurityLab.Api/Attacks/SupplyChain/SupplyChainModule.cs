using System.Security.Cryptography;
using System.Text;
using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.SupplyChain;

/// <summary>
/// NAPAD #10: Supply Chain (kompromitovana zavisnost, npr. "axios").
///
/// Ne napada se tvoj kod, nego BIBLIOTEKA koju koristiš. Napadač objavi zlonamernu
/// verziju popularnog paketa (preuzet nalog, typosquatting...). Kad je instaliraš,
/// njen kod (sa backdoor-om) se izvrši u tvojoj aplikaciji i recimo ukrade env tajne.
///
/// Ranjiva grana slepo koristi instaliranu verziju (^1.0.0 povuče 1.0.1 sa backdoor-om).
/// Bezbedna grana proverava INTEGRITET paketa preko hash-a iz lockfile-a, pa ako se hash
/// ne poklapa sa poznatim-dobrim, odbija da ga učita (isto kao npm integrity ili SRI).
/// </summary>
public sealed class SupplyChainModule : IAttackModule
{
    // "Izvor" paketa. Backdoor verzija ima jednu dodatnu liniju koja krade tajne.
    private const string CleanPackageSource = "axios@1.0.0::function get(url){ return fetch(url); }";
    private const string BackdooredPackageSource = "axios@1.0.1::function get(url){ exfiltrate(process.env); return fetch(url); }";

    // Hash poznate-dobre verzije, zapisan u lockfile-u (package-lock.json "integrity").
    private static readonly string KnownGoodIntegrity = Sha256(CleanPackageSource);

    private static readonly Dictionary<string, string> EnvSecrets = new()
    {
        ["JWT_SIGNING_KEY"] = "G7!kP2$wq9_Zx4r8",
        ["DB_PASSWORD"] = "Sup3rT@jna!2026",
        ["STRIPE_KEY"] = "sk_live_51H...."
    };

    public AttackMeta Meta => new(
        Id: "supply-chain",
        Number: 10,
        Title: "Supply Chain (Axios)",
        Category: "Dependency",
        Summary: "Kompromitovana verzija paketa krade env tajne. Bezbedna grana proverava integritet (lockfile hash).");

    public void Map(RouteGroupBuilder group)
    {
        // Simuliram da je u registry-ju trenutno objavljena backdoor verzija (1.0.1).
        group.MapGet("/vulnerable/install-and-run", () => Run(secure: false));
        group.MapGet("/secure/install-and-run", () => Run(secure: true));
    }

    private static IResult Run(bool secure)
    {
        var installed = BackdooredPackageSource;        // ono što je registry vratio
        var installedIntegrity = Sha256(installed);

        if (secure)
        {
            // Proveri hash protiv lockfile-a PRE izvršavanja.
            if (installedIntegrity != KnownGoodIntegrity)
            {
                return Results.Json(new
                {
                    mode = "secure",
                    blocked = true,
                    expectedIntegrity = KnownGoodIntegrity,
                    actualIntegrity = installedIntegrity,
                    exfiltratedSecrets = Array.Empty<string>(),
                    message = "Blokirano: integritet paketa se ne poklapa sa lockfile-om, instalacija odbijena."
                }, statusCode: 409);
            }
            return Results.Json(new { mode = "secure", blocked = false, message = "Integritet OK, paket učitan." });
        }

        // Ranjivo: izvrši instalirani paket bez provere, pa backdoor opali.
        var stolen = ExecuteBackdoorIfPresent(installed);
        return Results.Json(new
        {
            mode = "vulnerable",
            blocked = false,
            installedVersion = "axios@1.0.1",
            exfiltratedSecrets = stolen,
            message = stolen.Length > 0
                ? $"USPEO NAPAD: backdoor u zavisnosti je ukrao {stolen.Length} tajni i poslao ih napadaču!"
                : "Paket izvršen."
        });
    }

    // Simulacija: ako "izvor" sadrži poziv exfiltrate(...), backdoor pošalje tajne napadaču.
    private static string[] ExecuteBackdoorIfPresent(string source) =>
        source.Contains("exfiltrate(process.env)")
            ? EnvSecrets.Select(kv => $"{kv.Key}={kv.Value}").ToArray()
            : Array.Empty<string>();

    private static string Sha256(string s) =>
        "sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
}
