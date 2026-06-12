using SecurityLab.Api.Infrastructure;
using SecurityLab.Api.Infrastructure.Waf;

namespace SecurityLab.Api.Attacks.PathTraversal;

/// <summary>
/// NAPAD #1: Path Traversal (čitanje fajlova van dozvoljenog foldera).
///
/// Scenario: "sale" servis nudi preuzimanje faktura iz foldera App_Data/sales-docs.
/// Korisnik traži fajl po imenu: GET /api/path-traversal/vulnerable?file=invoice-1001.txt
///
/// Ranjiva grana ime fajla direktno spoji sa folderom, pa '../' izađe iz foldera i pročita
/// bilo šta (recimo ../secret/credentials.txt). Bezbedna grana pušta WAF da prepozna '../'
/// i enkodovane varijante, a uz to još jednom proverim da finalna putanja zaista ostaje
/// unutar dozvoljenog foldera.
/// </summary>
public sealed class PathTraversalModule : IAttackModule
{
    public AttackMeta Meta => new(
        Id: "path-traversal",
        Number: 1,
        Title: "Path Traversal (+ WAF)",
        Category: "WAF",
        Summary: "Čitanje fajlova van dozvoljenog foldera pomoću '../'. Bezbedna grana koristi WAF + proveru putanje.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable", (string? file, IWebHostEnvironment env) => Handle(file, env, useWaf: false));
        group.MapGet("/secure", (string? file, IWebHostEnvironment env) => Handle(file, env, useWaf: true));
    }

    private static IResult Handle(string? file, IWebHostEnvironment env, bool useWaf)
    {
        file ??= "";
        var baseDir = DemoData.EnsureSalesDocs(env.ContentRootPath);

        if (useWaf)
        {
            var waf = Waf.InspectPath(file);
            if (waf.Blocked)
            {
                return Results.Json(new
                {
                    mode = "secure",
                    requestedFile = file,
                    blocked = true,
                    findings = waf.Findings,
                    message = "WAF je blokirao zahtev (HTTP 403)."
                }, statusCode: 403);
            }
        }

        // Spajanje korisničkog ulaza sa folderom.
        var combined = Path.Combine(baseDir, file);
        var resolved = Path.GetFullPath(combined);

        // Bezbedna grana: još jedna provera da finalna putanja ne izlazi iz baseDir.
        if (useWaf && !resolved.StartsWith(Path.GetFullPath(baseDir) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            return Results.Json(new
            {
                mode = "secure",
                requestedFile = file,
                blocked = true,
                findings = new[] { new WafFinding("PATH_CANONICALIZATION", $"Finalna putanja '{resolved}' je van dozvoljenog foldera.") },
                message = "Blokirano: putanja izlazi iz dozvoljenog foldera."
            }, statusCode: 403);
        }

        if (!File.Exists(resolved))
        {
            return Results.Json(new
            {
                mode = useWaf ? "secure" : "vulnerable",
                requestedFile = file,
                blocked = false,
                resolvedPath = resolved,
                message = "Fajl ne postoji."
            }, statusCode: 404);
        }

        var content = File.ReadAllText(resolved);
        var escaped = resolved.StartsWith(Path.GetFullPath(baseDir), StringComparison.OrdinalIgnoreCase) == false;

        return Results.Json(new
        {
            mode = useWaf ? "secure" : "vulnerable",
            requestedFile = file,
            blocked = false,
            resolvedPath = resolved,
            escapedBaseFolder = escaped,
            content,
            message = escaped
                ? "USPEO NAPAD: pročitan je fajl IZVAN dozvoljenog foldera!"
                : "Pročitan dozvoljeni fajl."
        });
    }
}
