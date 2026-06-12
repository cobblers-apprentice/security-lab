using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.HostHeader;

/// <summary>
/// NAPAD #6: Host Header Injection.
///
/// Scenario: "zaboravljena lozinka" pravi link za reset koristeći domen iz zahteva
/// (Host ili X-Forwarded-Host header). Aplikacija veruje tom headeru i ugradi ga u link
/// koji šalje mejlom žrtvi.
///
/// Napad: napadač pošalje zahtev sa X-Forwarded-Host: evil.attacker.com, žrtva dobije link
/// https://evil.attacker.com/reset?token=..., klikne na njega i token (a sa njim i nalog)
/// završi kod napadača.
///
/// Ranjiva grana uzme domen linka pravo iz headera i ništa ne proverava. Bezbedna grana
/// domen bira sa bele liste poverljivih domena, a nepoznat host odbija.
/// </summary>
public sealed class HostHeaderModule : IAttackModule
{
    private static readonly string[] TrustedHosts = { "app.intellya-selecta.com", "localhost:5080" };

    public AttackMeta Meta => new(
        Id: "host-header",
        Number: 6,
        Title: "Host Header Injection",
        Category: "Web",
        Summary: "Trovanje reset-linka preko Host/X-Forwarded-Host headera. Bezbedna grana koristi belu listu domena.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable/reset-link", (HttpRequest req) => Build(req, secure: false));
        group.MapGet("/secure/reset-link", (HttpRequest req) => Build(req, secure: true));
    }

    private static IResult Build(HttpRequest req, bool secure)
    {
        // Napadač kontroliše ovaj header (proxy ga obično prosledi).
        var forwarded = req.Headers["X-Forwarded-Host"].ToString();
        var hostFromRequest = !string.IsNullOrEmpty(forwarded) ? forwarded : req.Host.Value;
        var token = "RESET-" + Guid.NewGuid().ToString("N")[..12];

        if (!secure)
        {
            var link = $"https://{hostFromRequest}/reset?token={token}";
            return Results.Json(new
            {
                mode = "vulnerable",
                hostUsed = hostFromRequest,
                resetLink = link,
                blocked = false,
                message = forwarded.Length > 0
                    ? $"USPEO NAPAD: link pokazuje na napadačev domen '{forwarded}', token curi napadaču!"
                    : "Link je napravljen od Host headera (probaj da pošalješ X-Forwarded-Host)."
            });
        }

        // Bezbedno: koristi se isključivo poznat, konfigurisan domen, a header se ignoriše.
        if (forwarded.Length > 0 && !TrustedHosts.Contains(forwarded, StringComparer.OrdinalIgnoreCase))
        {
            return Results.Json(new
            {
                mode = "secure",
                hostUsed = (string?)null,
                blocked = true,
                rejectedHeader = forwarded,
                message = $"Blokirano: '{forwarded}' nije na beloj listi domena."
            }, statusCode: 400);
        }

        var trusted = TrustedHosts[0];
        return Results.Json(new
        {
            mode = "secure",
            hostUsed = trusted,
            resetLink = $"https://{trusted}/reset?token={token}",
            blocked = false,
            message = "Link je napravljen od poverljivog domena (header se ignoriše)."
        });
    }
}
