using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.OAuth;

/// <summary>
/// NAPAD #9: OAuth 2.0 propusti (redirect_uri i state).
///
/// U OAuth toku server za autorizaciju vraća "code" na adresu redirect_uri, pa se prave
/// dve klasične greške. Prva je da se redirect_uri ne proverava, pa napadač podmetne svoj
/// i code (a sa njim i nalog) ode njemu, što je account takeover. Druga je nedostatak
/// "state" parametra, čime sam tok prijave ostaje otvoren za CSRF.
///
/// Ranjiva grana prihvata bilo koji redirect_uri i ne traži state. Bezbedna grana zahteva
/// da redirect_uri bude TAČNO na listi registrovanih i da state obavezno postoji.
/// </summary>
public sealed class OAuthModule : IAttackModule
{
    private static readonly string[] RegisteredRedirects =
    {
        "https://app.intellya-selecta.com/callback",
        "http://localhost:5080/callback"
    };

    public AttackMeta Meta => new(
        Id: "oauth",
        Number: 9,
        Title: "OAuth 2.0 propusti",
        Category: "Auth",
        Summary: "Krađa auth 'code'-a preko nevalidiranog redirect_uri + nedostatak state-a. Bezbedna grana strogo proverava oba.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable/authorize", (string? redirect_uri, string? state) => Authorize(redirect_uri, state, secure: false));
        group.MapGet("/secure/authorize", (string? redirect_uri, string? state) => Authorize(redirect_uri, state, secure: true));
    }

    private static IResult Authorize(string? redirectUri, string? state, bool secure)
    {
        redirectUri ??= "";
        var code = "AUTHCODE-" + Guid.NewGuid().ToString("N")[..12];

        if (secure)
        {
            if (!RegisteredRedirects.Contains(redirectUri, StringComparer.Ordinal))
                return Results.Json(new
                {
                    mode = "secure", blocked = true, rejectedRedirectUri = redirectUri,
                    message = $"Blokirano: redirect_uri '{redirectUri}' nije registrovan."
                }, statusCode: 400);

            if (string.IsNullOrEmpty(state))
                return Results.Json(new
                {
                    mode = "secure", blocked = true,
                    message = "Blokirano: nedostaje 'state' (zaštita od CSRF)."
                }, statusCode: 400);

            return Results.Json(new
            {
                mode = "secure", blocked = false,
                redirectTo = $"{redirectUri}?code={code}&state={state}",
                message = "OK: code ide samo na registrovan redirect_uri, uz proveren state."
            });
        }

        // Ranjivo: veruje baš svemu.
        var attacker = !RegisteredRedirects.Contains(redirectUri, StringComparer.Ordinal) && redirectUri.Length > 0;
        return Results.Json(new
        {
            mode = "vulnerable", blocked = false,
            redirectTo = $"{redirectUri}?code={code}",
            message = attacker
                ? $"USPEO NAPAD: 'code={code}' je poslat na napadačev redirect_uri '{redirectUri}'!"
                : "Code je izdat (redirect_uri se ne proverava, state se ne traži)."
        });
    }
}
