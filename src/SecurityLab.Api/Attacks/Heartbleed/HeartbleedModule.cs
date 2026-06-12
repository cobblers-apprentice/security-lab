using System.Text;
using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.Heartbleed;

/// <summary>
/// NAPAD #11: Heartbleed (OpenSSL CVE-2014-0160), simulacija.
///
/// TLS "heartbeat": klijent pošalje poruku i KAŽE koliko je dugačka, a server vrati
/// toliko bajtova nazad. Bug je u tome što server VERUJE prijavljenoj dužini i ne proverava je.
/// Ako klijent pošalje "hi" (2 bajta) ali kaže da je dužina 500, server pročita 500
/// bajtova iz memorije i vrati ih, a sa njima i SUSEDNE tajne (privatni ključ, sesije).
///
/// Ranjiva grana vrati 'length' bajtova iz bafera bez provere, to je over-read. Bezbedna
/// grana vrati najviše onoliko koliko je payload zaista dugačak.
/// </summary>
public sealed class HeartbleedModule : IAttackModule
{
    // "Memorija" servera: payload korisnika, a odmah do njega stoje tajne.
    private const string AdjacentSecrets =
        "SESSION=alice:9f3c...;PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----MIIEow...;PASSWORD=admin123";

    public AttackMeta Meta => new(
        Id: "heartbleed",
        Number: 11,
        Title: "Heartbleed (OpenSSL)",
        Category: "Crypto/TLS",
        Summary: "Buffer over-read kroz lažnu dužinu heartbeat-a curi susednu memoriju (ključeve). Bezbedna grana proverava dužinu.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable/heartbeat", (string? payload, int? length) => Beat(payload ?? "", length ?? 64, secure: false));
        group.MapGet("/secure/heartbeat", (string? payload, int? length) => Beat(payload ?? "", length ?? 64, secure: true));
    }

    private static IResult Beat(string payload, int claimedLength, bool secure)
    {
        // Memorijski bafer = payload + (susedne tajne koje "slučajno" stoje odmah do njega).
        var memory = Encoding.ASCII.GetBytes(payload + AdjacentSecrets);
        claimedLength = Math.Clamp(claimedLength, 0, memory.Length);

        if (secure)
        {
            // Ispravka: ne verujem prijavljenoj dužini, vraćam samo koliko je payload zaista dug.
            var safeLen = Math.Min(claimedLength, payload.Length);
            var echo = Encoding.ASCII.GetString(memory, 0, safeLen);
            return Results.Json(new
            {
                mode = "secure",
                payloadLength = payload.Length,
                claimedLength,
                returnedBytes = safeLen,
                returned = echo,
                blocked = claimedLength > payload.Length,
                message = claimedLength > payload.Length
                    ? "Provera dužine: vraćen je samo payload, susedna memorija NIJE procurela."
                    : "Heartbeat OK."
            });
        }

        // Ranjivo: vrati 'claimedLength' bajtova, pa čita preko payload-a u tajne.
        var leaked = Encoding.ASCII.GetString(memory, 0, claimedLength);
        var overRead = claimedLength > payload.Length;
        return Results.Json(new
        {
            mode = "vulnerable",
            payloadLength = payload.Length,
            claimedLength,
            returnedBytes = claimedLength,
            returned = leaked,
            blocked = false,
            message = overRead
                ? "USPEO NAPAD: pročitano je više od payload-a, susedna memorija (ključ/sesija/lozinka) je procurela!"
                : "Heartbeat OK (probaj length=200 da procuriš memoriju)."
        });
    }
}
