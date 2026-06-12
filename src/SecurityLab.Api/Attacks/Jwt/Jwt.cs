using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityLab.Api.Attacks.Jwt;

/// <summary>
/// Ručno napisana JWT implementacija da se vidi KAKO token izgleda iznutra: tri dela
/// razdvojena tačkom, base64url(header).base64url(payload).base64url(signature).
/// Namerno podržava i "alg":"none" i slab ključ, da bih mogao da demonstriram napade.
/// </summary>
internal static class Jwt
{
    public static string Encode(Dictionary<string, object> payload, string alg, string? secret)
    {
        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };
        var h = B64(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = B64(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signingInput = $"{h}.{p}";

        var sig = alg switch
        {
            "none" => "",
            "HS256" => B64(HmacSha256(signingInput, secret ?? "")),
            _ => throw new NotSupportedException(alg)
        };
        return $"{signingInput}.{sig}";
    }

    public static (Dictionary<string, JsonElement> header, Dictionary<string, JsonElement> payload, string signature, string signingInput)
        Decode(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2) throw new FormatException("Token nema 3 dela.");
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(UnB64(parts[0]))!;
        var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(UnB64(parts[1]))!;
        var sig = parts.Length > 2 ? parts[2] : "";
        return (header, payload, sig, $"{parts[0]}.{parts[1]}");
    }

    public static bool VerifyHs256(string signingInput, string signature, string secret)
    {
        var expected = B64(HmacSha256(signingInput, secret));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(signature));
    }

    private static byte[] HmacSha256(string data, string key)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return h.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    public static string B64(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] UnB64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }
}
