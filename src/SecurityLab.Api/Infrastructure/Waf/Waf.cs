using System.Text;
using System.Text.RegularExpressions;

namespace SecurityLab.Api.Infrastructure.Waf;

/// <summary>Jedan okidač WAF pravila: koje pravilo se aktiviralo i zašto.</summary>
public record WafFinding(string Rule, string Detail);

/// <summary>Rezultat WAF inspekcije. Ako ima nalaza, zahtev se blokira.</summary>
public class WafResult
{
    public List<WafFinding> Findings { get; } = new();
    public bool Blocked => Findings.Count > 0;
    public void Add(string rule, string detail) => Findings.Add(new WafFinding(rule, detail));
}

/// <summary>
/// Mini Web Application Firewall.
/// Ideja je da pre nego što zahtev dođe do "secure" rute ovde proverim ulaz
/// protiv poznatih obrazaca napada. Ako prepoznam napad, blokiram (HTTP 403).
/// Namerno je jednostavno i čitljivo radi učenja, ovo nije production WAF.
/// </summary>
public static class Waf
{
    // === PATH TRAVERSAL ===

    private static readonly string[] TraversalTokens =
    {
        "../", "..\\", "%2e%2e", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e%5c",
        "..%c0%af", "..%252f"  // dvostruko / over-long enkodovanje
    };

    public static WafResult InspectPath(string raw)
    {
        var result = new WafResult();
        if (string.IsNullOrEmpty(raw)) return result;

        // Dekodiramo nekoliko puta da uhvatimo i enkodovane napade (%2e%2e -> ..)
        var decoded = MultiUrlDecode(raw).ToLowerInvariant();

        foreach (var token in TraversalTokens)
        {
            if (decoded.Contains(token))
                result.Add("PATH_TRAVERSAL", $"Pronađen obrazac putanje '{token}' u ulazu '{raw}'.");
        }

        if (decoded.Contains("..")) // bilo koje "izađi iz foldera"
            result.Add("PATH_TRAVERSAL", "Ulaz sadrži '..' (pokušaj izlaska iz osnovnog direktorijuma).");

        if (raw.StartsWith('/') || raw.StartsWith('\\') || Regex.IsMatch(raw, @"^[a-zA-Z]:"))
            result.Add("ABSOLUTE_PATH", "Ulaz je apsolutna putanja (npr. /etc/passwd ili C:\\...).");

        if (raw.Contains('\0'))
            result.Add("NULL_BYTE", "Ulaz sadrži null bajt (\\0), klasičan trik za zaobilaženje provere ekstenzije.");

        return result;
    }


    // Shell meta-karakteri koji omogućavaju lančanje / izvršavanje dodatnih komandi.
    private static readonly char[] ShellMetacharacters =
        { ';', '&', '|', '`', '$', '>', '<', '\n', '\r', '(', ')', '{', '}' };

    private static readonly string[] DangerousCommands =
    {
        "whoami", "cat ", "type ", "curl", "wget", "nc ", "bash", "sh ", "powershell",
        "cmd", "rm ", "del ", "ping", "ls ", "dir ", "&&", "||", "$(", "..", "/etc/"
    };

    public static WafResult InspectCommandArg(string raw)
    {
        var result = new WafResult();
        if (string.IsNullOrEmpty(raw)) return result;

        var found = raw.Where(c => ShellMetacharacters.Contains(c)).Distinct().ToArray();
        if (found.Length > 0)
            result.Add("COMMAND_INJECTION",
                $"Ulaz sadrži shell meta-karakter(e): {string.Join(' ', found.Select(c => $"'{c}'"))}.");

        var lower = raw.ToLowerInvariant();
        foreach (var cmd in DangerousCommands)
        {
            if (lower.Contains(cmd))
                result.Add("COMMAND_INJECTION", $"Ulaz sadrži sumnjiv token '{cmd.Trim()}'.");
        }

        return result;
    }

    // === FILE UPLOAD ===

    private static readonly string[] AllowedExtensions = { ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".csv" };

    private static readonly string[] DangerousExtensions =
    {
        ".aspx", ".asp", ".php", ".php5", ".phtml", ".jsp", ".jspx", ".exe", ".dll",
        ".sh", ".bat", ".cmd", ".ps1", ".html", ".htm", ".svg", ".js", ".cshtml"
    };

    // Magic bytes: pravi potpis sadržaja, da se ne oslanjam samo na ekstenziju i Content-Type.
    private static readonly Dictionary<string, byte[]> MagicBytes = new()
    {
        [".png"] = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
        [".jpg"] = new byte[] { 0xFF, 0xD8, 0xFF },
        [".jpeg"] = new byte[] { 0xFF, 0xD8, 0xFF },
        [".gif"] = new byte[] { 0x47, 0x49, 0x46, 0x38 },
        [".pdf"] = new byte[] { 0x25, 0x50, 0x44, 0x46 }, // %PDF
    };

    public const long MaxUploadBytes = 2 * 1024 * 1024; // 2 MB

    public static WafResult InspectUpload(string fileName, string contentType, byte[] head, long size)
    {
        var result = new WafResult();
        var name = (fileName ?? "").Trim();

        if (name.Length == 0)
        {
            result.Add("FILE_UPLOAD", "Ime fajla je prazno.");
            return result;
        }

        // 1) Putanja u imenu fajla (npr. ../../shell.aspx)
        if (name.Contains("..") || name.Contains('/') || name.Contains('\\'))
            result.Add("FILE_UPLOAD", "Ime fajla sadrži putanju ('..', '/' ili '\\').");

        // 2) Null bajt / dvostruka ekstenzija (shell.php.png)
        if (name.Contains('\0'))
            result.Add("FILE_UPLOAD", "Ime fajla sadrži null bajt.");
        var dots = name.Count(c => c == '.');
        if (dots > 1)
            result.Add("FILE_UPLOAD", $"Ime fajla ima više tačaka ('{name}'), moguća dvostruka ekstenzija.");

        // 3) Ekstenzija
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (DangerousExtensions.Contains(ext))
            result.Add("FILE_UPLOAD", $"Opasna ekstenzija '{ext}' (izvršni ili skriptni sadržaj).");
        else if (!AllowedExtensions.Contains(ext))
            result.Add("FILE_UPLOAD", $"Ekstenzija '{ext}' nije na beloj listi {string.Join(", ", AllowedExtensions)}.");

        // 4) Veličina
        if (size > MaxUploadBytes)
            result.Add("FILE_UPLOAD", $"Fajl je prevelik ({size} B > {MaxUploadBytes} B).");

        // 5) Magic bytes moraju da odgovaraju ekstenziji
        if (MagicBytes.TryGetValue(ext, out var sig))
        {
            if (head.Length < sig.Length || !head.Take(sig.Length).SequenceEqual(sig))
                result.Add("FILE_UPLOAD", $"Sadržaj ne odgovara ekstenziji '{ext}' (magic bytes se ne poklapaju).");
        }

        // 6) Sniff: skriptni sadržaj unutar "slike"
        var text = Encoding.ASCII.GetString(head).ToLowerInvariant();
        if (text.Contains("<script") || text.Contains("<?php") || text.Contains("<%"))
            result.Add("FILE_UPLOAD", "Sadržaj fajla izgleda kao izvršni kod (<script>, <?php, <%).");

        return result;
    }


    private static string MultiUrlDecode(string s)
    {
        var prev = s;
        for (var i = 0; i < 3; i++)
        {
            var dec = Uri.UnescapeDataString(prev);
            if (dec == prev) break;
            prev = dec;
        }
        return prev;
    }
}
