using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using SecurityLab.Api.Infrastructure;
using SecurityLab.Api.Infrastructure.Waf;

namespace SecurityLab.Api.Attacks.CommandInjection;

/// <summary>
/// NAPAD #2: Command Injection (ubacivanje sistemskih komandi).
///
/// Scenario: "campaign" servis ima alatku "provera dostupnosti host-a partnera".
/// Korisnik unese host: GET /api/command-injection/vulnerable?host=partner.example.com
///
/// Ranjiva grana host ubaci u shell komandu i izvrši je preko /bin/sh (ili cmd.exe), pa ako
/// pošalješ host = "x; whoami" izvrši se i 'whoami', tj. bilo koja komanda. Bezbedna grana
/// prvo pusti WAF da odbije shell meta-karaktere, zatim host proverim regexom i samu proveru
/// radim bezbednim .NET API-jem (Dns.GetHostAddresses), bez ikakvog shell-a.
/// </summary>
public sealed class CommandInjectionModule : IAttackModule
{
    private static readonly Regex ValidHostname = new(
        @"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
        RegexOptions.Compiled);

    public AttackMeta Meta => new(
        Id: "command-injection",
        Number: 2,
        Title: "Command Injection (+ WAF)",
        Category: "WAF",
        Summary: "Ubacivanje sistemskih komandi kroz korisnički ulaz. Bezbedna grana koristi WAF + validaciju + bez shell-a.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapGet("/vulnerable", (string? host) => RunVulnerable(host ?? ""));
        group.MapGet("/secure", (string? host) => RunSecure(host ?? ""));
    }

    private static IResult RunVulnerable(string host)
    {
        // Korisnički ulaz se ovde direktno lepi u komandu koju izvršava SHELL.
        var command = $"echo Provera host-a: {host} && echo --- status: OK ---";
        var (stdout, stderr, exit) = Shell.Run(command);

        return Results.Json(new
        {
            mode = "vulnerable",
            host,
            executedCommand = command,
            exitCode = exit,
            output = stdout,
            error = stderr,
            message = "Ulaz je izvršen kroz shell. Probaj host = 'x && whoami' i pogledaj izlaz."
        });
    }

    private static IResult RunSecure(string host)
    {
        var waf = Waf.InspectCommandArg(host);
        if (waf.Blocked)
        {
            return Results.Json(new
            {
                mode = "secure",
                host,
                blocked = true,
                findings = waf.Findings,
                message = "WAF je blokirao zahtev (HTTP 403)."
            }, statusCode: 403);
        }

        if (!ValidHostname.IsMatch(host))
        {
            return Results.Json(new
            {
                mode = "secure",
                host,
                blocked = true,
                findings = new[] { new WafFinding("HOSTNAME_VALIDATION", "Ulaz nije validno ime host-a.") },
                message = "Blokirano: nevažeće ime host-a."
            }, statusCode: 400);
        }

        // Bezbedno: nema shell-a, koristim .NET API za DNS proveru.
        string[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(host).Select(a => a.ToString()).ToArray();
        }
        catch
        {
            addresses = Array.Empty<string>();
        }

        return Results.Json(new
        {
            mode = "secure",
            host,
            blocked = false,
            resolvedAddresses = addresses,
            message = addresses.Length > 0
                ? "Host razrešen bezbednim API-jem (bez shell-a)."
                : "Host nije razrešen (ali ništa opasno nije izvršeno)."
        });
    }
}

/// <summary>Pokreće komandu kroz sistemski shell (služi samo za ranjivu demonstraciju).</summary>
internal static class Shell
{
    public static (string stdout, string stderr, int exit) Run(string command)
    {
        var psi = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            psi.FileName = "cmd.exe";
            psi.Arguments = $"/c {command}";
        }
        else
        {
            psi.FileName = "/bin/sh";
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(command);
        }

        try
        {
            using var p = Process.Start(psi)!;
            var outp = p.StandardOutput.ReadToEnd();
            var err = p.StandardError.ReadToEnd();
            p.WaitForExit(5000);
            return (outp.Trim(), err.Trim(), p.HasExited ? p.ExitCode : -1);
        }
        catch (Exception ex)
        {
            return ("", ex.Message, -1);
        }
    }
}
