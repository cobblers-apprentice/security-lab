using SecurityLab.Api.Infrastructure;
using SecurityLab.Api.Infrastructure.Waf;

namespace SecurityLab.Api.Attacks.FileUpload;

/// <summary>
/// NAPAD #3: Nesiguran upload fajla (Unrestricted File Upload).
///
/// Scenario: "party" servis dozvoljava upload profilne slike koja se posle servira
/// kao statički fajl na /uploads/...
///
/// Ranjiva grana primi BILO KOJI fajl pod originalnim imenom i servira ga, pa upload
/// "evil.html" sa &lt;script&gt; znači stored XSS, tj. izvršni sadržaj. Bezbedna grana pušta
/// WAF da proveri ekstenziju (bela lista), magic bytes, veličinu, dvostruku ekstenziju,
/// null bajt i skriptni sadržaj, a fajl čuva pod bezbednim imenom.
/// </summary>
public sealed class FileUploadModule : IAttackModule
{
    public AttackMeta Meta => new(
        Id: "file-upload",
        Number: 3,
        Title: "File Upload (+ WAF)",
        Category: "WAF",
        Summary: "Upload izvršnog/skriptnog fajla koji se servira nazad. Bezbedna grana koristi WAF (ekstenzija, magic bytes, sniff).");

    public void Map(RouteGroupBuilder group)
    {
        group.MapPost("/vulnerable", (IFormFile? file, IWebHostEnvironment env) => Handle(file, env, useWaf: false))
             .DisableAntiforgery();
        group.MapPost("/secure", (IFormFile? file, IWebHostEnvironment env) => Handle(file, env, useWaf: true))
             .DisableAntiforgery();
    }

    private static async Task<IResult> Handle(IFormFile? file, IWebHostEnvironment env, bool useWaf)
    {
        if (file is null || file.Length == 0)
            return Results.Json(new { message = "Nije priložen fajl (form field: 'file')." }, statusCode: 400);

        var webRoot = env.WebRootPath ?? Path.Combine(env.ContentRootPath, "wwwroot");
        var uploadsDir = Path.Combine(webRoot, "uploads");
        Directory.CreateDirectory(uploadsDir);

        // Učitaj prvih 512 bajtova za inspekciju sadržaja.
        byte[] head;
        await using (var s = file.OpenReadStream())
        {
            head = new byte[Math.Min(512, file.Length)];
            _ = await s.ReadAsync(head);
        }

        if (useWaf)
        {
            var waf = Waf.InspectUpload(file.FileName, file.ContentType, head, file.Length);
            if (waf.Blocked)
            {
                return Results.Json(new
                {
                    mode = "secure",
                    fileName = file.FileName,
                    blocked = true,
                    findings = waf.Findings,
                    message = "WAF je blokirao upload (HTTP 403)."
                }, statusCode: 403);
            }
        }

        // Ime pod kojim čuvam fajl. Ranjiva grana zadrži original (i opasnu ekstenziju),
        // bezbedna grana daje nasumično ime sa očišćenom ekstenzijom.
        string storedName;
        if (useWaf)
        {
            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            storedName = $"{Guid.NewGuid():N}{ext}";
        }
        else
        {
            storedName = Path.GetFileName(file.FileName); // i dalje ranjivo na dvostruku ekstenziju i sl.
        }

        var fullPath = Path.Combine(uploadsDir, storedName);
        await using (var fs = File.Create(fullPath))
        {
            await file.CopyToAsync(fs);
        }

        var url = $"/uploads/{storedName}";
        return Results.Json(new
        {
            mode = useWaf ? "secure" : "vulnerable",
            fileName = file.FileName,
            blocked = false,
            storedAs = storedName,
            url,
            message = useWaf
                ? "Fajl je prošao WAF i sačuvan pod bezbednim imenom."
                : $"USPEO UPLOAD: fajl je serviran na {url}, otvori ga u browseru i vidi da se izvršava!"
        });
    }
}
