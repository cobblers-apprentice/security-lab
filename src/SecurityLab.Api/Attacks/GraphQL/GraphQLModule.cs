using System.Text.Json;
using SecurityLab.Api.Infrastructure;

namespace SecurityLab.Api.Attacks.GraphQL;

/// <summary>
/// NAPAD #8: GraphQL Injection / Information Disclosure.
///
/// GraphQL pušta klijenta da traži tačno koja polja hoće, pa se prave dve česte greške.
/// Prva je introspekcija ostavljena uključena u produkciji (__schema), čime napadač
/// pročita celu šemu, uključujući "skrivena" osetljiva polja. Druga je odsustvo
/// autorizacije po polju, pa napadač jednostavno zatraži passwordHash ili role i server
/// ih lepo vrati.
///
/// Ranjiva grana dozvoljava introspekciju i vraća bilo koje traženo polje, i osetljiva.
/// Bezbedna grana gasi introspekciju, blokira osetljiva polja i ograničava dužinu upita.
///
/// (Ovo je mini, namerno pojednostavljen GraphQL, taman da se vide oba propusta.)
/// </summary>
public sealed class GraphQLModule : IAttackModule
{
    private static readonly object[] Users =
    {
        new { id = 1, name = "Alice", email = "alice@corp.rs", passwordHash = "$2a$10$Q9...aLiCe", role = "admin" },
        new { id = 2, name = "Bob",   email = "bob@corp.rs",   passwordHash = "$2a$10$Z1...bOb",   role = "user" },
    };

    private static readonly string[] PublicFields = { "id", "name" };
    private static readonly string[] SensitiveFields = { "passwordhash", "email", "role" };

    public AttackMeta Meta => new(
        Id: "graphql",
        Number: 8,
        Title: "GraphQL Injection",
        Category: "API",
        Summary: "Introspekcija šeme + izvlačenje osetljivih polja (passwordHash). Bezbedna grana ih blokira.");

    public void Map(RouteGroupBuilder group)
    {
        group.MapPost("/vulnerable", (GqlRequest body) => Execute(body?.Query ?? "", secure: false));
        group.MapPost("/secure", (GqlRequest body) => Execute(body?.Query ?? "", secure: true));
    }

    private static IResult Execute(string query, bool secure)
    {
        var q = query.ToLowerInvariant();
        var isIntrospection = q.Contains("__schema") || q.Contains("__type");
        var requestedSensitive = SensitiveFields.Where(f => q.Contains(f)).ToArray();

        if (secure)
        {
            if (query.Length > 2000)
                return Block("Upit je predugačak (moguć DoS / duboko ugnežđenje).");
            if (isIntrospection)
                return Block("Introspekcija je isključena u produkciji.");
            if (requestedSensitive.Length > 0)
                return Block($"Pristup osetljivim poljima nije dozvoljen: {string.Join(", ", requestedSensitive)}.");

            var safe = Users.Select(u => Project(u, PublicFields)).ToArray();
            return Results.Json(new { mode = "secure", blocked = false, data = new { users = safe },
                message = "Vraćena su samo javna polja." });
        }

        // VULNERABLE
        if (isIntrospection)
        {
            return Results.Json(new
            {
                mode = "vulnerable",
                blocked = false,
                data = new
                {
                    __schema = new
                    {
                        type = "User",
                        fields = new[] { "id", "name", "email", "passwordHash", "role" }
                    }
                },
                message = "USPELA INTROSPEKCIJA: cela šema (uklj. skrivena polja) je procurela."
            });
        }

        var requested = new[] { "id", "name", "email", "passwordhash", "role" }.Where(f => q.Contains(f)).ToArray();
        if (requested.Length == 0) requested = PublicFields;
        var data = Users.Select(u => Project(u, requested)).ToArray();
        var leaked = requested.Intersect(SensitiveFields).ToArray();

        return Results.Json(new
        {
            mode = "vulnerable",
            blocked = false,
            data = new { users = data },
            message = leaked.Length > 0
                ? $"USPEO NAPAD: procurela osetljiva polja: {string.Join(", ", leaked)}."
                : "Vraćena tražena polja."
        });
    }

    private static Dictionary<string, object?> Project(object user, string[] fields)
    {
        var json = JsonSerializer.SerializeToElement(user);
        var dict = new Dictionary<string, object?>();
        foreach (var p in json.EnumerateObject())
        {
            if (fields.Contains(p.Name.ToLowerInvariant()))
                dict[p.Name] = p.Value.ToString();
        }
        return dict;
    }

    private static IResult Block(string reason) =>
        Results.Json(new { mode = "secure", blocked = true, message = "Blokirano: " + reason }, statusCode: 403);

    public sealed class GqlRequest { public string? Query { get; set; } }
}
