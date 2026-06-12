using SecurityLab.Api.Attacks.CommandInjection;
using SecurityLab.Api.Attacks.FileUpload;
using SecurityLab.Api.Attacks.GraphQL;
using SecurityLab.Api.Attacks.Heartbleed;
using SecurityLab.Api.Attacks.HostHeader;
using SecurityLab.Api.Attacks.Jwt;
using SecurityLab.Api.Attacks.OAuth;
using SecurityLab.Api.Attacks.PathTraversal;
using SecurityLab.Api.Attacks.PrototypePollution;
using SecurityLab.Api.Attacks.SupplyChain;
using SecurityLab.Api.Attacks.Toctou;
using SecurityLab.Api.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin()));

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();   // index.html
app.UseStaticFiles();

// Registar napada. Novi napad = samo jedan red ovde.
var modules = new List<IAttackModule>
{
    new PathTraversalModule(),
    new CommandInjectionModule(),
    new FileUploadModule(),
    new JwtModule(),
    new ToctouModule(),
    new HostHeaderModule(),
    new PrototypePollutionModule(),
    new GraphQLModule(),
    new OAuthModule(),
    new SupplyChainModule(),
    new HeartbleedModule(),
};

// Select lista u UI-ju čita ovaj endpoint.
app.MapGet("/api/attacks", () => modules
    .OrderBy(m => m.Meta.Number)
    .Select(m => m.Meta))
    .WithName("ListAttacks");

// Svaki modul dobija svoj prefiks /api/{id} i mapira svoje rute.
foreach (var module in modules)
{
    var group = app.MapGroup($"/api/{module.Meta.Id}");
    module.Map(group);
}

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

app.Run();
