namespace SecurityLab.Api.Infrastructure;

/// <summary>
/// Jedan napad = jedan modul. Svaki modul ima dve grane (mode): /vulnerable je
/// ranjiva implementacija, a /secure ista funkcionalnost samo zaštićena (WAF, validacija...).
/// Modul se sam mapira pod /api/{Meta.Id}/... i pojavi se u select listi na UI-ju.
/// </summary>
public interface IAttackModule
{
    AttackMeta Meta { get; }

    /// <summary>Mapira HTTP rute modula. <paramref name="group"/> je već prefiksiran sa /api/{Id}.</summary>
    void Map(RouteGroupBuilder group);
}

/// <summary>Metapodaci koji se prikazuju u select listi i na stranici napada.</summary>
public record AttackMeta(
    string Id,
    int Number,
    string Title,
    string Category,
    string Summary);
