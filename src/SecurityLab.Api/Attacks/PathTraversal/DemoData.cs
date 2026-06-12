namespace SecurityLab.Api.Attacks.PathTraversal;

/// <summary>Pravi demo fajlove pri prvom pozivu: dozvoljene fakture i jedan "tajni" fajl IZVAN foldera.</summary>
internal static class DemoData
{
    public static string EnsureSalesDocs(string contentRoot)
    {
        var salesDocs = Path.Combine(contentRoot, "App_Data", "sales-docs");
        var secret = Path.Combine(contentRoot, "App_Data", "secret");
        Directory.CreateDirectory(salesDocs);
        Directory.CreateDirectory(secret);

        Write(Path.Combine(salesDocs, "invoice-1001.txt"),
            "FAKTURA #1001\nKupac: Petar Petrović\nIznos: 12.500,00 RSD\nStatus: Plaćeno");
        Write(Path.Combine(salesDocs, "invoice-1002.txt"),
            "FAKTURA #1002\nKupac: Marko Marković\nIznos: 7.300,00 RSD\nStatus: Otvoreno");
        Write(Path.Combine(salesDocs, "readme.txt"),
            "Ovaj folder sadrži dozvoljene fakture za preuzimanje.");

        // Ovaj fajl NIKADA ne sme da bude dostupan preko endpointa za fakture.
        Write(Path.Combine(secret, "credentials.txt"),
            "DB_USER=sale_admin\nDB_PASSWORD=Sup3rT@jna!2026\nJWT_SIGNING_KEY=do-not-leak-this");

        return salesDocs;
    }

    private static void Write(string path, string content)
    {
        if (!File.Exists(path)) File.WriteAllText(path, content);
    }
}
