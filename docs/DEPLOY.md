# Deploy na besplatan hosting

Projekat je **jedan Docker kontejner** (.NET 10 + statički front), pa staje na free tier
nekoliko provajdera. Aplikacija sluša na portu iz env varijable `ASPNETCORE_URLS`
(default `8080`); većina hostova ubaci svoj `PORT` automatski.

## Opcija A - Render.com (najlakše, ima free web service)

1. Push projekat na GitHub.
2. Render > **New > Web Service** > poveži repo.
3. Environment: **Docker** (Render sam nađe `Dockerfile`).
4. Klikni **Create**. Render builduje i da ti javni `https://...onrender.com` URL.

> Render free instanca "zaspi" posle neaktivnosti; prvi zahtev posle pauze je sporiji.

## Opcija B - Railway.app

1. Push na GitHub.
2. Railway > **New Project > Deploy from GitHub repo**.
3. Railway detektuje `Dockerfile` i builduje. Generiše javni domen pod **Settings > Networking**.

## Opcija C - Fly.io


fly launch        # detektuje Dockerfile, napravi fly.toml
fly deploy
```

## Lokalno preko Dockera (provera pre deploy-a)


docker compose up --build
# http://localhost:8080
```

## Napomena o bezbednosti

Ovo je **namerno ranjiva** aplikacija. Kad je okačiš na javni internet:
- drži je iza nasumičnog/teško-pogodljivog URL-a ili Basic Auth-a ako ne želiš da je svako dira,
- ne stavljaj nikakve prave tajne u nju,
- kontejner je izolovan, ali `command-injection` izvršava komande **unutar kontejnera**,
  zato ga drži kao jednokratni/efemerni servis bez pristupa drugim resursima.
