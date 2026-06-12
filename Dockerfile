# build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/SecurityLab.Api/SecurityLab.Api.csproj src/SecurityLab.Api/
RUN dotnet restore src/SecurityLab.Api/SecurityLab.Api.csproj
COPY . .
RUN dotnet publish src/SecurityLab.Api/SecurityLab.Api.csproj -c Release -o /app

# runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
# Free hostovi (Render/Railway) ubace svoj PORT; ako ga nema, slušaj na 8080.
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "-c", "ASPNETCORE_URLS=http://+:${PORT:-8080} exec dotnet SecurityLab.Api.dll"]
