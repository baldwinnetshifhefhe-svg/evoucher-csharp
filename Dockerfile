# ---- build stage: compile the C#/.NET app ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY eVoucherApi.csproj ./
RUN dotnet restore eVoucherApi.csproj
COPY . ./
RUN dotnet publish eVoucherApi.csproj -c Release -o /app

# ---- run stage: small runtime image ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./
# The host (Render) sets PORT; the app reads it. EXPOSE is informational.
EXPOSE 8080
ENTRYPOINT ["dotnet", "eVoucherApi.dll"]
