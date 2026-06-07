# e-PSS — C# / .NET version (production-stack build)

This is the start of the **real** system on the technology the tender requires:
**C# language + .NET (ASP.NET Core) + Entity Framework Core**. Local development uses
SQLite; production switches one line to **SQL Server**.

## How to run it
- Double-click **run.bat**, or in a terminal here run: `dotnet run`
- Then open **http://localhost:5005** in your browser — that is the **full system**
  (same look and feel as the demo), now served by C#/.NET.
- The raw data is still visible at `http://localhost:5005/api/producers`,
  `/api/vouchers`, `/api/payments`, etc.
- Stop it with Ctrl+C.

## Log in with
- National admin: **admin / admin123**
- You: **baldwinnetshifhefhe@gmail.com / 2026**
- Provincial (KZN): **kzn / kzn123**  · District (uMzinyathi): **umzinyathi / dist123**
- Dealer: **dealer / dealer123**

## What each file is
- **Program.cs** — the whole backend: 13 data models (Producer, Package, Voucher, Dealer,
  User, Grievance, Catalogue, Audit, Message, Application, Payment, Feedback,
  FarmerRegister), the database context (`AppDb`), the seed data, and **all** the API
  endpoints — login, beneficiaries, packages, vouchers (issue + OTP redeem + immediate
  payment + financial-year expiry + anti double-dipping), dealers, applications
  (recommend/approve with **separation of duties**), payments, audit trail, feedback,
  and the simulated integrations (Farmer Register sync, RICA, DSS, BAS, SMS, gateway).
- **wwwroot/index.html** — the web interface, served by C#.
- **eVoucherApi.csproj** — the project file (lists the .NET version and packages, like
  EF Core).
- **evoucher.db** — the SQLite database file, created automatically on first run.
  Delete it to reset to fresh seed data.
- **bin/ , obj/** — build output (auto-generated; ignore).

## SQLite now -> SQL Server for production
In `Program.cs`, the line:
```
builder.Services.AddDbContext<AppDb>(o => o.UseSqlite("Data Source=evoucher.db"));
```
becomes, for production:
```
builder.Services.AddDbContext<AppDb>(o => o.UseSqlServer("<SQL Server connection string>"));
```
Everything else stays the same — that is the whole point of using Entity Framework Core.

## What's done vs next
- [x] Project scaffolded, builds, runs
- [x] Database (EF Core) + **all 13 entities** + full API (list / add / delete + actions)
- [x] Vouchers: issue, OTP redeem, immediate payment, financial-year expiry, anti double-dip
- [x] Applications: recommend + approve with separation of duties
- [x] Simulated integrations: Farmer Register sync, RICA, DSS, BAS, SMS, payment gateway
- [x] Login + roles/scope returned to the front-end
- [x] Port the web interface (served from `wwwroot`)
- [ ] Switch SQLite -> SQL Server (one line) and deploy to a Windows/.NET host
- [ ] Move passwords to hashing + real auth tokens (currently demo-grade, like the Node demo)

*The whole design is already proven in the Node demo, so this is "re-implement a known
design on the required engine", not "start from scratch".*
