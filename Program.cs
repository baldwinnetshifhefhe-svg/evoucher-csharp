// ============================================================================
//  e-PSS — C# / .NET version  (ASP.NET Core Minimal API + EF Core)
//  Local: SQLite.  Production: change UseSqlite -> UseSqlServer (one line).
//  Mirrors the proven Node design. Serves the web UI from wwwroot/.
// ============================================================================
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AppDb>(o => o.UseSqlite("Data Source=evoucher.db"));
var app = builder.Build();
var sessions = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();  // token -> issued epoch ms

// security headers (production hardening)
app.Use(async (ctx, next) => {
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "strict-origin-when-cross-origin";
    h["Content-Security-Policy"] = "frame-ancestors 'none'";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    await next();
});

// API authentication gate: every /api endpoint except /api/login needs a valid session token
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    if (path.StartsWith("/api/") && path != "/api/login")
    {
        var tok = ctx.Request.Headers["x-auth-token"].ToString();
        if (string.IsNullOrEmpty(tok)) { var a = ctx.Request.Headers["Authorization"].ToString(); if (a.StartsWith("Bearer ")) tok = a.Substring(7); }
        if (!sessions.TryGetValue(tok, out var ts) || (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - ts) > 12L * 3600 * 1000)
        { sessions.TryRemove(tok, out _); ctx.Response.StatusCode = 401; await ctx.Response.WriteAsJsonAsync(new { error = "Not signed in" }); return; }
    }
    await next();
});

app.UseDefaultFiles();   // serve wwwroot/index.html at "/"
app.UseStaticFiles();

// ---- helpers ----------------------------------------------------------------
static string FyEnd() { var d = DateTime.Now; int y = d.Month >= 4 ? d.Year + 1 : d.Year; return $"{y}-03-31"; }
static string Otp() => Random.Shared.Next(1000, 9999).ToString();
static string Today() => DateTime.Now.ToString("dd MMM yyyy");
static string Now() => DateTime.Now.ToString("yyyy/MM/dd HH:mm");
static string MakeEmail(string name) => new string(name.ToLower().Where(c => char.IsLetter(c) || c == ' ').ToArray()).Trim().Replace(" ", ".") + "@example.co.za";
static int Age(string demo) { var p = demo.Split('·'); return p.Length > 1 && int.TryParse(p[1].Trim(), out var a) ? a : 99; }
static string Sha256(string s) { using var sha = SHA256.Create(); return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant(); }
static void Log(AppDb db, string actor, string evt, string kind)   // tamper-evident hash chain
{
    var prev = db.Audit.OrderByDescending(a => a.Id).FirstOrDefault()?.Hash ?? "GENESIS";
    var ts = Now();
    var hash = Sha256($"{prev}|{ts}|{actor}|{evt}|{kind}");
    db.Audit.Add(new Audit { Ts = ts, Actor = actor, Event = evt, Kind = kind, PrevHash = prev, Hash = hash });
}
static string HashPw(string pw) { var salt = RandomNumberGenerator.GetBytes(16); var h = Rfc2898DeriveBytes.Pbkdf2(pw ?? "", salt, 100000, HashAlgorithmName.SHA256, 32); return Convert.ToHexString(salt) + ":" + Convert.ToHexString(h); }
static bool CheckPw(string pw, string stored) { if (string.IsNullOrEmpty(stored)) return false; if (!stored.Contains(':')) return pw == stored; var parts = stored.Split(':'); try { var salt = Convert.FromHexString(parts[0]); var h = Rfc2898DeriveBytes.Pbkdf2(pw ?? "", salt, 100000, HashAlgorithmName.SHA256, 32); return Convert.ToHexString(h) == parts[1]; } catch { return false; } }
// Real SMS: prefers BulkSMS (SA-local), then Twilio; otherwise safely simulated.
static async Task<object> SendSms(string to, string text)
{
    using var http = new HttpClient();
    // 1) BulkSMS — best for South African delivery
    var bUser = Environment.GetEnvironmentVariable("BULKSMS_USERNAME");
    var bPass = Environment.GetEnvironmentVariable("BULKSMS_PASSWORD");
    if (!string.IsNullOrEmpty(bUser) && !string.IsNullOrEmpty(bPass))
    {
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "https://api.bulksms.com/v1/messages");
            req.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(bUser + ":" + bPass)));
            req.Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new { to, body = text }), Encoding.UTF8, "application/json");
            var resp = await http.SendAsync(req);
            var txt = await resp.Content.ReadAsStringAsync();
            string? id = null;
            try { using var d = System.Text.Json.JsonDocument.Parse(txt); if (d.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array && d.RootElement.GetArrayLength() > 0 && d.RootElement[0].TryGetProperty("id", out var idEl)) id = idEl.GetString(); } catch { }
            return new { sent = resp.IsSuccessStatusCode, to, status = (int)resp.StatusCode, source = "BulkSMS", reff = id };
        }
        catch (Exception e) { return new { sent = false, error = e.Message, to, source = "BulkSMS" }; }
    }
    // 2) Twilio
    var sid = Environment.GetEnvironmentVariable("TWILIO_ACCOUNT_SID");
    var tok = Environment.GetEnvironmentVariable("TWILIO_AUTH_TOKEN");
    var from = Environment.GetEnvironmentVariable("TWILIO_FROM");
    if (!string.IsNullOrEmpty(sid) && !string.IsNullOrEmpty(tok) && !string.IsNullOrEmpty(from))
    {
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Post, $"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json");
            req.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(sid + ":" + tok)));
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string> { { "To", to }, { "From", from }, { "Body", text } });
            var resp = await http.SendAsync(req);
            return new { sent = resp.IsSuccessStatusCode, to, status = (int)resp.StatusCode, source = "Twilio" };
        }
        catch (Exception e) { return new { sent = false, error = e.Message, to, source = "Twilio" }; }
    }
    // 3) simulated
    return new { sent = false, simulated = true, to = string.IsNullOrEmpty(to) ? "•••• ••••" : to, source = "SMS gateway (simulated — add BULKSMS_* or TWILIO_* to send for real)" };
}
// Ask BulkSMS the real delivery status of a message id (ACCEPTED / SENT / DELIVERED / FAILED).
static async Task<object> SmsStatus(string id)
{
    var bUser = Environment.GetEnvironmentVariable("BULKSMS_USERNAME");
    var bPass = Environment.GetEnvironmentVariable("BULKSMS_PASSWORD");
    if (string.IsNullOrEmpty(bUser) || string.IsNullOrEmpty(bPass)) return new { id, status = "no-provider" };
    if (string.IsNullOrEmpty(id)) return new { id, status = "no-id" };
    try
    {
        using var http = new HttpClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "https://api.bulksms.com/v1/messages/" + Uri.EscapeDataString(id));
        req.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(bUser + ":" + bPass)));
        var resp = await http.SendAsync(req);
        var txt = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) return new { id, status = "error", detail = "HTTP " + (int)resp.StatusCode };
        using var doc = System.Text.Json.JsonDocument.Parse(txt);
        var root = doc.RootElement; string st = "unknown", sub = "";
        if (root.TryGetProperty("status", out var s)) { if (s.TryGetProperty("type", out var t)) st = t.GetString() ?? "unknown"; if (s.TryGetProperty("subtype", out var su)) sub = su.GetString() ?? ""; }
        return new { id, status = st, detail = sub };
    }
    catch (Exception e) { return new { id, status = "error", detail = e.Message }; }
}
// Read a property off an anonymous SMS-result object by name (null if absent).
static object? Prop(object o, string name) => o?.GetType().GetProperty(name)?.GetValue(o);
static List<Producer> Match(AppDb db, Criteria c)
{
    var list = db.Producers.Where(p => p.Status == "Active").ToList();
    if (c.gender == "F") list = list.Where(p => p.Demo.StartsWith("F")).ToList();
    else if (c.gender == "M") list = list.Where(p => p.Demo.StartsWith("M")).ToList();
    if (!string.IsNullOrEmpty(c.prov)) list = list.Where(p => p.Prov == c.prov).ToList();
    if (!string.IsNullOrEmpty(c.dist)) list = list.Where(p => p.Dist == c.dist).ToList();
    if (c.youth == true) list = list.Where(p => Age(p.Demo) <= 35).ToList();
    return list;
}

// ---- create + seed the database on first run -------------------------------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();
    if (!db.Producers.Any()) Seed.Run(db);
    // hash any plain-text passwords (one-time migration; safe to run every start)
    foreach (var usr in db.Users.ToList().Where(x => x.Password != null && !x.Password.Contains(':'))) usr.Password = HashPw(usr.Password);
    // seed two test farmers' cellphones (and name the second Mr Oscar Ndou) so issuing a voucher sends a REAL SMS
    var pTha = db.Producers.FirstOrDefault(x => x.Name == "Thabo Mokoena");
    if (pTha != null && string.IsNullOrEmpty(pTha.Phone)) pTha.Phone = "+27718724388";
    var pNom = db.Producers.FirstOrDefault(x => x.Name == "Nomsa Dlamini");
    if (pNom != null) { pNom.Phone = "+27716084771"; pNom.Name = "Mr Oscar Ndou"; }
    foreach (var vv in db.Vouchers.Where(v => v.Who == "Nomsa Dlamini").ToList()) vv.Who = "Mr Oscar Ndou";
    foreach (var fr in db.FarmerRegister.Where(f => f.Name == "Nomsa Dlamini").ToList()) fr.Name = "Mr Oscar Ndou";
    if (!db.Producers.Any(p => p.Phone == "+27785462294"))
        db.Producers.Add(new Producer { Name = "Mrs Bongane Netshifhefhe", Prov = "LP", Dist = "Vhembe", Ent = "Vegetables 2ha", Status = "Active", Rica = "Verified", Demo = "F·38", Email = "bongane.netshifhefhe@example.co.za", Phone = "+27785462294" });
    if (!db.Producers.Any(p => p.Phone == "+27722859144"))
        db.Producers.Add(new Producer { Name = "Miss Mukundi Luvhengo", Prov = "LP", Dist = "Vhembe", Ent = "Maize 3ha", Status = "Active", Rica = "Verified", Demo = "F·29", Email = "mukundi.luvhengo@example.co.za", Phone = "+27722859144" });
    db.SaveChanges();
}

// ============================ API ENDPOINTS ==================================

// ---- auth ----
app.MapPost("/api/login", (AppDb db, LoginReq r) =>
{
    var un = (r.username ?? "").Trim(); var pw = (r.password ?? "").Trim();
    var u = db.Users.FirstOrDefault(x => x.Username == un);
    var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    if (u != null && u.LockedUntil > nowMs)
        return Results.Json(new { error = "Account locked after too many attempts. Try again later." }, statusCode: 423);
    if (u is null || !CheckPw(pw, u.Password))
    {
        if (u != null) { u.FailedAttempts++; if (u.FailedAttempts >= 5) u.LockedUntil = nowMs + 15 * 60000; db.SaveChanges(); }
        return Results.Json(new { error = "Invalid username or password" }, statusCode: 401);
    }
    u.FailedAttempts = 0; u.LockedUntil = 0; db.SaveChanges();
    Log(db, u.Name, "Signed in", "info"); db.SaveChanges();
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    sessions[token] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    return Results.Ok(new { username = u.Username, name = u.Name, role = u.Role, scope = u.Scope, token });
});

// ---- producers ----
app.MapGet("/api/producers", (AppDb db) => db.Producers.OrderByDescending(p => p.Id).ToList());
app.MapPost("/api/producers", (AppDb db, Producer p) =>
{
    if (string.IsNullOrWhiteSpace(p.Name)) return Results.BadRequest(new { error = "name required" });
    p.Id = 0; if (string.IsNullOrEmpty(p.Status)) p.Status = "Active"; p.Email = MakeEmail(p.Name);
    db.Producers.Add(p); Log(db, "Admin", $"Beneficiary added: {p.Name}", "info"); db.SaveChanges();
    return Results.Ok(p);
});
app.MapDelete("/api/producers/{id}", (AppDb db, int id) =>
{
    var p = db.Producers.Find(id); if (p is null) return Results.NotFound();
    db.Producers.Remove(p); Log(db, "Admin", $"Beneficiary removed: {p.Name}", "no"); db.SaveChanges();
    return Results.Ok(new { ok = true });
});
app.MapPost("/api/producers/{id}/suspend", (AppDb db, int id) =>
{
    var p = db.Producers.Find(id); if (p is null) return Results.NotFound();
    p.Status = p.Status == "Suspended" ? "Active" : "Suspended";
    Log(db, "Admin", $"{p.Name} {(p.Status == "Suspended" ? "suspended" : "reactivated")}", p.Status == "Suspended" ? "no" : "ok");
    db.SaveChanges(); return Results.Ok(new { status = p.Status });
});

// ---- packages ----
app.MapGet("/api/packages", (AppDb db) => db.Packages.OrderBy(p => p.Id).ToList());
app.MapPost("/api/packages", (AppDb db, Package p) => { p.Id = 0; p.Status = "Active"; db.Packages.Add(p); Log(db, "Admin", $"Package created: {p.Name}", "info"); db.SaveChanges(); return Results.Ok(p); });
app.MapDelete("/api/packages/{id}", (AppDb db, int id) => { var p = db.Packages.Find(id); if (p != null) { db.Packages.Remove(p); db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- catalogue ----
app.MapGet("/api/catalogue", (AppDb db) => db.Catalogue.OrderBy(c => c.Id).ToList());
app.MapPost("/api/catalogue", (AppDb db, Catalogue c) => { c.Id = 0; c.S = "Under review"; db.Catalogue.Add(c); Log(db, "Admin", $"Input added: {c.N}", "info"); db.SaveChanges(); return Results.Ok(new { ok = true }); });
app.MapDelete("/api/catalogue/{id}", (AppDb db, int id) => { var c = db.Catalogue.Find(id); if (c != null) { db.Catalogue.Remove(c); db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- dealers ----
app.MapGet("/api/dealers", (AppDb db) => db.Dealers.OrderBy(d => d.Id).ToList());
app.MapPost("/api/dealers", (AppDb db, Dealer d) => { d.Id = 0; d.Status = "Pending"; db.Dealers.Add(d); Log(db, "Admin", $"Dealer registered (pending): {d.Name}", "wait"); db.SaveChanges(); return Results.Ok(new { ok = true }); });
app.MapPost("/api/dealers/{id}/approve", (AppDb db, int id) => { var d = db.Dealers.Find(id); if (d != null) { d.Status = "Active"; Log(db, "Admin", $"Dealer accredited: {d.Name}", "ok"); db.SaveChanges(); } return Results.Ok(new { ok = true }); });
app.MapDelete("/api/dealers/{id}", (AppDb db, int id) => { var d = db.Dealers.Find(id); if (d != null) { db.Dealers.Remove(d); db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- users ----
app.MapGet("/api/users", (AppDb db) => db.Users.Select(u => new { id = u.Id, username = u.Username, name = u.Name, role = u.Role, scope = u.Scope }).ToList());
app.MapPost("/api/users", (AppDb db, User u) => { u.Id = 0; u.Username = (new string(u.Name.ToLower().Where(char.IsLetter).ToArray())) + Random.Shared.Next(100, 999); u.Password = "demo123"; db.Users.Add(u); Log(db, "Admin", $"User added: {u.Name}", "info"); db.SaveChanges(); return Results.Ok(new { ok = true }); });
app.MapDelete("/api/users/{id}", (AppDb db, int id) => { var u = db.Users.Find(id); if (u != null) { db.Users.Remove(u); db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- grievances ----
app.MapGet("/api/grievances", (AppDb db) => db.Grievances.OrderByDescending(g => g.Id).ToList());
app.MapPost("/api/grievances", (AppDb db, GrievanceReq r) => { var refn = "GR-" + (40 + db.Grievances.Count() + 3).ToString("D4"); db.Grievances.Add(new Grievance { Ref = refn, Who = r.who ?? "-", Issue = r.issue ?? "-", Status = "Open", Created = Today() }); Log(db, "Admin", $"Grievance logged: {refn}", "wait"); db.SaveChanges(); return Results.Ok(new { @ref = refn }); });
app.MapPost("/api/grievances/{id}/resolve", (AppDb db, int id) => { var g = db.Grievances.Find(id); if (g != null) { g.Status = "Resolved"; db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- vouchers ----
app.MapGet("/api/vouchers", (AppDb db) => db.Vouchers.OrderByDescending(v => v.Id).ToList());
app.MapPost("/api/vouchers", async (AppDb db, IssueReq r) =>
{
    var pk = db.Packages.FirstOrDefault(p => p.Name == r.pkg);
    if (string.IsNullOrEmpty(r.who) || pk is null) return Results.BadRequest(new { error = "producer and package required" });
    if (db.Vouchers.Any(v => v.Who == r.who && v.Pkg == pk.Name && v.Status == "Issued"))
        return Results.BadRequest(new { error = "Beneficiary already has an active voucher for this package (anti double-dipping)" });
    var prod = db.Producers.FirstOrDefault(p => p.Name == r.who);
    // RULE: no SMS = no voucher. The farmer can only redeem with the OTP we SMS them,
    // so a voucher that can't be delivered must not be issued. Check phone + send + confirm BEFORE committing.
    if (prod is null || string.IsNullOrEmpty(prod.Phone))
        return Results.BadRequest(new { error = "Voucher NOT issued — " + r.who + " has no mobile number on file, so the voucher SMS (with the OTP) cannot be delivered. Add a phone number on the Beneficiaries register first." });
    var no = "EV-2026-00" + (480 + db.Vouchers.Count() + 1);
    var otp = Otp(); var prov = prod.Prov ?? "";
    var sms = await SendSms(prod.Phone, $"DoA e-Voucher: You have received {pk.Name} (R{pk.Val}). Redeem at an accredited agro-dealer with OTP {otp}. Valid until {FyEnd()}. Ref {no}.");
    bool simulated = Prop(sms, "simulated") is bool sb && sb;
    if (simulated)
    {
        // On a live server, "simulated" means NO gateway is configured -> nothing was really sent -> refuse (Baldwin's rule). Local dev still allowed.
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("RENDER")))
            return Results.BadRequest(new { error = "Voucher NOT issued — no SMS gateway is configured on this server, so the voucher OTP cannot be delivered to " + prod.Phone + ". Add BULKSMS_USERNAME and BULKSMS_PASSWORD to this service, then retry.", sms });
    }
    else
    {
        bool sent = Prop(sms, "sent") is bool s2 && s2;
        if (!sent) return Results.BadRequest(new { error = "Voucher NOT issued — SMS could not be sent to " + prod.Phone + ": " + (Prop(sms, "error") as string ?? "unknown") + ". Fix the number, then retry.", sms });
        var reff = Prop(sms, "reff") as string;
        if (!string.IsNullOrEmpty(reff))
        {
            foreach (var dly in new[] { 1500, 2000, 2500, 3000 })
            {
                await Task.Delay(dly);
                var stt = await SmsStatus(reff);
                var t = (Prop(stt, "status") as string ?? "").ToUpper();
                var det = (Prop(stt, "detail") as string ?? "").ToUpper();
                if (t == "DELIVERED" || t == "SENT") break;
                if (t == "FAILED" || t == "REJECTED" || t == "UNDELIVERED" || det == "NOT_SENT")
                    return Results.BadRequest(new { error = "Voucher NOT issued — the network rejected the SMS to " + prod.Phone + " (" + (det.Length > 0 ? det : t) + "). This number is likely on the WASPA Do-Not-Contact list or is not SMS-active. Enable WASPA transactional consent in BulkSMS, or use a different number, then retry.", sms, delivery = stt });
            }
        }
    }
    db.Vouchers.Add(new Voucher { No = no, Who = r.who, Prov = prov, Pkg = pk.Name, Val = pk.Val, Status = "Issued", Otp = otp, Created = Today(), Expiry = FyEnd() });
    Log(db, r.who, $"Voucher {no} issued ({pk.Name}) — SMS sent to {prod.Phone}; valid until {FyEnd()}", "info"); db.SaveChanges();
    return Results.Ok(new { no, val = pk.Val, otp, expiry = FyEnd(), sms });
});
app.MapPost("/api/vouchers/{id}/redeem", async (AppDb db, int id, RedeemReq r) =>
{
    var v = db.Vouchers.Find(id); if (v is null) return Results.NotFound();
    if (v.Status == "Redeemed") return Results.BadRequest(new { error = "already redeemed" });
    if (!string.IsNullOrEmpty(v.Expiry) && DateTime.Now > DateTime.Parse(v.Expiry + "T23:59:59")) return Results.BadRequest(new { error = "Voucher expired (financial year ended) — cannot redeem" });
    if ((r.otp ?? "").Trim() != v.Otp) return Results.BadRequest(new { error = "Wrong OTP — redemption refused" });
    var dealer = r.dealer ?? "(dealer)"; v.Status = "Redeemed"; v.Dealer = dealer; v.RedeemedAt = Today();
    var cc = Otp(); v.ConfirmCode = cc; v.ConfirmStatus = "";   // farmer confirmation code SMS-sent (added layer)
    var pref = "PG-" + DateTime.Now.Ticks.ToString()[^8..];
    // dealer OTP method retained: supplier paid immediately on redemption (unchanged)
    db.Payments.Add(new Payment { Ts = Now(), Supplier = dealer, VoucherNo = v.No, Who = v.Who, Amount = v.Val, Gateway = "PayGate (gateway)", Ref = pref, Status = "Paid" });
    Log(db, v.Who, $"Voucher {v.No} redeemed at {dealer} — OTP verified; payment R{v.Val} via gateway ({pref}). Farmer confirmation code SMS-sent to verify receipt.", "ok"); db.SaveChanges();
    var rprod = db.Producers.FirstOrDefault(p => p.Name == v.Who);
    if (rprod != null && !string.IsNullOrEmpty(rprod.Phone))
        await SendSms(rprod.Phone, $"DoA e-Voucher: Please confirm you received your inputs for voucher {v.No}. Confirmation code: {cc}.");
    return Results.Ok(new { ok = true, paid = v.Val, @ref = pref, confirm_code = cc });
});
// FARMER confirms they actually received the goods (added assurance, after redemption)
app.MapPost("/api/vouchers/{id}/confirm", (AppDb db, int id, ConfirmReq r) =>
{
    var v = db.Vouchers.Find(id); if (v is null) return Results.NotFound();
    if (v.Status != "Redeemed") return Results.BadRequest(new { error = "only a redeemed voucher can be confirmed" });
    if (v.ConfirmStatus == "Confirmed") return Results.BadRequest(new { error = "already confirmed by the farmer" });
    if ((r.code ?? "").Trim() != v.ConfirmCode) return Results.BadRequest(new { error = "Wrong confirmation code — only the farmer who received the goods can confirm" });
    v.ConfirmStatus = "Confirmed"; v.ConfirmedAt = Now();
    Log(db, v.Who, $"Voucher {v.No} — FARMER CONFIRMED receipt of goods from {v.Dealer}.", "ok"); db.SaveChanges();
    return Results.Ok(new { ok = true });
});
// FARMER disputes (did not receive / short) — opens a grievance for investigation/recovery
app.MapPost("/api/vouchers/{id}/dispute", (AppDb db, int id, ConfirmReq r) =>
{
    var v = db.Vouchers.Find(id); if (v is null) return Results.NotFound();
    if (v.Status != "Redeemed") return Results.BadRequest(new { error = "only a redeemed voucher can be disputed" });
    v.ConfirmStatus = "Disputed";
    var refn = "GR-" + (40 + db.Grievances.Count() + 3).ToString("D4");
    db.Grievances.Add(new Grievance { Ref = refn, Who = v.Who, Issue = $"Did not receive / short delivery — voucher {v.No} at {v.Dealer}. {r.reason ?? "Reported by farmer."} (Payment already made — investigate / recover.)", Status = "Open", Created = Today() });
    Log(db, v.Who, $"Voucher {v.No} DISPUTED by farmer — grievance {refn} opened to investigate {v.Dealer} (payment already released; recovery may be needed).", "no"); db.SaveChanges();
    return Results.Ok(new { ok = true, grievance = refn });
});

// ---- targeted distribution ----
app.MapPost("/api/distribute", (AppDb db, Criteria c) =>
{
    var pk = db.Packages.FirstOrDefault(p => p.Name == c.pkg); if (pk is null) return Results.BadRequest(new { error = "package required" });
    int n = 0;
    foreach (var pr in Match(db, c))
    {
        if (db.Vouchers.Any(v => v.Who == pr.Name && v.Pkg == pk.Name && v.Status == "Issued")) continue;
        db.Vouchers.Add(new Voucher { No = "EV-2026-00" + (480 + db.Vouchers.Count() + 1 + n), Who = pr.Name, Prov = pr.Prov, Pkg = pk.Name, Val = pk.Val, Status = "Issued", Otp = Otp(), Created = Today(), Expiry = FyEnd() });
        n++;
    }
    Log(db, "Admin", $"Auto-distributed '{pk.Name}' to {n} beneficiaries by criteria", "info"); db.SaveChanges();
    return Results.Ok(new { count = n });
});

// ---- communications ----
app.MapGet("/api/messages", (AppDb db) => db.Messages.OrderByDescending(m => m.Id).ToList());
app.MapPost("/api/messages", (AppDb db, Criteria c) => { var n = Match(db, c).Count; db.Messages.Add(new Message { Ts = Now(), Audience = c.audience ?? "All", Channel = c.channel ?? "Email", Subject = c.subject ?? "", Body = c.body ?? "", Recipients = n }); Log(db, "Admin", $"{c.channel ?? "Email"} sent to {n} beneficiaries: \"{c.subject}\"", "info"); db.SaveChanges(); return Results.Ok(new { count = n }); });

// ---- applications ----
app.MapGet("/api/applications", (AppDb db) => db.Applications.OrderByDescending(a => a.Id).ToList());
app.MapPost("/api/applications", (AppDb db, Application a) => { a.Id = 0; a.Status = "Applied"; a.Created = Today(); db.Applications.Add(a); Log(db, "Farmer", $"Application received: {a.Name}", "wait"); db.SaveChanges(); return Results.Ok(new { ok = true }); });
app.MapPost("/api/applications/{id}/recommend", (AppDb db, int id, AppAction r) => { var a = db.Applications.Find(id); if (a is null) return Results.NotFound(); if (a.Status != "Applied") return Results.BadRequest(new { error = "Only new applications can be recommended" }); a.Status = "Recommended"; a.RecommendedBy = r.by ?? "District officer"; Log(db, a.RecommendedBy, $"Application recommended: {a.Name}", "info"); db.SaveChanges(); return Results.Ok(new { ok = true }); });
app.MapPost("/api/applications/{id}/approve", (AppDb db, int id, AppAction r) =>
{
    var a = db.Applications.Find(id); if (a is null) return Results.NotFound();
    if (a.Status != "Recommended") return Results.BadRequest(new { error = "Application must be RECOMMENDED by a district officer before approval (separation of duties)" });
    if (!string.IsNullOrEmpty(r.by) && r.by == a.RecommendedBy) return Results.BadRequest(new { error = "The same official cannot both recommend and approve (separation of duties)" });
    a.Status = "Approved"; a.ApprovedBy = r.by ?? "Approver";
    db.Producers.Add(new Producer { Name = a.Name, Prov = a.Prov, Dist = a.Dist, Ent = a.Ent, Status = "Active", Rica = "Verified", Demo = a.Demo, Email = MakeEmail(a.Name) });
    Log(db, a.ApprovedBy, $"Application APPROVED & added to register: {a.Name} (recommended by {a.RecommendedBy})", "ok"); db.SaveChanges();
    return Results.Ok(new { ok = true });
});
app.MapPost("/api/applications/{id}/reject", (AppDb db, int id, AppAction r) => { var a = db.Applications.Find(id); if (a != null) { a.Status = "Rejected"; a.Reason = r.reason ?? ""; Log(db, r.by ?? "Admin", $"Application rejected: {a.Name} ({r.reason})", "no"); db.SaveChanges(); } return Results.Ok(new { ok = true }); });

// ---- payments / audit / feedback ----
app.MapGet("/api/payments", (AppDb db) => db.Payments.OrderByDescending(p => p.Id).ToList());
app.MapGet("/api/audit", (AppDb db) => db.Audit.OrderByDescending(a => a.Id).Take(80).ToList());
// tamper-evident audit: recompute the hash chain and report any break
app.MapGet("/api/audit/verify", (AppDb db) =>
{
    var rows = db.Audit.OrderBy(a => a.Id).ToList();
    string prev = "GENESIS"; bool ok = true; int? broken = null; int n = 0;
    foreach (var rrec in rows)
    {
        if (string.IsNullOrEmpty(rrec.Hash)) continue;
        var expect = Sha256($"{prev}|{rrec.Ts}|{rrec.Actor}|{rrec.Event}|{rrec.Kind}");
        if (rrec.PrevHash != prev || rrec.Hash != expect) { ok = false; broken = rrec.Id; break; }
        prev = rrec.Hash; n++;
    }
    return Results.Ok(new { ok, @checked = n, broken });
});
// confirmation oversight: per-dealer confirmed/awaiting/disputed (the aggregate-silence red flag)
app.MapGet("/api/oversight/confirmation", (AppDb db) =>
{
    var rows = db.Vouchers.Where(v => v.Dealer != null && v.Dealer != "").AsEnumerable()
        .GroupBy(v => v.Dealer)
        .Select(g => new {
            dealer = g.Key,
            redeemed = g.Count(v => v.Status == "Redeemed"),
            confirmed = g.Count(v => v.ConfirmStatus == "Confirmed"),
            awaiting = g.Count(v => v.Status == "Redeemed" && string.IsNullOrEmpty(v.ConfirmStatus)),
            disputed = g.Count(v => v.ConfirmStatus == "Disputed")
        }).OrderByDescending(x => x.disputed).ThenByDescending(x => x.awaiting).ToList();
    return Results.Ok(rows);
});
app.MapGet("/api/feedback", (AppDb db) => db.Feedback.OrderByDescending(f => f.Id).ToList());
app.MapPost("/api/feedback", (AppDb db, FeedbackReq r) => { db.Feedback.Add(new Feedback { Ts = Now(), Role = r.role ?? "-", Rating = r.rating, Comment = r.comment ?? "", By = r.by ?? "" }); Log(db, r.by ?? "User", $"Feedback: {r.rating}* ({r.role})", "info"); db.SaveChanges(); return Results.Ok(new { ok = true }); });

// ---- simulated integrations ----
app.MapGet("/api/integrations/farmer-register", (AppDb db) => db.FarmerRegister.OrderBy(f => f.Enrolled).ThenBy(f => f.Name).ToList());
app.MapPost("/api/integrations/farmer-register/sync", (AppDb db) =>
{
    int n = 0;
    foreach (var f in db.FarmerRegister.Where(x => x.Enrolled == 0).ToList())
    {
        if (!db.Producers.Any(p => p.Name == f.Name)) { db.Producers.Add(new Producer { Name = f.Name, Prov = f.Prov, Dist = f.Dist, Ent = f.Ent, Status = "Active", Rica = f.Rica, Demo = f.Demo, Email = MakeEmail(f.Name) }); n++; }
        f.Enrolled = 1;
    }
    Log(db, "System", $"Synced {n} farmers from the Farmer Register into beneficiaries", "info"); db.SaveChanges();
    return Results.Ok(new { synced = n });
});
app.MapGet("/api/integrations/dss", (string? prov) => { prov ??= "national"; var lv = new[] { "Low", "Watch", "Medium", "High" }; int i = prov.Sum(ch => ch) % lv.Length; return Results.Ok(new { prov, risk = lv[i], rainfall_mm = i * 7 + 3, advisory = i >= 2 ? "Dry spell expected — advise water-wise inputs" : "Conditions favourable for planting", source = "DSS (simulated)" }); });
app.MapGet("/api/integrations/rica", (string? name) => { name ??= ""; bool ok = !name.ToLower().Contains("botha"); return Results.Ok(new { name, verified = ok, result = ok ? "Number registered in the producer's name" : "Name mismatch — manual check required", source = "RICA (simulated)" }); });
app.MapGet("/api/integrations/extension-directory", () => Results.Ok(new[] { new { name = "M. Sitali", role = "Extension Officer", prov = "KZN", cell = "082 000 0001" }, new { name = "J. Ngaka", role = "Extension Officer", prov = "LP", cell = "082 000 0002" }, new { name = "T. Mothibi", role = "Extension Officer", prov = "MP", cell = "082 000 0003" } }));
app.MapPost("/api/integrations/sms", async (SmsReq r) => Results.Ok(await SendSms(r.to ?? "", r.body ?? r.message ?? "Test message from e-PSS (e-Voucher).")));
app.MapGet("/api/integrations/sms-status", async (string? id) => Results.Ok(await SmsStatus(id ?? "")));
app.MapPost("/api/integrations/bas", () => Results.Ok(new { @ref = "BAS-" + DateTime.Now.Ticks.ToString()[^8..], status = "Disbursement raised", source = "BAS (simulated)" }));
app.MapPost("/api/integrations/gateway", () => Results.Ok(new { @ref = "PG-" + DateTime.Now.Ticks.ToString()[^8..], status = "Paid", source = "Payment gateway (simulated)" }));

// Locally this is 5005; a host (Render/Azure) supplies its own port via the PORT variable.
var port = Environment.GetEnvironmentVariable("PORT") ?? "5005";
app.Run($"http://0.0.0.0:{port}");

// ============================ DATA MODELS ===================================
public class Producer { public int Id { get; set; } public string Name { get; set; } = ""; public string Prov { get; set; } = ""; public string Dist { get; set; } = ""; public string Ent { get; set; } = ""; public string Status { get; set; } = "Active"; public string Rica { get; set; } = "Verified"; public string Demo { get; set; } = ""; public string Email { get; set; } = ""; public string Phone { get; set; } = ""; }
public class Package { public int Id { get; set; } public string Name { get; set; } = ""; public int Val { get; set; } public string Items { get; set; } = ""; public string Status { get; set; } = "Active"; }
public class Voucher { public int Id { get; set; } public string No { get; set; } = ""; public string Who { get; set; } = ""; public string Prov { get; set; } = ""; public string Pkg { get; set; } = ""; public int Val { get; set; } public string Status { get; set; } = ""; public string Otp { get; set; } = ""; public string Dealer { get; set; } = ""; public string Created { get; set; } = ""; [JsonPropertyName("redeemed_at")] public string RedeemedAt { get; set; } = ""; public string Expiry { get; set; } = ""; [JsonPropertyName("confirm_code")] public string ConfirmCode { get; set; } = ""; [JsonPropertyName("confirmed_at")] public string ConfirmedAt { get; set; } = ""; [JsonPropertyName("confirm_status")] public string ConfirmStatus { get; set; } = ""; }
public class Dealer { public int Id { get; set; } public string Name { get; set; } = ""; public string Prov { get; set; } = ""; public string Dist { get; set; } = ""; public string Contact { get; set; } = ""; public string Status { get; set; } = "Active"; [JsonPropertyName("company_reg")] public string CompanyReg { get; set; } = ""; public string Vat { get; set; } = ""; public string Csd { get; set; } = ""; public string Bank { get; set; } = ""; public string Address { get; set; } = ""; public string Email { get; set; } = ""; public string Phone { get; set; } = ""; public string Catalogue { get; set; } = ""; }
public class User { public int Id { get; set; } public string Username { get; set; } = ""; public string Password { get; set; } = ""; public string Name { get; set; } = ""; public string Role { get; set; } = ""; public string Scope { get; set; } = ""; [JsonIgnore] public int FailedAttempts { get; set; } [JsonIgnore] public long LockedUntil { get; set; } }
public class Grievance { public int Id { get; set; } public string Ref { get; set; } = ""; public string Who { get; set; } = ""; public string Issue { get; set; } = ""; public string Status { get; set; } = "Open"; public string Created { get; set; } = ""; }
public class Catalogue { public int Id { get; set; } public string N { get; set; } = ""; public string C { get; set; } = ""; public int P { get; set; } public string S { get; set; } = "Approved"; }
public class Audit { public int Id { get; set; } public string Ts { get; set; } = ""; public string Actor { get; set; } = ""; public string Event { get; set; } = ""; public string Kind { get; set; } = ""; [JsonPropertyName("prev_hash")] public string PrevHash { get; set; } = ""; public string Hash { get; set; } = ""; }
public class Message { public int Id { get; set; } public string Ts { get; set; } = ""; public string Audience { get; set; } = ""; public string Channel { get; set; } = ""; public string Subject { get; set; } = ""; public string Body { get; set; } = ""; public int Recipients { get; set; } }
public class Application { public int Id { get; set; } public string Name { get; set; } = ""; public string Prov { get; set; } = ""; public string Dist { get; set; } = ""; public string Ent { get; set; } = ""; public string Demo { get; set; } = ""; public string Status { get; set; } = "Applied"; public string Created { get; set; } = ""; [JsonPropertyName("recommended_by")] public string RecommendedBy { get; set; } = ""; [JsonPropertyName("approved_by")] public string ApprovedBy { get; set; } = ""; public string Reason { get; set; } = ""; }
public class Payment { public int Id { get; set; } public string Ts { get; set; } = ""; public string Supplier { get; set; } = ""; [JsonPropertyName("voucher_no")] public string VoucherNo { get; set; } = ""; public string Who { get; set; } = ""; public int Amount { get; set; } public string Gateway { get; set; } = ""; public string Ref { get; set; } = ""; public string Status { get; set; } = ""; }
public class Feedback { public int Id { get; set; } public string Ts { get; set; } = ""; public string Role { get; set; } = ""; public int Rating { get; set; } public string Comment { get; set; } = ""; public string By { get; set; } = ""; }
public class FarmerRegister { public int Id { get; set; } public string Name { get; set; } = ""; public string Prov { get; set; } = ""; public string Dist { get; set; } = ""; public string Ent { get; set; } = ""; public string Demo { get; set; } = ""; public string Rica { get; set; } = "Verified"; public int Enrolled { get; set; } }

// request bodies (JSON -> these)
public record LoginReq(string? username, string? password);
public record IssueReq(string? who, string? pkg);
public record RedeemReq(string? otp, string? dealer);
public record ConfirmReq(string? code, string? reason);
public record SmsReq(string? to, string? body, string? message);
public record GrievanceReq(string? who, string? issue);
public record FeedbackReq(int rating, string? role, string? comment, string? by);
public record AppAction(string? by, string? reason);
public record Criteria(string? gender, bool? youth, string? prov, string? dist, string? pkg, string? channel, string? subject, string? body, string? audience);

public class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> o) : base(o) { }
    public DbSet<Producer> Producers => Set<Producer>();
    public DbSet<Package> Packages => Set<Package>();
    public DbSet<Voucher> Vouchers => Set<Voucher>();
    public DbSet<Dealer> Dealers => Set<Dealer>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Grievance> Grievances => Set<Grievance>();
    public DbSet<Catalogue> Catalogue => Set<Catalogue>();
    public DbSet<Audit> Audit => Set<Audit>();
    public DbSet<Message> Messages => Set<Message>();
    public DbSet<Application> Applications => Set<Application>();
    public DbSet<Payment> Payments => Set<Payment>();
    public DbSet<Feedback> Feedback => Set<Feedback>();
    public DbSet<FarmerRegister> FarmerRegister => Set<FarmerRegister>();
}

static class Seed
{
    public static void Run(AppDb db)
    {
        // demo strings use · (middle dot) so the front-end can split out the age
        var prods = new (string n, string pr, string di, string en, string st, string ri, string de)[] {
            ("Thabo Mokoena","FS","Mangaung","Maize 4ha","Active","Verified","M·41"),
            ("Nomsa Dlamini","KZN","uMzinyathi","Vegetables 1.5ha","Active","Verified","F·29"),
            ("Thandeka Mthembu","KZN","uMzinyathi","Maize 2ha","Active","Verified","F·41"),
            ("Sipho Buthelezi","KZN","uMzinyathi","Goats 35 head","Active","Verified","M·52"),
            ("Zanele Khumalo","KZN","Zululand","Vegetables 2ha","Active","Verified","F·26"),
            ("Pieter van Wyk","WC","West Coast","Wheat 12ha","Pending","Verified","M·53"),
            ("Lerato Sithole","GP","Tshwane","Poultry 800 birds","Active","Verified","F·34"),
            ("Kabelo Maluleke","GP","Tshwane","Vegetables 2ha","Active","Verified","M·40"),
            ("Sipho Ndlovu","MP","Ehlanzeni","Sugarcane 6ha","Active","Verified","M·47"),
            ("Grace Nkosi","MP","Ehlanzeni","Vegetables 1ha","Active","Verified","F·27"),
            ("Tshepo Molefe","NW","Bojanala Platinum","Sunflower 15ha","Active","Verified","M·36"),
            ("Anna Botha","NW","Ngaka Modiri Molema","Cattle 40 head","Suspended","Mismatch","F·61"),
            ("Dineo Phiri","LP","Vhembe","Tomatoes 3ha","Active","Verified","F·31"),
            ("Mulalo Ramavhoya","LP","Vhembe","Maize 4ha","Active","Verified","M·38"),
            ("Andile Mbeki","EC","OR Tambo","Maize 2.5ha","Active","Verified","M·33"),
        };
        foreach (var p in prods) db.Producers.Add(new Producer { Name = p.n, Prov = p.pr, Dist = p.di, Ent = p.en, Status = p.st, Rica = p.ri, Demo = p.de, Email = MakeEmailS(p.n) });

        db.Packages.AddRange(
            new Package { Name = "Maize starter pack", Val = 3200, Items = "Maize seed 10kg + LAN 50kg" },
            new Package { Name = "Vegetable seed + fertiliser", Val = 1850, Items = "Veg seed kit + fertiliser" },
            new Package { Name = "Poultry feed pack", Val = 2400, Items = "Starter feed 40kg x2" },
            new Package { Name = "Sunflower seed + fertiliser", Val = 5400, Items = "Sunflower seed 5kg + fert." });

        db.Dealers.AddRange(
            new Dealer { Name = "AgriMart Tshwane", Prov = "GP", Dist = "Tshwane", Contact = "D. Naidoo", Status = "Active" },
            new Dealer { Name = "uMzinyathi Agri Co-op", Prov = "KZN", Dist = "uMzinyathi", Contact = "M. Ndlovu", Status = "Active" },
            new Dealer { Name = "KZN Agri Supplies", Prov = "KZN", Dist = "Zululand", Contact = "B. Cele", Status = "Active" },
            new Dealer { Name = "Vhembe Farm Centre", Prov = "LP", Dist = "Vhembe", Contact = "R. Netshi", Status = "Active" });

        db.Users.AddRange(
            new User { Username = "admin", Password = "admin123", Name = "Motshidisi Sitali", Role = "national", Scope = "All provinces" },
            new User { Username = "baldwinnetshifhefhe@gmail.com", Password = "2026", Name = "Baldwin Netshifhefhe", Role = "national", Scope = "All provinces" },
            new User { Username = "kzn", Password = "kzn123", Name = "Quinton Nyoka", Role = "provincial", Scope = "KZN" },
            new User { Username = "umzinyathi", Password = "dist123", Name = "Bongani Ndlovu", Role = "district", Scope = "uMzinyathi" },
            new User { Username = "dealer", Password = "dealer123", Name = "AgriMart Tshwane", Role = "dealer", Scope = "AgriMart Tshwane" });

        db.Catalogue.AddRange(
            new Catalogue { N = "Maize seed (10kg)", C = "Seed", P = 850, S = "Approved" },
            new Catalogue { N = "LAN fertiliser (50kg)", C = "Fertiliser", P = 620, S = "Approved" },
            new Catalogue { N = "Vegetable seed kit", C = "Seed", P = 430, S = "Approved" });

        db.Vouchers.AddRange(
            new Voucher { No = "EV-2026-004471", Who = "Thabo Mokoena", Prov = "FS", Pkg = "Maize starter pack", Val = 3200, Status = "Redeemed", Otp = "1234", Dealer = "AgriMart Tshwane", Created = "12 May 2026", RedeemedAt = "12 May 2026", Expiry = FyEndS() },
            new Voucher { No = "EV-2026-004472", Who = "Nomsa Dlamini", Prov = "KZN", Pkg = "Vegetable seed + fertiliser", Val = 1850, Status = "Issued", Otp = "4821", Created = "13 May 2026", Expiry = FyEndS() });
        db.Payments.Add(new Payment { Ts = "12 May 2026", Supplier = "AgriMart Tshwane", VoucherNo = "EV-2026-004471", Who = "Thabo Mokoena", Amount = 3200, Gateway = "PayGate (gateway)", Ref = "PG-10000001", Status = "Paid" });
        db.Applications.AddRange(
            new Application { Name = "Sibusiso Khoza", Prov = "KZN", Dist = "uMzinyathi", Ent = "Maize 2ha", Demo = "M·30", Status = "Applied", Created = "today" },
            new Application { Name = "Refilwe Mahlangu", Prov = "GP", Dist = "Tshwane", Ent = "Vegetables 1ha", Demo = "F·27", Status = "Applied", Created = "today" });
        db.Grievances.AddRange(
            new Grievance { Ref = "GR-0041", Who = "Pieter van Wyk", Issue = "Agro-dealer out of stock of fertiliser", Status = "Resolved", Created = "today" },
            new Grievance { Ref = "GR-0042", Who = "Anna Botha", Issue = "Voucher not received — RICA mismatch", Status = "Open", Created = "today" });
        db.SaveChanges();

        // farmer register = all current beneficiaries (enrolled) + a few awaiting enrolment
        foreach (var p in db.Producers.ToList()) db.FarmerRegister.Add(new FarmerRegister { Name = p.Name, Prov = p.Prov, Dist = p.Dist, Ent = p.Ent, Demo = p.Demo, Rica = p.Rica, Enrolled = 1 });
        db.FarmerRegister.AddRange(
            new FarmerRegister { Name = "Lwazi Nene", Prov = "KZN", Dist = "uMzinyathi", Ent = "Vegetables 1ha", Demo = "M·28", Enrolled = 0 },
            new FarmerRegister { Name = "Naledi Radebe", Prov = "FS", Dist = "Mangaung", Ent = "Beans 2ha", Demo = "F·35", Enrolled = 0 },
            new FarmerRegister { Name = "Vusi Mabaso", Prov = "MP", Dist = "Ehlanzeni", Ent = "Maize 3ha", Demo = "M·44", Enrolled = 0 },
            new FarmerRegister { Name = "Precious Sibeko", Prov = "LP", Dist = "Vhembe", Ent = "Tomatoes 1ha", Demo = "F·32", Enrolled = 0 });
        db.SaveChanges();
    }
    static string MakeEmailS(string name) => new string(name.ToLower().Where(c => char.IsLetter(c) || c == ' ').ToArray()).Trim().Replace(" ", ".") + "@example.co.za";
    static string FyEndS() { var d = DateTime.Now; int y = d.Month >= 4 ? d.Year + 1 : d.Year; return $"{y}-03-31"; }
}
