# Put the C# system live on the web (Render)

The code is already on GitHub:
**https://github.com/baldwinnetshifhefhe-svg/evoucher-csharp**

Render will build the included **Dockerfile** in the cloud (you do NOT need Docker on your
PC) and give you a public link like `https://evoucher-csharp.onrender.com`.

## Steps (in your browser)
1. Go to **https://dashboard.render.com** and log in (same account as your other apps).
2. Top-right: click **New +** → **Blueprint**.
3. Pick the repository **evoucher-csharp** (connect GitHub if it asks).
4. Render reads `render.yaml` and shows a service called **evoucher-csharp** (Docker, Free).
   Click **Apply** / **Create**.
5. Wait ~5–10 minutes for the first build. When it goes **Live**, open the URL at the top.
6. Log in with **admin / admin123** (or **baldwinnetshifhefhe@gmail.com / 2026**).

If "Blueprint" gives trouble, use **New + → Web Service** instead, pick the same repo,
Render auto-detects the Dockerfile, leave defaults, **Create Web Service**.

## Notes
- **Free plan** sleeps after 15 min idle and wipes the SQLite data on restart — fine for a
  demo. For permanent data, attach a Render disk or move to SQL Server.
- Every time you (or I) push to GitHub `main`, Render auto-rebuilds and redeploys.
