# Version 4 - Shareable Local Demo

CyberIntel Copilot is a local-first application. Its local Qwen model, Chroma
database, CISA data, NVD cache, and uploaded reports live on the laptop that
runs it. A free Render web service cannot host this full system: its free plan
has 512 MB RAM, can spin down after idle time, and loses local files on restart.

This Version 4 workflow exposes the running local app through a temporary
Cloudflare Quick Tunnel. It needs no Docker, cloud database, paid API, or model
API key.

## One-time setup

Open PowerShell and run:

```powershell
winget install --id Cloudflare.cloudflared -e
```

Close and reopen PowerShell after installation. Check it with:

```powershell
cloudflared --version
```

## Start a public demo

Open two PowerShell windows.

In window 1, start CyberIntel Copilot:

```powershell
cd C:\Users\sanyaagr\Documents\ChatGPT\GL\cyberintel-copilot
powershell -ExecutionPolicy Bypass -File .\scripts\start_local.ps1
```

In window 2, create the temporary public URL:

```powershell
cd C:\Users\sanyaagr\Documents\ChatGPT\GL\cyberintel-copilot
powershell -ExecutionPolicy Bypass -File .\scripts\share_local_demo.ps1
```

Copy the `https://...trycloudflare.com` URL shown in window 2 and share it for
a short demo. Keep both terminal windows open. Press `Ctrl+C` in window 2 to
remove the public URL; press `Ctrl+C` in window 1 to stop the app.

## Safety checklist

- Share only with people you trust.
- Do not upload private, internal, customer, or sensitive reports while public.
- The URL is temporary and changes each time you run the tunnel.
- Treat the link as a demo URL, not a production deployment.

## Future Render deployment

Do not deploy the current full local stack to Render Free. A future paid/cloud
deployment needs a hosted model or a sufficiently large model server, persistent
storage for Chroma/uploads, authentication, rate limiting, and a privacy review.
