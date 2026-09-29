# VidForge Forensic Command & Navigation Portal

A high-performance, cyber-forensics dashboard designed as a centralized landing pad and quick-access directory for the VidForge Video Recovery & Analysis platform.

## Features
- **Centralized Links & Endpoints**: Instant navigation to the deployed web application, Axum REST endpoints, HLS video streams, seeded Dahua DVR cases, and GitHub repositories.
- **Dynamic Deployment Switcher**: Live toggle between your Render deployment, local ports (`:10000`, `:5173`), or any custom cloud domain.
- **Live Health Status Probe**: Real-time ping tester evaluating `/health` latency directly against your deployed backend.
- **Interactive Search & Filtering**: Instant fuzzy filtering (`/` hotkey) across categories (Live Deployment, Forensic Tools, APIs, Docs, Repos).
- **One-Click Clipboard Actions**: Quick-copy buttons for target URLs and local/Docker launch commands.
- **Ultra-Modern Aesthetics**: Cyber dark theme, ambient mesh particle canvas, glassmorphic cards, and responsive grid.

## How to Run

### Option 1: Direct File Open
Simply double-click `index.html` or open it in any modern browser (Chrome, Edge, Firefox, Safari).

### Option 2: Run via Any Static HTTP Server
```bash
# Using Node's npx serve
npx serve dashboard

# Or using Python's built-in HTTP server
python -m http.server 3000 --directory dashboard
```

### Option 3: Deploy as a Static Web Page
This folder is 100% self-contained and zero-dependency. You can deploy it to:
- **GitHub Pages**
- **Vercel**
- **Netlify**
- **Render Static Site**
