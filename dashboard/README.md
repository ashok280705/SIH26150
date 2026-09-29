# VidForge Forensic Command & Navigation Portal

A standalone, visually rich cyber-forensics dashboard designed as a centralized landing pad and quick-access directory for the VidForge Video Recovery & Analysis platform.

---

## Deploying ONLY the Dashboard on Vercel

You can deploy just this `dashboard/` directory to Vercel without building or deploying the rest of the project.

### Step-by-Step Vercel Deployment

1. **Import the Repository**:
   - Go to [Vercel](https://vercel.com) and click **"Add New..."** → **"Project"**.
   - Select your repository: **`ashok280705/VIDEO`**.

2. **Set the Root Directory**:
   - In the project configuration screen, look for **Root Directory**.
   - Click **Edit** and set it to:
     ```text
     dashboard
     ```
   - Check the box **"Include files outside the Root Directory"** if prompted (or leave default).

3. **Build & Output Settings**:
   - **Framework Preset**: **Other**
   - **Build Command**: `node build.js` (or leave as default `npm run build`)
   - **Output Directory**: `.` (current directory / root of `dashboard`)
   - **Install Command**: *(leave blank or default)*

4. **Environment Variables for the Dashboard**:
   Expand **Environment Variables** and add the links you want:

   | Key | Value | Description |
   | :--- | :--- | :--- |
   | `VIDFORGE_RENDER_URL` | `https://vidforge-forensics.onrender.com` | Deployed backend / frontend URL |
   | `VIDFORGE_GITHUB_URL` | `https://github.com/ashok280705/VIDEO` | Your repository link |
   | `VIDFORGE_API_URL` | *(optional)* `https://vidforge-forensics.onrender.com/api` | Specific API endpoint override |
   | `VIDFORGE_HEALTH_URL`| *(optional)* `https://vidforge-forensics.onrender.com/health`| Health probe endpoint override |

5. **Click "Deploy"**:
   - Vercel will run `build.js`, inject your environment variables, and publish the dashboard in seconds!

---

## Customizing Links in Code (`config.js`)

If you prefer to edit links directly in the code without Vercel environment variables:
1. Open [`dashboard/config.js`](file:///c:/Users/HP/Downloads/COMPUTER/SIH-TakeUForward/VIDEO/dashboard/config.js).
2. Edit `DEPLOYED_WEB_URL` or add custom items to `CUSTOM_LINKS`:
   ```javascript
   CUSTOM_LINKS: [
     {
       id: "my-tool",
       title: "External Forensic Storage",
       desc: "Secure evidentiary archive storage",
       category: "tools", // Options: "deployment" | "tools" | "api" | "docs" | "repo"
       icon: "🗄️",
       tag: "Archive",
       path: "https://my-storage.example.com",
       isRelative: false,
       primaryAction: "Open Archive"
     }
   ]
   ```

---

## Running Locally

- **Double-click** `index.html` to open directly in any browser.
- **Or serve via Node**: `npx serve .` inside `dashboard/`.
