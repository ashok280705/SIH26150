/**
 * VidForge Portal & Deployment Dashboard Engine
 */

// Comprehensive Link Registry
const PORTAL_LINKS = [
  {
    id: 'web-app',
    title: 'VidForge Web Application',
    desc: 'Main forensic operator workstation — case explorer, preloaded Dahua DVR evidence, timeline, and multi-camera synchronized playback.',
    category: 'deployment',
    icon: '🖥️',
    tag: 'Web Interface',
    path: '/',
    isRelative: true,
    primaryAction: 'Launch Console'
  },
  {
    id: 'health-check',
    title: 'Production Health Check',
    desc: 'Lightweight zero-allocation monitoring endpoint for Render health probes and uptime checkers.',
    category: 'api',
    icon: '💚',
    tag: 'Monitoring',
    path: '/health',
    isRelative: true,
    primaryAction: 'Ping Probe'
  },
  {
    id: 'api-cases',
    title: 'Cases & Evidence API',
    desc: 'Axum REST endpoint managing court cases, physical disk acquisitions, and read-only evidence attachments.',
    category: 'api',
    icon: '📁',
    tag: 'REST API',
    path: '/api/cases',
    isRelative: true,
    primaryAction: 'Open Endpoint'
  },
  {
    id: 'demo-case',
    title: 'Preloaded Dahua DHFS 4.1 Case',
    desc: 'Immediate access to the seeded Dahua DVR/NVR demonstration case with live carving and frame recovery ready.',
    category: 'deployment',
    icon: '🎥',
    tag: 'Seeded Data',
    path: '/?case=demo',
    isRelative: true,
    primaryAction: 'View Demo Case'
  },
  {
    id: 'forensic-timeline',
    title: 'Synchronized Forensic Timeline',
    desc: 'Frame-accurate temporal indexing with microsecond precision, motion heatmaps, and multi-channel alignment.',
    category: 'tools',
    icon: '⏱️',
    tag: 'Core Tool',
    path: '/timeline',
    isRelative: true,
    primaryAction: 'Open Timeline'
  },
  {
    id: 'ai-copilot',
    title: 'Offline AI Forensic Copilot',
    desc: 'Air-gapped local LLM assistant (Ollama-backed) for automated incident questioning, metadata querying, and hypothesis validation.',
    category: 'tools',
    icon: '🧠',
    tag: 'AI Intelligence',
    path: '/assistant',
    isRelative: true,
    primaryAction: 'Launch Copilot'
  },
  {
    id: 'video-player',
    title: 'Multi-Camera Forensic Player',
    desc: 'Hardware-accelerated player supporting H.264 & H.265 transmuxing with timestamp overlays and tamper warnings.',
    category: 'tools',
    icon: '🎬',
    tag: 'Media Engine',
    path: '/player',
    isRelative: true,
    primaryAction: 'Open Player'
  },
  {
    id: 'carving-analysis',
    title: 'Deep Carving & Recovery Hub',
    desc: 'Automated OEM signature analysis, broken stream reconstruction, and fragmented cluster reassembly for proprietary DVRs.',
    category: 'tools',
    icon: '🔬',
    tag: 'Recovery Engine',
    path: '/analysis',
    isRelative: true,
    primaryAction: 'Inspect Carving'
  },
  {
    id: 'reporting-hub',
    title: 'Chain-of-Custody & Report Generator',
    desc: 'Generate ISO/IEC 27037 compliant court documentation, cryptographic hash records, and examiner logs.',
    category: 'docs',
    icon: '📜',
    tag: 'Compliance',
    path: '/reports',
    isRelative: true,
    primaryAction: 'View Reports'
  },
  {
    id: 'repo-root',
    title: 'GitHub Source Repository',
    desc: 'Primary Git repository hosting the complete Rust workspace, React frontend, OEM profiles, and test pipelines.',
    category: 'repo',
    icon: '📦',
    tag: 'Repository',
    path: 'https://github.com/ashok280705/VIDEO',
    isRelative: false,
    primaryAction: 'Browse GitHub'
  },
  {
    id: 'branch-desktop',
    title: 'Active Render Branch (windows-desktop)',
    desc: 'Production deployment branch containing Windows & Linux multi-platform fixes, process window isolation, and seeding.',
    category: 'repo',
    icon: '🌿',
    tag: 'Deployment Branch',
    path: 'https://github.com/ashok280705/VIDEO/tree/feature/windows-desktop',
    isRelative: false,
    primaryAction: 'View Branch'
  },
  {
    id: 'branch-acquisition',
    title: 'Physical Acquisition Branch',
    desc: 'Physical drive lock state, direct raw block reading, and safe disk-level acquisition subsystem branch.',
    category: 'repo',
    icon: '💾',
    tag: 'Core Branch',
    path: 'https://github.com/ashok280705/VIDEO/tree/feature/acquisition',
    isRelative: false,
    primaryAction: 'View Branch'
  },
  {
    id: 'docker-spec',
    title: 'Multi-Stage Dockerfile',
    desc: 'Official 3-stage container build (Node.js SPA + Rust Axum + Debian Bookworm runtime) with FFmpeg support.',
    category: 'docs',
    icon: '🐳',
    tag: 'Container Spec',
    path: 'https://github.com/ashok280705/VIDEO/blob/feature/windows-desktop/Dockerfile',
    isRelative: false,
    primaryAction: 'View Dockerfile'
  },
  {
    id: 'render-blueprint',
    title: 'Render Service Blueprint (render.yaml)',
    desc: 'Infrastructure-as-Code specification for zero-config Docker deployment on Render cloud.',
    category: 'docs',
    icon: '☁️',
    tag: 'Cloud Blueprint',
    path: 'https://github.com/ashok280705/VIDEO/blob/feature/windows-desktop/render.yaml',
    isRelative: false,
    primaryAction: 'View Blueprint'
  },
  {
    id: 'audit-spec',
    title: 'Universal Recovery & Data I/O Audit',
    desc: 'Comprehensive engineering verification of OEM format support, filesystem carvers, and memory safety benchmarks.',
    category: 'docs',
    icon: '🛡️',
    tag: 'Audit Report',
    path: 'https://github.com/ashok280705/VIDEO/blob/feature/windows-desktop/DATAIO_IMPLEMENTATION_AUDIT.md',
    isRelative: false,
    primaryAction: 'Read Audit'
  }
];

// App State
let currentBaseUrl = '';
let currentCategory = 'all';
let searchQuery = '';

// DOM Elements
const targetInput = document.getElementById('target-base-url');
const pingBtn = document.getElementById('btn-test-health');
const pingResult = document.getElementById('ping-result');
const searchInput = document.getElementById('link-search');
const categoryTabs = document.getElementById('category-tabs');
const linksGrid = document.getElementById('links-grid');
const toast = document.getElementById('toast');
const liveUtc = document.getElementById('live-utc');
const liveIndicator = document.getElementById('live-indicator');

// Preset buttons
const btnAuto = document.getElementById('btn-preset-auto');
const btnLocal10k = document.getElementById('btn-preset-local-10k');
const btnLocalVite = document.getElementById('btn-preset-local-vite');

// Initialize
function init() {
  detectInitialBaseUrl();
  setupEventListeners();
  renderCards();
  startClock();
  initCyberCanvas();
}

// Detect default base URL
function detectInitialBaseUrl() {
  const origin = window.location.origin;
  // If served via http/https, default to current origin; if opened via file:///, use default local/render
  if (origin && origin !== 'null' && !origin.startsWith('file://')) {
    currentBaseUrl = origin;
  } else {
    currentBaseUrl = 'http://localhost:10000';
  }
  targetInput.value = currentBaseUrl;
}

// Resolve Full URL
function resolveUrl(item) {
  if (!item.isRelative) {
    return item.path;
  }
  const base = (currentBaseUrl || '').trim().replace(/\/+$/, '');
  const path = item.path.startsWith('/') ? item.path : '/' + item.path;
  return base ? `${base}${path}` : path;
}

// Setup Event Listeners
function setupEventListeners() {
  // Target URL input change
  targetInput.addEventListener('input', (e) => {
    currentBaseUrl = e.target.value.trim();
    clearPresetActive();
    renderCards();
  });

  // Presets
  btnAuto.addEventListener('click', () => {
    setActivePreset(btnAuto);
    detectInitialBaseUrl();
    renderCards();
  });

  btnLocal10k.addEventListener('click', () => {
    setActivePreset(btnLocal10k);
    currentBaseUrl = 'http://localhost:10000';
    targetInput.value = currentBaseUrl;
    renderCards();
  });

  btnLocalVite.addEventListener('click', () => {
    setActivePreset(btnLocalVite);
    currentBaseUrl = 'http://localhost:5173';
    targetInput.value = currentBaseUrl;
    renderCards();
  });

  // Health Ping
  pingBtn.addEventListener('click', checkServiceHealth);

  // Search
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    renderCards();
  });

  // Keyboard shortcut '/' to search
  window.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== searchInput && document.activeElement !== targetInput) {
      e.preventDefault();
      searchInput.focus();
    }
  });

  // Category Tabs
  categoryTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentCategory = btn.dataset.category || 'all';
    renderCards();
  });

  // Command Cards copy buttons
  document.querySelectorAll('.copy-cmd-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.getAttribute('data-cmd');
      copyToClipboard(cmd, 'Command copied to clipboard!');
    });
  });
}

function clearPresetActive() {
  [btnAuto, btnLocal10k, btnLocalVite].forEach(b => b.classList.remove('active'));
}

function setActivePreset(button) {
  clearPresetActive();
  button.classList.add('active');
}

// Check Service Health (Ping)
async function checkServiceHealth() {
  const base = (currentBaseUrl || '').trim().replace(/\/+$/, '');
  if (!base) {
    showPingStatus('error', '⚠️ Please specify a valid target deployment host.');
    return;
  }

  showPingStatus('loading', '⚡ Pinging /health endpoint on ' + base + '...');
  const startTime = performance.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(`${base}/health`, {
      method: 'GET',
      mode: 'cors',
      signal: controller.signal
    }).catch(async () => {
      // Try /api/health fallback
      return await fetch(`${base}/api/health`, {
        method: 'GET',
        mode: 'cors',
        signal: controller.signal
      });
    });

    clearTimeout(timeoutId);
    const latency = Math.round(performance.now() - startTime);

    if (response.ok) {
      showPingStatus('success', `🟢 Service Online (${response.status} OK) — Latency: ${latency}ms`);
      liveIndicator.textContent = 'HOST REACHABLE';
      liveIndicator.style.color = 'var(--accent-green)';
    } else {
      showPingStatus('error', `🟠 Server responded with HTTP ${response.status} in ${latency}ms`);
    }
  } catch (err) {
    const latency = Math.round(performance.now() - startTime);
    if (err.name === 'AbortError') {
      showPingStatus('error', `🔴 Connection timed out after 6000ms. If deploying on Render Free Tier, the container might be waking up.`);
    } else {
      showPingStatus('error', `🔴 Host unreachable (${err.message}). Check CORS or if server is started.`);
    }
  }
}

function showPingStatus(type, msg) {
  pingResult.className = `config-status-bar ${type}`;
  const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : '⏳';
  pingResult.innerHTML = `<span class="ping-icon">${icon}</span><span class="ping-text">${msg}</span>`;
}

// Render Link Cards
function renderCards() {
  const filtered = PORTAL_LINKS.filter(item => {
    const matchesCategory = currentCategory === 'all' || item.category === currentCategory;
    const matchesSearch = !searchQuery ||
      item.title.toLowerCase().includes(searchQuery) ||
      item.desc.toLowerCase().includes(searchQuery) ||
      item.tag.toLowerCase().includes(searchQuery) ||
      item.path.toLowerCase().includes(searchQuery);
    return matchesCategory && matchesSearch;
  });

  if (filtered.length === 0) {
    linksGrid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 48px; background: var(--bg-card); border-radius: var(--radius-lg); border: 1px dashed var(--border-subtle);">
        <p style="font-size: 1.2rem; color: var(--text-secondary); margin-bottom: 8px;">No matching portals or tools found</p>
        <p style="font-size: 0.85rem; color: var(--text-muted);">Try a different search query or clear the filter.</p>
      </div>
    `;
    return;
  }

  linksGrid.innerHTML = filtered.map(item => {
    const fullUrl = resolveUrl(item);
    const tagClass = `tag-${item.category}`;

    return `
      <div class="link-card" data-id="${item.id}">
        <div>
          <div class="card-top">
            <div class="card-icon-title">
              <div class="card-icon">${item.icon}</div>
              <div>
                <span class="card-tag ${tagClass}">${item.tag}</span>
                <h3 class="card-title">${item.title}</h3>
              </div>
            </div>
          </div>
          <p class="card-desc" style="margin-top: 12px;">${item.desc}</p>
        </div>

        <div>
          <div class="card-target-url">
            <span>${escapeHtml(fullUrl)}</span>
          </div>

          <div class="card-actions" style="margin-top: 12px;">
            <a href="${fullUrl}" target="_blank" rel="noopener noreferrer" class="action-launch">
              <span>${item.primaryAction}</span>
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15 3 21 3 21 9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </a>
            <button class="action-copy" title="Copy URL" onclick="copyCardUrl('${escapeAttr(fullUrl)}')">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

window.copyCardUrl = function(url) {
  copyToClipboard(url, 'Target URL copied to clipboard!');
};

function copyToClipboard(text, message) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast(message));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast(message);
  }
}

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2600);
}

// Live Clock
function startClock() {
  function update() {
    const now = new Date();
    const utcStr = now.toISOString().substring(11, 19) + ' UTC';
    liveUtc.textContent = utcStr;
  }
  update();
  setInterval(update, 1000);
}

// Interactive Cyber Canvas Background
function initCyberCanvas() {
  const canvas = document.getElementById('cyber-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = canvas.width = window.innerWidth;
  let height = canvas.height = window.innerHeight;

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = [];
  const particleCount = Math.min(Math.floor((width * height) / 22000), 55);

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      radius: Math.random() * 1.5 + 0.8,
      color: Math.random() > 0.4 ? 'rgba(0, 242, 254, ' : 'rgba(121, 40, 202, '
    });
  }

  function render() {
    ctx.clearRect(0, 0, width, height);

    // Draw connecting lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 120) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0, 242, 254, ${0.12 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.7;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw and update particles
    for (let p of particles) {
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      if (p.y > height) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color + '0.5)';
      ctx.fill();
    }

    requestAnimationFrame(render);
  }

  requestAnimationFrame(render);
}

// Start app
document.addEventListener('DOMContentLoaded', init);
