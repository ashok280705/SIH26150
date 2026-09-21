import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      // Proxy the offline assistant to the local Ollama server so the browser can
      // reach it same-origin (no CORS / no OLLAMA_ORIGINS setup needed in dev).
      // Override the target with VITE_OLLAMA_TARGET if Ollama runs elsewhere.
      '/ollama': {
        target: process.env.VITE_OLLAMA_TARGET || 'http://127.0.0.1:11434',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/ollama/, ''),
      },
    },
  },
});
