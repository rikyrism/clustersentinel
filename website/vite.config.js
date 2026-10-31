import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// One HTML entry per page, so GitHub Pages serves real URLs (/docs/, /roadmap/)
// without a single-page-app fallback.
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        home: resolve(import.meta.dirname, 'index.html'),
        docs: resolve(import.meta.dirname, 'docs/index.html'),
        roadmap: resolve(import.meta.dirname, 'roadmap/index.html'),
        notFound: resolve(import.meta.dirname, '404.html'),
      },
    },
  },
})
