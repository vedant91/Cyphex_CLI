import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'
import fs from 'fs'
import os from 'os'
import crypto from 'crypto'

// The backend (backend/backend/api.py) requires a shared X-API-Key on every
// request — see backend/backend/auth.py. Read the same per-installation key
// off disk here (a trusted Node build-time process, never over the network)
// so the frontend picks it up automatically with no manual configuration.
// Mirrors auth.py's get_or_create_api_key() so whichever process starts
// first "wins" and every other process converges on the same value.
function getOrCreateApiKey(): string {
  if (process.env.CYPHEX_API_KEY) return process.env.CYPHEX_API_KEY

  const keyDir = path.join(os.homedir(), '.cyphex')
  const keyFile = path.join(keyDir, 'api_key')

  try {
    return fs.readFileSync(keyFile, 'utf8').trim()
  } catch {
    // doesn't exist yet — generate it below
  }

  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 })
  const key = crypto.randomBytes(32).toString('base64url')
  try {
    fs.writeFileSync(keyFile, key, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    return key
  } catch {
    // Lost a race with another process creating the file at the same time —
    // whatever it wrote is the key everyone should use.
    return fs.readFileSync(keyFile, 'utf8').trim()
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  define: {
    'import.meta.env.VITE_API_KEY': JSON.stringify(getOrCreateApiKey()),
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
