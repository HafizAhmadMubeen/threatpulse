import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Loopback only, and a fixed port: the backend's CORS allows exactly this origin.
const server = { host: '127.0.0.1', port: 5173, strictPort: true }

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  // The tests read contracts/samples/. The dev server stays limited to frontend/.
  server: mode === 'test' ? { ...server, fs: { allow: ['.', '../contracts/samples'] } } : server,
  preview: server,
  test: { environment: 'jsdom' },
}))
