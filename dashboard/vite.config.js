import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',  // ✅ Все /api/* → сервер
      '/logs': 'http://localhost:8080', // ✅ /logs → сервер
      '/alerts': 'http://localhost:8080' // ✅ /alerts → сервер
    }
  }
})
