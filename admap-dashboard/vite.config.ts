import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from "path"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Port figé sur 3000 : c'est l'origine déjà autorisée par la liste CORS du
  // gateway (admap_gateway/main.py). `strictPort` évite un glissement silencieux
  // vers 5173/5174 qui casserait le CORS. Le dashboard cible le gateway sur
  // http://localhost:9000 (cf. src/lib/config.ts, surchargeable via VITE_GATEWAY_URL).
  server: {
    port: 3000,
    strictPort: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
