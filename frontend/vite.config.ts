import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, /api and /health are proxied to the FastAPI backend.
const api = process.env.PRIVTRACE_API_URL ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": api, "/health": api },
  },
});
