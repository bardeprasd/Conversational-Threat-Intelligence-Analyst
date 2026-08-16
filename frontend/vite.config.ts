/** Development and production bundler configuration for the React client. */
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // Match the backend's default local CORS allowlist and README instructions.
    port: 5173,
  },
});
