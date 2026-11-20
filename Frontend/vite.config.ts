import { defineConfig } from "vite";
const api = process.env.LAUNDROMAT_API_URL || "http://127.0.0.1:8731";
export default defineConfig({
  server: {
    host: "127.0.0.1",
    proxy: {
      "/scans": api,
      "/events": api,
      "/repositories": api,
    },
  },
});
