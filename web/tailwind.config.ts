import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0f172a",
        bg2: "#1e293b",
        bg3: "#334155",
        border: "#475569",
        accent: "#38bdf8",
      },
    },
  },
  plugins: [],
};

export default config;
