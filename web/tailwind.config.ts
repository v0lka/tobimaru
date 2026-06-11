import type { Config } from "tailwindcss";

// Monokai Pro (Classic filter) palette — colors taken from monokai.pro.
//
// The base UI tokens (bg, bg2, bg3, border, accent, fg, muted, comment) are
// the canonical Monokai Pro background and editor colors. The semantic
// scales (slate/sky/amber/emerald/red/indigo) are overridden so the existing
// Tailwind class usage across the dashboard automatically picks up the new
// palette without renaming utilities.
const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Core Monokai Pro Classic UI tokens.
        bg: "#2D2A2E", // editor background
        bg2: "#221F22", // sidebar / chrome
        bg3: "#403E41", // line / panel highlight
        border: "#5B595C", // separator
        accent: "#FFD866", // signature yellow
        fg: "#FCFCFA", // foreground text
        muted: "#939293", // secondary text
        comment: "#727072", // tertiary text

        // Monokai Pro hue tokens (named for direct reference where helpful).
        mono: {
          red: "#FF6188",
          orange: "#FC9867",
          yellow: "#FFD866",
          green: "#A9DC76",
          blue: "#78DCE8",
          purple: "#AB9DF2",
        },

        // Override default Tailwind scales so existing utilities such as
        // text-slate-400, bg-sky-500/20, pill-warning, etc. render in
        // Monokai Pro hues without touching every component.
        slate: {
          50: "#FCFCFA",
          100: "#FCFCFA",
          200: "#E3E1E4",
          300: "#C1C0C0",
          400: "#939293",
          500: "#727072",
          600: "#5B595C",
          700: "#403E41",
          800: "#2D2A2E",
          900: "#221F22",
          950: "#19181A",
        },
        sky: {
          50: "#E7FAFC",
          100: "#CFF4F8",
          200: "#A6EAF1",
          300: "#9EE6F0",
          400: "#78DCE8",
          500: "#78DCE8",
          600: "#3DC0CF",
          700: "#1A7A88",
          800: "#0E5560",
          900: "#0E3B43",
          950: "#0A2227",
        },
        amber: {
          50: "#FFF6D9",
          100: "#FFEEB3",
          200: "#FFE699",
          300: "#FFE699",
          400: "#FFD866",
          500: "#FFD866",
          600: "#FC9867",
          700: "#D17C4D",
          800: "#9E5C3A",
          900: "#6B3D26",
        },
        emerald: {
          50: "#E8F4D6",
          100: "#D6EDB6",
          200: "#C5E89C",
          300: "#C5E89C",
          400: "#A9DC76",
          500: "#A9DC76",
          600: "#7BC74D",
          700: "#5B9C36",
          800: "#3F7026",
          900: "#284817",
        },
        red: {
          50: "#FFE6ED",
          100: "#FFCFDB",
          200: "#FFA9BF",
          300: "#FF8DA9",
          400: "#FF6188",
          500: "#FF6188",
          600: "#E5476F",
          700: "#B92F58",
          800: "#8C2342",
          900: "#5E172D",
        },
        indigo: {
          300: "#C5BCF7",
          400: "#AB9DF2",
          500: "#AB9DF2",
          600: "#8C7BD8",
        },
        violet: {
          300: "#C5BCF7",
          400: "#AB9DF2",
          500: "#AB9DF2",
        },
      },
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "ui-monospace",
          "SF Mono",
          "Menlo",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};

export default config;
