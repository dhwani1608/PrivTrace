/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        display: ["'Space Grotesk'", "Inter", "system-ui", "sans-serif"],
        serif: ["'Instrument Serif'", "Georgia", "serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
      colors: {
        ink: {
          950: "#050409",
          900: "#0a0912",
          850: "#0e0c18",
          800: "#13111f",
          700: "#1b1829",
          600: "#26223a",
          500: "#3a3552",
        },
        lime: { DEFAULT: "#d4ff3f", 400: "#e1ff73", 500: "#d4ff3f", 600: "#b8e622" },
        sun: { DEFAULT: "#ffd84d" },
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(167,139,250,.35), 0 10px 40px -10px rgba(139,92,246,.55)",
        "glow-lg": "0 0 0 1px rgba(167,139,250,.25), 0 30px 80px -20px rgba(139,92,246,.6)",
        lift: "0 1px 0 0 rgba(255,255,255,.06) inset, 0 20px 50px -20px rgba(0,0,0,.8)",
        "lime-glow": "0 20px 60px -20px rgba(212,255,63,.55)",
      },
      keyframes: {
        float: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-12px)" } },
        "spin-slow": { to: { transform: "rotate(360deg)" } },
        "flow-dash": { to: { strokeDashoffset: "-24" } },
        "pulse-ring": { "0%": { transform: "scale(.8)", opacity: ".8" }, "100%": { transform: "scale(2.2)", opacity: "0" } },
        "fade-up": { "0%": { opacity: "0", transform: "translateY(14px)" }, "100%": { opacity: "1", transform: "translateY(0)" } },
        shimmer: { "0%": { backgroundPosition: "-200% 0" }, "100%": { backgroundPosition: "200% 0" } },
        aurora: {
          "0%,100%": { transform: "translate(0,0) scale(1)" },
          "33%": { transform: "translate(6%,-4%) scale(1.08)" },
          "66%": { transform: "translate(-5%,5%) scale(.95)" },
        },
      },
      animation: {
        float: "float 6s ease-in-out infinite",
        "float-slow": "float 9s ease-in-out infinite",
        "spin-slow": "spin-slow 18s linear infinite",
        "spin-slower": "spin-slow 40s linear infinite",
        "flow-dash": "flow-dash 1s linear infinite",
        "pulse-ring": "pulse-ring 1.8s cubic-bezier(.2,.6,.4,1) infinite",
        "fade-up": "fade-up .6s cubic-bezier(.2,.7,.2,1) both",
        shimmer: "shimmer 2.4s linear infinite",
        aurora: "aurora 22s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
