/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"],
      },
      colors: {
        base:    "#070A10",
        surface: "#0D1117",
        card:    "#13171F",
        border:  "#1E2530",
        teal:    "#00E5C5",
      },
    },
  },
  plugins: [],
};
