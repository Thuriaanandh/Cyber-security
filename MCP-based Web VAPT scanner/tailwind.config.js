/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        surface: "#f5f7fb",
        card: "#ffffff",
        line: "#e5e7eb",
        ink: "#0f172a"
      },
      boxShadow: {
        panel: "0 10px 24px -18px rgba(15, 23, 42, 0.35)",
        soft: "0 2px 14px -10px rgba(15, 23, 42, 0.25)"
      }
    }
  },
  plugins: []
};
