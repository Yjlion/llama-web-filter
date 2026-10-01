/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./management/ui/*.html"],
  theme: {
    extend: {
      colors: {
        canvas: "rgb(var(--wf-canvas) / <alpha-value>)",
        card:   "rgb(var(--wf-card)   / <alpha-value>)",
        gray: {
          50:  "rgb(var(--wf-gray-50)  / <alpha-value>)",
          100: "rgb(var(--wf-gray-100) / <alpha-value>)",
          200: "rgb(var(--wf-gray-200) / <alpha-value>)",
          300: "rgb(var(--wf-gray-300) / <alpha-value>)",
          400: "rgb(var(--wf-gray-400) / <alpha-value>)",
          500: "rgb(var(--wf-gray-500) / <alpha-value>)",
          600: "rgb(var(--wf-gray-600) / <alpha-value>)",
          700: "rgb(var(--wf-gray-700) / <alpha-value>)",
          800: "rgb(var(--wf-gray-800) / <alpha-value>)",
          900: "rgb(var(--wf-gray-900) / <alpha-value>)",
        },
        blue: {
          50:  "rgb(var(--wf-accent-50)  / <alpha-value>)",
          100: "rgb(var(--wf-accent-100) / <alpha-value>)",
          400: "rgb(var(--wf-accent-400) / <alpha-value>)",
          500: "rgb(var(--wf-accent-500) / <alpha-value>)",
          600: "rgb(var(--wf-accent-600) / <alpha-value>)",
          700: "rgb(var(--wf-accent-700) / <alpha-value>)",
          800: "rgb(var(--wf-accent-800) / <alpha-value>)",
        },
        sidebar: {
          DEFAULT: "rgb(var(--wf-sidebar)        / <alpha-value>)",
          ink:     "rgb(var(--wf-sidebar-ink)    / <alpha-value>)",
          muted:   "rgb(var(--wf-sidebar-muted)  / <alpha-value>)",
          active:  "rgb(var(--wf-sidebar-active) / <alpha-value>)",
          border:  "rgb(var(--wf-sidebar-border) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
