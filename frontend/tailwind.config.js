/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        slate: {
          925: "#0B1120",
          950: "#070D18",
        },
      },
    },
  },
  plugins: [],
};
