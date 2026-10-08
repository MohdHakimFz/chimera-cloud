/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './resources/views/**/*.php',
    './public/assets/js/**/*.js'
  ],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        chimera: {
          400: '#5ee0c1',
          500: '#32c3a1',
          600: '#1b9a80',
          700: '#147563'
        }
      }
    }
  },
  plugins: []
};
