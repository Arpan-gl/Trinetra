/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: '#090A0F',
          subtle: '#0D0E15',
          elevated: '#13141F',
          surface: '#1A1C2B',
        },
        sentinel: {
          emerald: '#00FFA3',
          cyan: '#00E5FF',
          blue: '#3B82F6',
          purple: '#8B5CF6',
          red: '#FF3366',
          amber: '#FFB800',
        },
        border: {
          subtle: 'rgba(255, 255, 255, 0.08)',
          glow: 'rgba(0, 255, 163, 0.3)',
          cyan: 'rgba(0, 229, 255, 0.3)',
        }
      },
      fontFamily: {
        sans: ['Geist', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'glow-emerald': '0 0 25px -5px rgba(0, 255, 163, 0.3)',
        'glow-cyan': '0 0 25px -5px rgba(0, 229, 255, 0.3)',
        'glow-red': '0 0 25px -5px rgba(255, 51, 102, 0.4)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
}
