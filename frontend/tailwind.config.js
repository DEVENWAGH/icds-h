/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#050a14',
          surface: '#0a1628',
          card: '#0d1f3c',
          border: '#1a3a6e',
          cyan: '#00e5ff',
          blue: '#0066ff',
          purple: '#7c3aed',
          red: '#ff2d55',
          green: '#00ff88',
          yellow: '#ffd60a',
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        sans: ['"Exo 2"', '"Rajdhani"', 'sans-serif'],
      },
      animation: {
        'pulse-cyan': 'pulse-cyan 2s ease-in-out infinite',
        'scan': 'scan 3s linear infinite',
        'flicker': 'flicker 0.3s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.4s ease-out',
      },
      keyframes: {
        'pulse-cyan': {
          '0%, 100%': { boxShadow: '0 0 5px #00e5ff, 0 0 10px #00e5ff' },
          '50%': { boxShadow: '0 0 20px #00e5ff, 0 0 40px #00e5ff' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        flicker: {
          '0%': { opacity: 1 }, '100%': { opacity: 0.8 }
        },
        slideIn: {
          '0%': { transform: 'translateX(-20px)', opacity: 0 },
          '100%': { transform: 'translateX(0)', opacity: 1 }
        }
      },
      backdropBlur: { xs: '2px' }
    }
  },
  plugins: []
}
