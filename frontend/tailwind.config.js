/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Vercel Dark Theme Tokens (Default)
        primary: {
          DEFAULT: '#ffffff',
          hover: '#e5e5e5',
        },
        'on-primary': '#000000',
        ink: '#ededed',
        body: '#a1a1a1',
        mute: '#737373',
        hairline: {
          DEFAULT: '#262626',
          strong: '#404040',
        },
        canvas: {
          DEFAULT: '#0a0a0a',
          soft: '#000000',
          'soft-2': '#141414',
          card: '#0a0a0a',
          dark: '#000000',
        },
        link: {
          DEFAULT: '#0070f3',
          deep: '#3291ff',
          soft: '#00254d',
        },
        error: {
          DEFAULT: '#f87171',
          soft: '#450a0a',
          deep: '#ef4444',
        },
        warning: {
          DEFAULT: '#fbbf24',
          soft: '#451a03',
          deep: '#f59e0b',
        },
        violet: {
          DEFAULT: '#a855f7',
          soft: '#2e1065',
          deep: '#7928ca',
        },
        cyan: {
          DEFAULT: '#50e3c2',
          soft: '#042f2e',
          deep: '#29bc9b',
        },
        highlight: {
          pink: '#ff0080',
          magenta: '#eb367f',
        },
        gradient: {
          'develop-start': '#007cf0',
          'develop-end': '#00dfd8',
          'preview-start': '#7928ca',
          'preview-end': '#ff0080',
          'ship-start': '#ff4d4d',
          'ship-end': '#f9cb28',
        },
        // Cyber compatibility layer mapped to crisp Vercel Dark Mode
        cyber: {
          bg: '#000000',
          surface: '#0a0a0a',
          card: '#0a0a0a',
          border: '#262626',
          cyan: '#50e3c2',
          blue: '#0070f3',
          purple: '#a855f7',
          red: '#f87171',
          green: '#50e3c2',
          yellow: '#fbbf24',
        },
      },
      fontFamily: {
        sans: ['Geist', 'Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"Geist Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      borderRadius: {
        xs: '4px',
        sm: '6px',
        md: '8px',
        lg: '12px',
        xl: '16px',
        'pill-sm': '64px',
        pill: '100px',
        full: '9999px',
      },
      letterSpacing: {
        'tight-xl': '-2.4px',
        'tight-lg': '-1.28px',
        'tight-md': '-0.96px',
        'tight-sm': '-0.6px',
        'tight-xs': '-0.28px',
      },
      boxShadow: {
        'elevation-1': 'inset 0 0 0 1px #262626',
        'elevation-2': '0 0 0 1px #262626, 0 2px 4px rgba(0,0,0,0.4)',
        'elevation-3': '0 0 0 1px #262626, 0 4px 12px rgba(0,0,0,0.5)',
        'elevation-4': '0 0 0 1px #262626, 0 8px 24px -4px rgba(0,0,0,0.6)',
        'elevation-5': '0 0 0 1px #262626, 0 16px 36px -8px rgba(0,0,0,0.8)',
        'elevation-glow': '0 0 0 1px rgba(80,227,194,0.3), 0 0 20px rgba(80,227,194,0.15)',
      },
      animation: {
        'pulse-subtle': 'pulse-subtle 2s ease-in-out infinite',
        'scan': 'scan 3s linear infinite',
        'slide-in': 'slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        'pulse-subtle': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-12px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
