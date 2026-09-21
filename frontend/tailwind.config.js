/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        github: {
          canvas: '#0d1117',
          subtle: '#161b22',
          overlay: '#21262d',
          inset: '#010409',
          border: '#30363d',
          'border-muted': '#21262d',
          fg: '#f0f6fc',
          muted: '#8b949e',
          blue: '#58a6ff',
          green: '#238636',
          'green-hover': '#2ea043',
          'green-text': '#3fb950',
          red: '#f85149',
          gold: '#d29922',
          purple: '#bc8cff',
        },
        navy: {
          750: '#30363d', // GitHub border / active surface
          800: '#21262d', // GitHub overlay / elevated surface
          850: '#1c2128', // GitHub card background
          900: '#161b22', // GitHub canvas subtle (sidebar, header, panels)
          950: '#0d1117', // GitHub canvas default (main background)
        },
        slate: {
          850: '#1c2128',
          900: '#161b22',
          950: '#0d1117',
        },
        cyan: {
          300: '#79c0ff', // GitHub light blue
          400: '#58a6ff', // GitHub primary accent blue
          500: '#1f6feb', // GitHub solid blue
          600: '#388bfd', // GitHub deep blue
        },
        emerald: {
          400: '#3fb950', // GitHub verified green text/badge
          500: '#238636', // GitHub primary button green
          600: '#2ea043', // GitHub hover green
        },
        rose: {
          400: '#f85149', // GitHub issue / alert red
          500: '#da3633', // GitHub solid red
          600: '#b62324',
        },
        amber: {
          400: '#d29922', // GitHub warning gold
          500: '#9e6a03',
        },
        purple: {
          400: '#bc8cff', // GitHub merged purple
          500: '#8957e5',
        },
        silver: {
          100: '#f8fafc',
          200: '#e2e8f0', // Clean silver/platinum
          300: '#cbd5e1', // Classic metallic silver
          400: '#94a3b8',
          500: '#64748b',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Noto Sans', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'SF Mono', 'Menlo', 'Consolas', 'Liberation Mono', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 0 1px rgba(88, 166, 255, 0.4), 0 2px 8px rgba(1, 4, 9, 0.4)',
        'glow-green': '0 0 0 1px rgba(63, 185, 80, 0.4), 0 2px 8px rgba(1, 4, 9, 0.4)',
        'glow-silver': '0 0 0 1px rgba(226, 232, 240, 0.3), 0 2px 8px rgba(1, 4, 9, 0.5)',
        'glow-red': '0 0 0 1px rgba(248, 81, 73, 0.4), 0 2px 8px rgba(1, 4, 9, 0.4)',
        'subtle': '0 1px 3px rgba(1, 4, 9, 0.8), 0 0 0 1px #30363d',
        'github-card': '0 1px 0 rgba(255, 255, 255, 0.04), 0 0 0 1px #30363d',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 2s ease-in-out infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-in-left': 'slideInLeft 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        scanLine: {
          '0%, 100%': { transform: 'translateX(-100%)' },
          '50%': { transform: 'translateX(100%)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInLeft: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
};
