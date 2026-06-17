import type { Config } from "tailwindcss"
import tailwindcssAnimate from "tailwindcss-animate"

const config = {
  darkMode: ["class"],
  content: [
    './pages/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './app/**/*.{ts,tsx}',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
  	container: {
  		center: true,
  		padding: '2rem',
  		screens: {
  			'2xl': '1400px'
  		}
  	},
  	extend: {
  		colors: {
  			border: 'var(--border)',
  			input: 'var(--bg-tertiary)',
  			ring: 'var(--accent-cyan)',
  			background: 'var(--bg-primary)',
  			foreground: 'var(--text-primary)',
  			primary: {
  				DEFAULT: 'var(--accent-cyan)',
  				foreground: 'var(--bg-primary)'
  			},
  			secondary: {
  				DEFAULT: 'var(--bg-secondary)',
  				foreground: 'var(--text-secondary)'
  			},
  			destructive: {
  				DEFAULT: 'var(--accent-red)',
  				foreground: 'var(--text-primary)'
  			},
  			muted: {
  				DEFAULT: 'var(--bg-tertiary)',
  				foreground: 'var(--text-muted)'
  			},
  			accent: {
  				DEFAULT: 'var(--accent-cyan)',
  				foreground: 'var(--bg-primary)'
  			},
  			popover: {
  				DEFAULT: 'var(--bg-secondary)',
  				foreground: 'var(--text-primary)'
  			},
  			card: {
  				DEFAULT: 'var(--bg-secondary)',
  				foreground: 'var(--text-primary)'
  			}
  		},
  		borderRadius: {
  			lg: 'var(--radius)',
  			md: 'calc(var(--radius) - 2px)',
  			sm: 'calc(var(--radius) - 4px)'
  		},
  		keyframes: {
  			'accordion-down': {
  				from: {
  					height: '0'
  				},
  				to: {
  					height: 'var(--radix-accordion-content-height)'
  				}
  			},
  			'accordion-up': {
  				from: {
  					height: 'var(--radix-accordion-content-height)'
  				},
  				to: {
  					height: '0'
  				}
  			}
  		},
  		animation: {
  			'accordion-down': 'accordion-down 0.2s ease-out',
  			'accordion-up': 'accordion-up 0.2s ease-out'
  		}
  	}
  },
  plugins: [tailwindcssAnimate],
} satisfies Config

export default config
