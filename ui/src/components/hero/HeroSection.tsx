/**
 * HeroSection — Landing hero for SIH 26153 Predictive Cyber Defense
 *
 * Layer stack (bottom → top):
 *   1. ShaderBackground (supplied 21st.dev Silk — authoritative visual)
 *   2. Subtle readability gradient (pointer-events: none)
 *   3. Navigation (absolute top)
 *   4. Hero content (editorial lower-third with responsive spacing)
 */

import { Link } from 'react-router-dom'
import { ShaderBackground } from '@/components/ui/rds-silk'
import SlideTextButton from '@/components/kokonutui/slide-text-button'

export function HeroSection() {
  return (
    <section
      className="relative w-full overflow-hidden"
      style={{ height: '100vh', minHeight: '600px', maxHeight: '1200px' }}
      aria-label="Predictive Cyber Defense — hero"
    >
      {/* ── 1. Supplied Silk Shader ───────────────────────── */}
      <div className="absolute inset-0 z-0" aria-hidden="true">
        <ShaderBackground className="h-full w-full" />
      </div>

      {/* ── 2. Readability gradient ──────────────────────── */}
      <div
        className="absolute inset-0 z-10 pointer-events-none"
        style={{
          background: [
            'linear-gradient(to bottom, rgba(0,0,0,0.35) 0%, transparent 28%)',
            'linear-gradient(to top, rgba(0,0,0,0.50) 0%, transparent 40%)',
          ].join(', '),
        }}
        aria-hidden="true"
      />

      {/* ── 3. Navigation ────────────────────────────────── */}
      <nav
        className="absolute top-0 left-0 right-0 z-30 flex items-center justify-between"
        style={{ padding: 'clamp(1.25rem, 3vh, 2rem) clamp(1.5rem, 7vw, 5rem)' }}
        aria-label="Primary navigation"
      >
        {/* Brand mark — left */}
        <div className="flex flex-col" style={{ gap: '3px' }}>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(10px, 0.85vw, 13px)',
              letterSpacing: '0.22em',
              textTransform: 'uppercase' as const,
              color: 'rgba(255,255,255,0.92)',
              fontWeight: 500,
            }}
          >
            PREDICTIVE DEFENSE
          </span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(9px, 0.7vw, 11px)',
              letterSpacing: '0.18em',
              textTransform: 'uppercase' as const,
              color: 'var(--muted)',
            }}
          >
            SIH 26153
          </span>
        </div>

        {/* Nav links — right */}
        <div className="flex items-center" style={{ gap: 'clamp(1.2rem, 2.5vw, 2.5rem)' }}>
          {['SYSTEM', 'EVIDENCE'].map((label) => (
            <a
              key={label}
              href="#"
              className="hidden sm:block"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(10px, 0.8vw, 12px)',
                letterSpacing: '0.2em',
                textTransform: 'uppercase' as const,
                color: 'rgba(255,255,255,0.50)',
                textDecoration: 'none',
                transition: 'color 0.2s ease',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#fff' }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.50)' }}
            >
              {label}
            </a>
          ))}
          <Link
            to="/command-center"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(10px, 0.8vw, 12px)',
              letterSpacing: '0.2em',
              textTransform: 'uppercase' as const,
              color: 'var(--signal)',
              textDecoration: 'none',
              transition: 'color 0.2s ease',
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#fff' }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = 'var(--signal)' }}
          >
            ENTER →
          </Link>
        </div>
      </nav>

      {/* ── 4. Hero content ──────────────────────────────── */}
      <div
        className="absolute z-20"
        style={{
          bottom: 'clamp(2.5rem, 8vh, 6rem)',
          left: 'clamp(1.5rem, 7vw, 5rem)',
          right: 'clamp(1.5rem, 7vw, 5rem)',
          maxWidth: '56rem',
        }}
      >
        {/* Technical eyebrow */}
        <p
          className="animate-fade-in"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 'clamp(10px, 0.85vw, 13px)',
            letterSpacing: '0.3em',
            textTransform: 'uppercase' as const,
            color: 'var(--signal)',
            marginBottom: 'clamp(1rem, 2.5vh, 2rem)',
          }}
        >
          AR(5) · FORECASTING · UNCERTAINTY · RECONSIDERATION
        </p>

        {/* Display heading */}
        <h1
          className="animate-fade-in-up"
          style={{
            fontSize: 'clamp(2.8rem, 6.5vw, 6.5rem)',
            fontWeight: 800,
            lineHeight: 0.92,
            letterSpacing: '-0.035em',
            fontFamily: 'var(--font-display)',
            color: '#ffffff',
            margin: 0,
          }}
        >
          <span className="block">PREDICTIVE</span>
          <span className="block" style={{ color: 'var(--signal)' }}>CYBER</span>
          <span className="block">DEFENSE</span>
        </h1>

        {/* Thesis line */}
        <p
          className="animate-fade-in-up delay-200"
          style={{
            fontSize: 'clamp(1rem, 1.6vw, 1.3rem)',
            fontWeight: 500,
            letterSpacing: '-0.01em',
            lineHeight: 1.35,
            color: 'rgba(255,255,255,0.85)',
            maxWidth: '32ch',
            marginTop: 'clamp(1.2rem, 2.5vh, 2rem)',
          }}
        >
          SEE WHAT THE NETWORK<br />
          BECOMES NEXT.
        </p>

        {/* Supporting copy */}
        <p
          className="animate-fade-in-up delay-300"
          style={{
            fontSize: 'clamp(0.8rem, 1vw, 0.95rem)',
            lineHeight: 1.7,
            color: 'var(--muted)',
            maxWidth: '40ch',
            marginTop: 'clamp(0.6rem, 1.5vh, 1rem)',
          }}
        >
          Observe evolving network behaviour.{' '}
          <span style={{ color: 'rgba(255,255,255,0.45)' }}>Forecast what comes next.</span>
          {' '}Reconsider when reality changes.
        </p>

        {/* CTA */}
        <div
          className="animate-fade-in-up delay-500"
          style={{ marginTop: 'clamp(1.5rem, 3vh, 2.5rem)' }}
        >
          <SlideTextButton
            text="ENTER COMMAND CENTER"
            hoverText="ENTER COMMAND CENTER"
            href="/command-center"
            variant="default"
          />
        </div>

        {/* Technical metadata */}
        <div
          className="animate-fade-in delay-700"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'clamp(0.8rem, 1.5vw, 1.5rem)',
            flexWrap: 'wrap' as const,
            marginTop: 'clamp(1.5rem, 3vh, 2.5rem)',
          }}
        >
          {['SIH 26153', 'PREDICTIVE SECURITY', 'HUMAN-GATED'].map((tag, i) => (
            <span
              key={i}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(9px, 0.7vw, 11px)',
                letterSpacing: '0.2em',
                textTransform: 'uppercase' as const,
                color: 'var(--muted)',
              }}
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </section>
  )
}
