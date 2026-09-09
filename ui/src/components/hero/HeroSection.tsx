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
import { TraceText, OrbitText } from '@/components/common/EncasedHover'
import { MetallicShimmerText } from '@/components/common/MetallicShimmerText'

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
        {/* Brand mark — left (Curvy Pill) */}
        <div className="flex items-center gap-3 bg-black/45 border border-white/10 backdrop-blur-md px-4 py-2 rounded-full shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
          <div className="w-2.5 h-2.5 rounded-full bg-[#F0C808] shadow-[0_0_8px_rgba(240,200,8,0.7)] animate-pulse" />
          <div className="flex flex-col" style={{ gap: '1px' }}>
            <MetallicShimmerText
              as="span"
              variant="gold"
              mode="sweep"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(10px, 0.85vw, 12px)',
                letterSpacing: '0.22em',
                textTransform: 'uppercase' as const,
                fontWeight: 600,
              }}
            >
              PREDICTIVE DEFENSE
            </MetallicShimmerText>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(8px, 0.7vw, 10px)',
                letterSpacing: '0.18em',
                textTransform: 'uppercase' as const,
                color: 'var(--muted)',
              }}
            >
              SIH 26153
            </span>
          </div>
        </div>

        {/* Nav links — right (Curvy Pill Container) */}
        <div className="flex items-center gap-2 bg-black/45 border border-white/10 backdrop-blur-md px-3 py-1 rounded-full shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
          <TraceText
            to="/pipeline/observe"
            variant="pill"
            className="hidden sm:inline-flex text-white/70 hover:text-[#F0C808] text-[10px] tracking-[0.2em] px-3 py-1"
          >
            OBSERVE
          </TraceText>
          <TraceText
            to="/pipeline/trace"
            variant="pill"
            className="hidden sm:inline-flex text-white/70 hover:text-[#F0C808] text-[10px] tracking-[0.2em] px-3 py-1"
          >
            AUDIT TRACE
          </TraceText>
          <Link
            to="/pipeline/observe"
            data-hover="true"
            className="px-4 py-1.5 rounded-full bg-[#F0C808] text-black font-bold text-xs uppercase tracking-wider transition-all duration-200 hover:bg-[#FFE14C] hover:shadow-[0_0_15px_rgba(240,200,8,0.45)]"
            style={{
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.15em',
              textDecoration: 'none',
            }}
          >
            CONTROL CENTER →
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
          tabIndex={0}
          className="group animate-fade-in-up select-none outline-none focus-visible:ring-2 focus-visible:ring-[#F0C808]/60 focus-visible:ring-offset-4 focus-visible:ring-offset-black rounded-xl"
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
          <span className="block">
            <MetallicShimmerText as="span" variant="monochrome" mode="sweep">
              PREDICTIVE
            </MetallicShimmerText>
          </span>
          <span className="block">
            <MetallicShimmerText as="span" variant="gold" mode="ambient">
              CYBER
            </MetallicShimmerText>
          </span>
          <span className="block">
            <MetallicShimmerText as="span" variant="monochrome" mode="sweep">
              DEFENSE
            </MetallicShimmerText>
          </span>
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
          className="animate-fade-in-up delay-500 inline-block"
          style={{ marginTop: 'clamp(1.5rem, 3vh, 2.5rem)' }}
        >
          <OrbitText
            to="/pipeline/observe"
            className="text-xs sm:text-sm font-bold shadow-[0_0_24px_rgba(240,200,8,0.2)]"
          >
            <span>ENTER CONTROL CENTRE</span>
            <span className="text-[#F0C808]">→</span>
          </OrbitText>
        </div>

        {/* Technical metadata */}
        <div
          className="animate-fade-in delay-700"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'clamp(0.6rem, 1.2vw, 1rem)',
            flexWrap: 'wrap' as const,
            marginTop: 'clamp(1.5rem, 3vh, 2.5rem)',
          }}
        >
          {['SIH 26153', 'PREDICTIVE SECURITY', 'HUMAN-GATED'].map((tag, i) => (
            <span
              key={i}
              className="px-4 py-1.5 rounded-full border border-white/10 bg-white/[0.04] backdrop-blur-md text-white/70 font-mono tracking-widest text-[10px] uppercase shadow-[0_2px_10px_rgba(0,0,0,0.3)] hover:border-[#F0C808]/40 hover:text-white transition-all"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </section>
  )
}
