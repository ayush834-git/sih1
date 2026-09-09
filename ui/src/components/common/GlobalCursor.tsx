import React, { useEffect, useRef } from 'react';

/**
 * GlobalCursor
 *
 * Source of truth: CodeFronts "Smooth Glowing Cursor Follower with a Trailing Ring using requestAnimationFrame Lerp"
 *
 * Architecture:
 * - Mounted once at application root level (App.tsx)
 * - Persists continuously across route navigation, dialogs, drawers, and technical views
 * - Pure requestAnimationFrame linear interpolation (rx += (mx - rx) * 0.15, ry += (my - ry) * 0.15)
 * - Zero React re-renders on mousemove: coordinates and DOM transforms updated directly on refs
 * - Automatic interactive detection via global event delegation
 * - Respects (hover: hover) and (pointer: fine) and (prefers-reduced-motion: reduce)
 * - Pointer-events: none across all elements (never interferes with charts or click handlers)
 */

type CursorState = 'default' | 'interactive' | 'critical' | 'hidden';

export const GlobalCursor: React.FC = () => {
  const dotRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // 1. Accessibility & Device capabilities check
    const finePointerQuery = window.matchMedia('(hover: hover) and (pointer: fine)');
    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

    const isSupported = () => finePointerQuery.matches && !reducedMotionQuery.matches;

    if (!isSupported()) {
      return;
    }

    const dot = dotRef.current;
    const ring = ringRef.current;
    if (!dot || !ring) return;

    // Enable global cursor styling on html
    document.documentElement.classList.add('has-global-cursor');

    // 2. State & coordinates (held in closure to avoid React re-renders)
    let mx = -100;
    let my = -100;
    let rx = -100;
    let ry = -100;
    let isLive = false;
    let currentState: CursorState = 'default';
    let rafId = 0;

    const setCursorState = (state: CursorState) => {
      if (currentState === state) return;
      currentState = state;

      ring.classList.remove('is-interactive', 'is-critical', 'is-hidden');
      dot.classList.remove('is-interactive', 'is-critical', 'is-hidden');

      if (state !== 'default') {
        ring.classList.add(`is-${state}`);
        dot.classList.add(`is-${state}`);
      }
    };

    const showCursor = () => {
      if (!isLive) {
        isLive = true;
        ring.classList.add('is-live');
        dot.classList.add('is-live');
      }
    };

    const hideCursor = () => {
      if (isLive) {
        isLive = false;
        ring.classList.remove('is-live');
        dot.classList.remove('is-live');
      }
    };

    // 3. Pointer event handlers
    const onPointerMove = (e: PointerEvent) => {
      mx = e.clientX;
      my = e.clientY;

      if (!isLive) {
        // Initialize trailing ring position on first movement to avoid spring across screen
        rx = mx;
        ry = my;
        showCursor();
      }
    };

    const onPointerEnter = (e: PointerEvent) => {
      mx = e.clientX;
      my = e.clientY;
      showCursor();
    };

    const onPointerLeave = (e: PointerEvent) => {
      // If pointer leaves the viewport
      if (
        e.clientY <= 0 ||
        e.clientX <= 0 ||
        e.clientX >= window.innerWidth ||
        e.clientY >= window.innerHeight
      ) {
        hideCursor();
      }
    };

    // 4. Global interactive detection via event delegation (seamless across all routes/drawers/modals)
    const onPointerOver = (e: PointerEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target || !(target instanceof Element)) return;

      if (target.closest('[data-cursor="hidden"]')) {
        setCursorState('hidden');
      } else if (target.closest('[data-cursor="critical"]')) {
        setCursorState('critical');
      } else if (
        target.closest(
          'a, button, input, select, textarea, [role="button"], [data-cursor="interactive"], [data-hover="true"], [data-hover], label[for]'
        )
      ) {
        setCursorState('interactive');
      } else {
        setCursorState('default');
      }
    };

    const onPointerOut = (e: PointerEvent) => {
      // When leaving to window background, revert to default unless leaving document
      if (!e.relatedTarget) {
        hideCursor();
      }
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerenter', onPointerEnter, { passive: true });
    window.addEventListener('pointerleave', onPointerLeave, { passive: true });
    document.addEventListener('pointerover', onPointerOver, { passive: true });
    document.addEventListener('pointerout', onPointerOut, { passive: true });

    // 5. CodeFronts requestAnimationFrame Lerp loop
    const loop = () => {
      rx += (mx - rx) * 0.15;
      ry += (my - ry) * 0.15;

      // Use direct hardware-accelerated transforms
      dot.style.transform = `translate3d(${mx}px, ${my}px, 0) translate(-50%, -50%)`;
      ring.style.transform = `translate3d(${rx}px, ${ry}px, 0) translate(-50%, -50%)`;

      rafId = requestAnimationFrame(loop);
    };

    rafId = requestAnimationFrame(loop);

    // 6. Media query listeners (if user toggles settings or disconnects mouse)
    const handleMediaChange = () => {
      if (!isSupported()) {
        document.documentElement.classList.remove('has-global-cursor');
        hideCursor();
      } else {
        document.documentElement.classList.add('has-global-cursor');
      }
    };

    finePointerQuery.addEventListener('change', handleMediaChange);
    reducedMotionQuery.addEventListener('change', handleMediaChange);

    // 7. Cleanup
    return () => {
      cancelAnimationFrame(rafId);
      document.documentElement.classList.remove('has-global-cursor');
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerenter', onPointerEnter);
      window.removeEventListener('pointerleave', onPointerLeave);
      document.removeEventListener('pointerover', onPointerOver);
      document.removeEventListener('pointerout', onPointerOut);
      finePointerQuery.removeEventListener('change', handleMediaChange);
      reducedMotionQuery.removeEventListener('change', handleMediaChange);
    };
  }, []);

  return (
    <div className="global-cursor-portal" aria-hidden="true">
      <div ref={ringRef} className="global-cursor-ring" />
      <div ref={dotRef} className="global-cursor-dot" />
    </div>
  );
};

export default GlobalCursor;
