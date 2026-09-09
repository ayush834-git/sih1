import React, { useEffect, useRef } from 'react';
import './GlowingCursorFollower.css';

export interface GlowingCursorFollowerProps {
  className?: string;
  eyebrow?: string;
  title?: string;
  description?: string;
  linkText?: string;
  linkHref?: string;
}

export const GlowingCursorFollower: React.FC<GlowingCursorFollowerProps> = ({
  className = '',
  eyebrow = 'Portfolio · hero',
  title = 'A cursor that trails behind you',
  description = 'The dot locks to your pointer; the ring eases in with a springy lag. Pure requestAnimationFrame interpolation.',
  linkText = 'See the work',
  linkHref = '#',
}) => {
  const stageRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const stage = stageRef.current;
    const dot = dotRef.current;
    const ring = ringRef.current;
    if (!stage || !dot || !ring) return;

    const fine = window.matchMedia('(hover:hover) and (pointer:fine)').matches;
    const reduce = window.matchMedia('(prefers-reduced-motion:reduce)').matches;
    if (!fine || reduce) return;

    let mx = 0, my = 0, rx = 0, ry = 0;
    let raf = 0;

    const onPointerEnter = (e: PointerEvent) => {
      const r = stage.getBoundingClientRect();
      mx = rx = e.clientX - r.left;
      my = ry = e.clientY - r.top;
      stage.classList.add('is-live');
    };

    const onPointerMove = (e: PointerEvent) => {
      const r = stage.getBoundingClientRect();
      mx = e.clientX - r.left;
      my = e.clientY - r.top;
    };

    const onPointerLeave = () => {
      stage.classList.remove('is-live');
    };

    stage.addEventListener('pointerenter', onPointerEnter);
    stage.addEventListener('pointermove', onPointerMove);
    stage.addEventListener('pointerleave', onPointerLeave);

    const hoverElements = stage.querySelectorAll('[data-hover]');
    const onElementEnter = () => {
      ring.style.transform = `${ring.style.transform} scale(1.8)`;
      ring.style.scale = '1.8';
    };
    const onElementLeave = () => {
      ring.style.scale = '1';
    };

    hoverElements.forEach((el) => {
      el.addEventListener('pointerenter', onElementEnter);
      el.addEventListener('pointerleave', onElementLeave);
    });

    const loop = () => {
      rx += (mx - rx) * 0.15;
      ry += (my - ry) * 0.15;
      ring.style.transform = `translate(${rx}px,${ry}px) translate(-50%,-50%)`;
      dot.style.transform = `translate(${mx}px,${my}px) translate(-50%,-50%)`;
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      stage.removeEventListener('pointerenter', onPointerEnter);
      stage.removeEventListener('pointermove', onPointerMove);
      stage.removeEventListener('pointerleave', onPointerLeave);
      hoverElements.forEach((el) => {
        el.removeEventListener('pointerenter', onElementEnter);
        el.removeEventListener('pointerleave', onElementLeave);
      });
    };
  }, []);

  return (
    <section className={`ccs-02 ${className}`}>
      <div className="ccs-02__stage" ref={stageRef} data-stage>
        <div className="ccs-02__ring" ref={ringRef} data-ring aria-hidden="true" />
        <div className="ccs-02__dot" ref={dotRef} data-dot aria-hidden="true" />
        <div className="ccs-02__content">
          <span className="ccs-02__eyebrow">{eyebrow}</span>
          <h2>{title}</h2>
          <p>
            {description.includes('requestAnimationFrame') ? (
              <>
                The dot locks to your pointer; the ring eases in with a springy lag. Pure{' '}
                <code>requestAnimationFrame</code> interpolation.
              </>
            ) : (
              description
            )}
          </p>
          <a className="ccs-02__link" href={linkHref} data-hover>
            {linkText}
          </a>
        </div>
      </div>
    </section>
  );
};

export default GlowingCursorFollower;
