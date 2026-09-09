import React from 'react';
import { Link } from 'react-router-dom';

/**
 * CodeFronts CTH-18 — Animated Border / Encased Text Hover
 * Reusable presentation components for TRACE and ORBIT interaction languages.
 *
 * TRACE:
 * Two corner pseudo-elements draw an enclosing hairline border clockwise,
 * corner meeting corner, with text color accenting on hover.
 * Default for secondary, editorial, forensic inspection, and technical actions.
 *
 * ORBIT:
 * Rotating conic-gradient comet of light around enclosed text driven by @property --cth18-a.
 * Reserved strictly for rare primary CTAs (e.g. Landing Page ENTER, Pipeline START DEMO).
 */

export interface TraceTextProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
  as?: 'button' | 'a' | 'span' | 'div';
  to?: string;
  href?: string;
  variant?: 'default' | 'surface' | 'pill';
  isActive?: boolean;
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
  'data-cursor'?: string;
}

export const TraceText: React.FC<TraceTextProps> = ({
  children,
  as,
  to,
  href,
  variant = 'default',
  isActive = false,
  className = '',
  style,
  disabled,
  type = 'button',
  'data-cursor': dataCursor = 'interactive',
  ...rest
}) => {
  const variantClass =
    variant === 'surface'
      ? 'cth-trace--surface'
      : variant === 'pill'
      ? 'cth-trace--pill'
      : '';
  const activeClass = isActive ? 'is-active' : '';
  const combinedClasses = `cth-trace ${variantClass} ${activeClass} ${className}`.trim();
  const effectiveCursor = disabled ? 'default' : dataCursor;

  // If React Router 'to' is provided, render Link
  if (to) {
    return (
      <Link
        to={to}
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        {...(rest as any)}
      >
        <span className="cth-trace__content">{children}</span>
      </Link>
    );
  }

  // If standard anchor href is provided
  if (href || as === 'a') {
    return (
      <a
        href={href}
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        {...(rest as any)}
      >
        <span className="cth-trace__content">{children}</span>
      </a>
    );
  }

  if (as === 'span') {
    return (
      <span
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        tabIndex={rest.tabIndex ?? 0}
        {...rest}
      >
        <span className="cth-trace__content">{children}</span>
      </span>
    );
  }

  if (as === 'div') {
    return (
      <div
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        tabIndex={rest.tabIndex ?? 0}
        {...rest}
      >
        <span className="cth-trace__content">{children}</span>
      </div>
    );
  }

  // Default: button
  return (
    <button
      type={type}
      disabled={disabled}
      className={combinedClasses}
      style={style}
      data-cursor={effectiveCursor}
      {...(rest as any)}
    >
      <span className="cth-trace__content">{children}</span>
    </button>
  );
};

export interface OrbitTextProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
  as?: 'button' | 'a' | 'span' | 'div';
  to?: string;
  href?: string;
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
  'data-cursor'?: string;
}

export const OrbitText: React.FC<OrbitTextProps> = ({
  children,
  as,
  to,
  href,
  className = '',
  style,
  disabled,
  type = 'button',
  'data-cursor': dataCursor = 'interactive',
  ...rest
}) => {
  const combinedClasses = `cth-orbit ${className}`.trim();
  const effectiveCursor = disabled ? 'default' : dataCursor;

  if (to) {
    return (
      <Link
        to={to}
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        {...(rest as any)}
      >
        <span className="cth-orbit__inner">{children}</span>
      </Link>
    );
  }

  if (href || as === 'a') {
    return (
      <a
        href={href}
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        {...(rest as any)}
      >
        <span className="cth-orbit__inner">{children}</span>
      </a>
    );
  }

  if (as === 'span') {
    return (
      <span
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        tabIndex={rest.tabIndex ?? 0}
        {...rest}
      >
        <span className="cth-orbit__inner">{children}</span>
      </span>
    );
  }

  if (as === 'div') {
    return (
      <div
        className={combinedClasses}
        style={style}
        data-cursor={effectiveCursor}
        tabIndex={rest.tabIndex ?? 0}
        {...rest}
      >
        <span className="cth-orbit__inner">{children}</span>
      </div>
    );
  }

  return (
    <button
      type={type}
      disabled={disabled}
      className={combinedClasses}
      style={style}
      data-cursor={effectiveCursor}
      {...(rest as any)}
    >
      <span className="cth-orbit__inner">{children}</span>
    </button>
  );
};

