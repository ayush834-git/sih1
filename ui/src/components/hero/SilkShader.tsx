/**
 * SilkShader — WebGL silk shader hero background
 * SIH 26153 / Predictive Cyber Defense
 *
 * Uses a raw WebGL canvas with custom GLSL for smooth, animated,
 * pointer-interactive silk-like fabric effect in the brand palette.
 * Palette: OLED Black (#000), Electric Yellow (#FFD60A), pale highlight.
 *
 * Preserved behavior:
 * - Continuous animation loop
 * - Pointer / mouse interaction
 * - Resize handling via ResizeObserver
 * - Page visibility pause/resume
 * - WebGL context cleanup on unmount
 */

import { useEffect, useRef } from 'react'

/* ── GLSL Shaders ──────────────────────────────────────────────────── */

const VERT = /* glsl */ `
  attribute vec2 a_position;
  void main() {
    gl_Position = vec4(a_position, 0.0, 1.0);
  }
`

const FRAG = /* glsl */ `
  precision highp float;

  uniform vec2  u_resolution;
  uniform float u_time;
  uniform vec2  u_pointer;   /* normalised [0,1] */

  /* ── Brand palette ──────────────────────────────────────── */
  /* OLED black: 0,0,0  Electric yellow: 1.0,0.839,0.039     */
  const vec3 COL_BLACK  = vec3(0.00, 0.00, 0.00);
  const vec3 COL_DARK   = vec3(0.04, 0.04, 0.04);
  const vec3 COL_YELLOW = vec3(1.00, 0.839, 0.039);  /* #FFD60A */
  const vec3 COL_PALE   = vec3(1.00, 0.95,  0.70);   /* warm pale highlight */

  /* ── Noise helpers ──────────────────────────────────────── */
  float hash(vec2 p) {
    p = fract(p * vec2(127.1, 311.7));
    p += dot(p, p + 19.31);
    return fract(p.x * p.y);
  }

  float smoothNoise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(
      mix(hash(i + vec2(0,0)), hash(i + vec2(1,0)), u.x),
      mix(hash(i + vec2(0,1)), hash(i + vec2(1,1)), u.x),
      u.y
    );
  }

  float fbm(vec2 p) {
    float v = 0.0;
    float a = 0.5;
    vec2  s = vec2(1.0);
    for (int i = 0; i < 5; i++) {
      v += a * smoothNoise(p * s);
      s  *= 2.1;
      a  *= 0.5;
    }
    return v;
  }

  /* ── Silk fold function ─────────────────────────────────── */
  float silk(vec2 uv, float t) {
    float n1 = fbm(uv * 2.0 + t * 0.09);
    float n2 = fbm(uv * 3.5 - t * 0.06 + n1);
    float n3 = fbm(uv * 1.2 + t * 0.04 + n2 * 0.8);
    return n3;
  }

  void main() {
    vec2 uv = gl_FragCoord.xy / u_resolution;
    /* keep aspect correct for the silk field */
    vec2 aspect = u_resolution / min(u_resolution.x, u_resolution.y);
    vec2 st  = (uv - 0.5) * aspect;

    float t  = u_time * 0.55;

    /* pointer influence — very gentle warp */
    vec2 ptr = (u_pointer - 0.5) * aspect;
    float pDist  = length(st - ptr);
    float pWarp  = exp(-pDist * 2.0) * 0.28;
    vec2  pShift = normalize(st - ptr + 0.001) * pWarp;

    float s = silk(st + pShift, t);

    /* ── colour mapping ─────────────────────────────────── */
    /* primary layer: dark → rich black */
    vec3 col = mix(COL_BLACK, COL_DARK, smoothstep(0.0, 0.35, s));

    /* yellow accent: visible in meaningful regions of silk folds */
    float yMask = smoothstep(0.38, 0.62, s);
    col = mix(col, COL_YELLOW * 0.85, yMask * 0.75);

    /* pale yellow specular highlight at brightest crests */
    float hMask = smoothstep(0.60, 0.80, s);
    col = mix(col, COL_PALE * 0.9, hMask * 0.45);

    /* pointer-area brightening — clearly interactive */
    float pGlow = exp(-pDist * 2.8) * 0.22;
    col += COL_YELLOW * pGlow;

    /* gentle vignette — edges fade but don't kill the shader */
    float vignette = 1.0 - smoothstep(0.6, 1.4, length(uv - 0.5) * 1.3);
    col *= vignette;

    gl_FragColor = vec4(col, 1.0);
  }
`

/* ── WebGL bootstrap helpers ───────────────────────────────────────── */

function compileShader(gl: WebGLRenderingContext, type: number, src: string) {
  const shader = gl.createShader(type)!
  gl.shaderSource(shader, src)
  gl.compileShader(shader)
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error('Shader compile error:', gl.getShaderInfoLog(shader))
    gl.deleteShader(shader)
    return null
  }
  return shader
}

function buildProgram(gl: WebGLRenderingContext) {
  const vert = compileShader(gl, gl.VERTEX_SHADER, VERT)
  const frag = compileShader(gl, gl.FRAGMENT_SHADER, FRAG)
  if (!vert || !frag) return null

  const prog = gl.createProgram()!
  gl.attachShader(prog, vert)
  gl.attachShader(prog, frag)
  gl.linkProgram(prog)

  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
    console.error('Program link error:', gl.getProgramInfoLog(prog))
    return null
  }
  return prog
}

/* ── Component ─────────────────────────────────────────────────────── */

interface SilkShaderProps {
  className?: string
}

export function SilkShader({ className }: SilkShaderProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const gl = canvas.getContext('webgl', { antialias: false, alpha: false })
    if (!gl) {
      console.warn('SilkShader: WebGL not available')
      return
    }

    const program = buildProgram(gl)
    if (!program) return

    gl.useProgram(program)

    /* Full-screen quad */
    const buf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, buf)
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
      gl.STATIC_DRAW,
    )

    const aPos = gl.getAttribLocation(program, 'a_position')
    gl.enableVertexAttribArray(aPos)
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0)

    /* Uniform locations */
    const uRes = gl.getUniformLocation(program, 'u_resolution')
    const uTime = gl.getUniformLocation(program, 'u_time')
    const uPtr = gl.getUniformLocation(program, 'u_pointer')

    /* State */
    let raf = 0
    let startTime = performance.now()
    let pointer = { x: 0.5, y: 0.5 }
    let targetPointer = { x: 0.5, y: 0.5 }
    let visible = !document.hidden

    /* ── Resize ──────────────────────────────────────────── */
    function resize() {
      const w = canvas!.clientWidth * devicePixelRatio
      const h = canvas!.clientHeight * devicePixelRatio
      if (canvas!.width !== w || canvas!.height !== h) {
        canvas!.width = w
        canvas!.height = h
        gl!.viewport(0, 0, w, h)
      }
    }

    const ro = new ResizeObserver(resize)
    ro.observe(canvas)
    resize()

    /* ── Pointer ─────────────────────────────────────────── */
    function onPointerMove(e: PointerEvent) {
      const rect = canvas!.getBoundingClientRect()
      targetPointer = {
        x: (e.clientX - rect.left) / rect.width,
        y: 1.0 - (e.clientY - rect.top) / rect.height,
      }
    }

    /* Lerp factor per frame — very gentle */
    const LERP = 0.04

    /* ── Render loop ─────────────────────────────────────── */
    function render() {
      if (!visible) {
        raf = requestAnimationFrame(render)
        return
      }

      /* Smoothly lerp pointer to target */
      pointer.x += (targetPointer.x - pointer.x) * LERP
      pointer.y += (targetPointer.y - pointer.y) * LERP

      const t = (performance.now() - startTime) * 0.001

      gl!.uniform2f(uRes, canvas!.width, canvas!.height)
      gl!.uniform1f(uTime, t)
      gl!.uniform2f(uPtr, pointer.x, pointer.y)
      gl!.drawArrays(gl!.TRIANGLE_STRIP, 0, 4)

      raf = requestAnimationFrame(render)
    }

    /* ── Visibility handling ─────────────────────────────── */
    function onVisibilityChange() {
      visible = !document.hidden
      if (visible) startTime = performance.now() - startTime
    }

    /* ── Reduced motion ──────────────────────────────────── */
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (!mq.matches) {
      window.addEventListener('pointermove', onPointerMove, { passive: true })
      document.addEventListener('visibilitychange', onVisibilityChange)
      raf = requestAnimationFrame(render)
    } else {
      /* Still render one frame for static display */
      const t = 0
      gl.uniform2f(uRes, canvas.width, canvas.height)
      gl.uniform1f(uTime, t)
      gl.uniform2f(uPtr, 0.5, 0.5)
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4)
    }

    /* ── Cleanup ─────────────────────────────────────────── */
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      window.removeEventListener('pointermove', onPointerMove)
      document.removeEventListener('visibilitychange', onVisibilityChange)
      gl.deleteBuffer(buf)
      gl.deleteProgram(program)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={className}
      style={{ display: 'block', width: '100%', height: '100%' }}
      aria-hidden="true"
    />
  )
}
