import { useEffect } from 'react'

/**
 * Scroll effects for the whole page, with no animation library:
 * - [data-parallax] elements get --p, their distance from the viewport centre in viewport
 *   heights (0 when centred, negative above). Layers inside move by calc(var(--p) * depth).
 * - .reveal elements get .in the first time they scroll into view.
 * Nothing moves when the visitor prefers reduced motion.
 */
export function useMotion() {
  useEffect(() => {
    const root = document.documentElement
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return
    root.classList.add('motion')

    const reveal = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue
        e.target.classList.add('in')
        reveal.unobserve(e.target)
      }
    }, { rootMargin: '0px 0px -8% 0px' })
    document.querySelectorAll('.reveal').forEach((el) => reveal.observe(el))

    const layers = [...document.querySelectorAll('[data-parallax]')]
    let frame = 0
    const update = () => {
      frame = 0
      const vh = innerHeight
      for (const el of layers) {
        const r = el.getBoundingClientRect()
        if (r.bottom < -vh || r.top > 2 * vh) continue
        el.style.setProperty('--p', ((r.top + r.height / 2 - vh / 2) / vh).toFixed(4))
      }
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(update) }
    update()
    addEventListener('scroll', schedule, { passive: true })
    addEventListener('resize', schedule)
    return () => {
      reveal.disconnect()
      cancelAnimationFrame(frame)
      removeEventListener('scroll', schedule)
      removeEventListener('resize', schedule)
      root.classList.remove('motion')
    }
  }, [])
}
