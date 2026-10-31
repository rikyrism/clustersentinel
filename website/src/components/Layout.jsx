import { REPO } from '../data/site.js'
import GitHubStars from './GitHubStars.jsx'
import { useMotion } from './motion.js'

const NAV = [
  { href: '/docs/', label: 'Docs', key: 'docs' },
  { href: '/roadmap/', label: 'Roadmap', key: 'roadmap' },
]

export default function Layout({ current, children }) {
  useMotion()
  return (
    <>
      <header className="site-header">
        <div className="container">
          <a className="brand" href="/">
            <img src="/mark.svg" alt="" width="26" height="26" />
            <span>ClusterSentinel</span>
          </a>
          <nav className="site-nav" aria-label="Main">
            {NAV.map((n) => (
              <a key={n.key} href={n.href} aria-current={n.key === current ? 'page' : undefined}>
                {n.label}
              </a>
            ))}
            <GitHubStars />
          </nav>
        </div>
      </header>
      <main id="main">{children}</main>
      <footer className="site-footer">
        <div className="container">
          <p>
            © {new Date().getFullYear()} ClusterSentinel. All rights reserved. Source code:{' '}
            <a href={REPO}>{REPO.replace('https://', '')}</a>
          </p>
          <nav aria-label="Footer">
            <a href="/docs/">Docs</a>
            <a href="/roadmap/">Roadmap</a>
            <a href={REPO}>GitHub</a>
            <a href={`${REPO}/issues`}>Issues</a>
            <a href={`${REPO}/blob/main/CHANGELOG.md`}>Changelog</a>
          </nav>
        </div>
      </footer>
    </>
  )
}
