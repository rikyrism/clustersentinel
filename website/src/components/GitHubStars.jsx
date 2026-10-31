import { useEffect, useState } from 'react'
import { REPO } from '../data/site.js'

const API = 'https://api.github.com/repos/rikyrism/clustersentinel'
const CACHE_KEY = 'cs-stars'

// Octicons "mark-github" (MIT licensed).
const MARK = 'M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z'
const STAR = 'M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z'

function readCache() {
  try {
    const v = sessionStorage.getItem(CACHE_KEY)
    return v === null ? null : Number(v)
  } catch {
    return null
  }
}

/** GitHub link with the repository's star count. Without the count (offline, rate limited)
 *  it is still a plain link to the repository. */
export default function GitHubStars() {
  const [stars, setStars] = useState(readCache)

  useEffect(() => {
    if (stars !== null) return
    const ctrl = new AbortController()
    fetch(API, { signal: ctrl.signal, headers: { Accept: 'application/vnd.github+json' } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.statusText))))
      .then((repo) => {
        if (typeof repo.stargazers_count !== 'number') return
        setStars(repo.stargazers_count)
        try { sessionStorage.setItem(CACHE_KEY, String(repo.stargazers_count)) } catch { /* storage off */ }
      })
      .catch(() => {})
    return () => ctrl.abort()
  }, [stars])

  const label = stars === null ? 'ClusterSentinel on GitHub' : `ClusterSentinel on GitHub, ${stars} stars`
  return (
    <a className="gh" href={REPO} aria-label={label}>
      <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" d={MARK} /></svg>
      <span className="gh-text">GitHub</span>
      <span className="gh-stars">
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d={STAR} /></svg>
        {stars === null ? 'Star' : new Intl.NumberFormat('en', { notation: 'compact' }).format(stars)}
      </span>
    </a>
  )
}
