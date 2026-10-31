import { PHASES, REPO } from '../data/site.js'

export function Notice({ label, children }) {
  return (
    <div className="notice">
      <span className="label">{label}</span>
      <p>{children}</p>
    </div>
  )
}

export function Severity({ level }) {
  return <span className={`sev ${level}`}>{level}</span>
}

export function Progress() {
  return (
    <div className="progress" aria-hidden="true">
      {PHASES.map((p) => <i key={p.title} className={p.state} />)}
    </div>
  )
}

export function BlockHead({ label, title, children }) {
  return (
    <div className="block-head reveal">
      <span className="label">{label}</span>
      <h2>{title}</h2>
      {children && <p>{children}</p>}
    </div>
  )
}

/** Terminal block: lines starting with "$ " get a prompt, "# ..." after a command is a comment. */
export function Shell({ lines, title = 'zsh' }) {
  return (
    <div className="window">
      <div className="window-bar" aria-hidden="true"><i /><i /><i /><span>{title}</span></div>
      <pre>
        <code>
          {lines.map(([cmd, comment], i) => (
            <span key={i}>
              <span className="p">$ </span>
              {cmd}
              {comment && <span className="c">{`  # ${comment}`}</span>}
              {i < lines.length - 1 && '\n'}
            </span>
          ))}
        </code>
      </pre>
    </div>
  )
}

export function QuickStart() {
  return (
    <Shell
      lines={[
        [`git clone ${REPO}.git`],
        ['cd clustersentinel'],
        ['make kind-deploy', 'local kind cluster, image built and loaded, operator deployed'],
        ['export KUBECONFIG=$PWD/bin/kind-dev.kubeconfig'],
        ['kubectl get securityfindings -A'],
      ]}
    />
  )
}

/** Soft background for a page hero: a grid and two colour washes that drift as you scroll. */
export function Backdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="layer grid" />
      <div className="layer wash a" />
      <div className="layer wash b" />
    </div>
  )
}

/** Hero for inner pages. */
export function PageHero({ label, title, children }) {
  return (
    <div className="hero page" data-parallax>
      <Backdrop />
      <div className="container">
        <span className="pill">{label}</span>
        <h1>{title}</h1>
        {children}
      </div>
    </div>
  )
}
