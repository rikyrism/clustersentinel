import Layout from '../components/Layout.jsx'
import { BlockHead, PageHero, Progress } from '../components/ui.jsx'
import { PHASES, REPO } from '../data/site.js'

const STATUS = { done: 'Done', next: 'Next', planned: 'Planned' }

const OUT_OF_SCOPE = [
  'Automatic remediation: fixes stay a patch for a human to review',
  'Image vulnerability scanning',
  'Runtime threat detection or a node agent',
  'Admission control',
  'A web dashboard or an external database',
]

export default function Roadmap() {
  return (
    <Layout current="roadmap">
      <PageHero label="Roadmap" title="From operator to 0.1 in seven phases.">
        <p className="lede">
          Each phase is tested on its own before the next one starts. The reasoning behind every decision is in
          the <a href={`${REPO}/blob/main/docs/implementation-plan.md`}>implementation plan</a>.
        </p>
        <Progress />
      </PageHero>

      <section className="block">
        <div className="container">
          <ol className="timeline">
            {PHASES.map((p, i) => (
              <li key={p.title} className={`${p.state} reveal`}>
                <div className="row">
                  <span className="label">Phase {i + 1}</span>
                  <span className={`status ${p.state}`}>{STATUS[p.state]}</span>
                </div>
                <h2>{p.title}</h2>
                <p>{p.summary}</p>
                <ul>{p.items.map((item) => <li key={item}>{item}</li>)}</ul>
                {p.verified && <p className="verified">Verified: {p.verified}</p>}
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="block">
        <div className="container">
          <BlockHead label="Not planned" title="Out of scope, on purpose.">
            These keep ClusterSentinel small. Good tools for them already exist.
          </BlockHead>
          <ul className="checks no reveal">{OUT_OF_SCOPE.map((x) => <li key={x}>{x}</li>)}</ul>
        </div>
      </section>
    </Layout>
  )
}
