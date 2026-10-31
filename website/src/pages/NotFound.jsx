import Layout from '../components/Layout.jsx'
import { PageHero } from '../components/ui.jsx'

export default function NotFound() {
  return (
    <Layout current="">
      <PageHero label="404" title="This page does not exist.">
        <div className="actions">
          <a className="btn primary" href="/">Home</a>
          <a className="btn" href="/docs/">Docs</a>
        </div>
      </PageHero>
    </Layout>
  )
}
