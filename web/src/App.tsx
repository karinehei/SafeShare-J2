import { useEffect, useState } from "react"
import { loadPublishedBundle, type LoadedBundle } from "./data.ts"
import { parseHash, type Route } from "./model.ts"
import { ExampleWorkspace, ExamplesHome, HowView, ProvenanceFooter, RulesView } from "./components/Views.tsx"

function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash))
  useEffect(() => {
    const sync = () => setRoute(parseHash(window.location.hash))
    window.addEventListener("hashchange", sync)
    return () => window.removeEventListener("hashchange", sync)
  }, [])
  return route
}

export function App() {
  const route = useRoute()
  const [bundle, setBundle] = useState<LoadedBundle | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    loadPublishedBundle(controller.signal)
      .then((loaded) => {
        if (!controller.signal.aborted) setBundle(loaded)
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return
        setError(reason instanceof Error ? reason.message : String(reason))
      })
    return () => controller.abort()
  }, [])

  return (
    <>
      <a className="skip" href="#content">
        Skip to content
      </a>
      <header className="site-header">
        <p className="kicker">SafeShare J2</p>
        <h1>SafeShare J2 Explorer</h1>
        <p className="banner">Actual J2-generated results · Synthetic examples · Interactive report viewer</p>
        <ul className="boundary">
          <li>J2 runs during dataset generation, before publication.</li>
          <li>The browser displays previously generated results.</li>
          <li>No scanning or sanitization runs in the visitor’s browser.</li>
          <li>Results demonstrate heuristic detection, not a guarantee of safety.</li>
        </ul>
      </header>
      <nav className="site-nav" aria-label="Primary">
        <a href="#/examples" aria-current={route.page === "examples" ? "page" : undefined}>
          Examples
        </a>
        <a href="#/rules" aria-current={route.page === "rules" ? "page" : undefined}>
          Rule explorer
        </a>
        <a href="#/how" aria-current={route.page === "how" ? "page" : undefined}>
          How it works
        </a>
      </nav>
      <main id="content" className="wrap">
        {error ? (
          <section role="alert" className="card error-card">
            <h2>Demo data is not available</h2>
            <pre className="error-text">{error}</pre>
          </section>
        ) : null}
        {!error && !bundle ? <p role="status">Loading published demo data.</p> : null}
        {bundle ? <Workspace bundle={bundle} route={route} /> : null}
      </main>
      {bundle ? <ProvenanceFooter manifest={bundle.manifest} /> : null}
    </>
  )
}

function Workspace({ bundle, route }: { bundle: LoadedBundle; route: Route }) {
  if (route.page === "rules") return <RulesView rules={bundle.rules} />
  if (route.page === "how") return <HowView manifest={bundle.manifest} />
  if (route.page === "unknown") {
    return (
      <section role="alert">
        <h2>Unrecognized link</h2>
        <p>This hash does not match an example or a page in the explorer.</p>
        <p>
          <a href="#/examples">Back to examples</a>
        </p>
      </section>
    )
  }
  if (route.page === "examples") return <ExamplesHome examples={bundle.examples} />
  const example = bundle.examples.find((item) => item.id === route.exampleId)
  if (!example) {
    return (
      <section role="alert">
        <h2>Unknown example</h2>
        <p>No packaged example has id {route.exampleId}.</p>
        <ExamplesHome examples={bundle.examples} />
      </section>
    )
  }
  return <ExampleWorkspace example={example} route={route} />
}
