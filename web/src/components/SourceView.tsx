interface SourceViewProps {
  text: string
  label: string
  highlightLines: ReadonlySet<number>
  selectedLine: number | null
}

export function SourceView({ text, label, highlightLines, selectedLine }: SourceViewProps) {
  const lines = text.split("\n")
  return (
    <div className="code-panel">
      <p className="code-label">{label}</p>
      <pre tabIndex={0}>
        <code>
          {lines.map((line, index) => {
            const number = index + 1
            const selected = selectedLine === number
            const hit = highlightLines.has(number)
            const className = selected ? "line line-selected" : hit ? "line line-hit" : "line"
            return (
              <span key={number} className={className}>
                <span className="ln" aria-hidden="true">
                  {number}
                </span>
                <span className="lt">{line}</span>
              </span>
            )
          })}
        </code>
      </pre>
    </div>
  )
}
