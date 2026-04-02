function GraphPanel({ graphData }) {
  const nodes = graphData?.nodes || graphData?.graph?.nodes || [];
  const edges = graphData?.edges || graphData?.graph?.edges || [];

  return (
    <section className="rounded-2xl border border-line bg-card p-4 shadow-soft">
      <h3 className="text-sm font-semibold text-ink">Attack Graph</h3>
      <p className="mt-1 text-sm text-slate-500">Node-edge snapshot of discovered assets and relationships.</p>

      {nodes.length === 0 && edges.length === 0 ? (
        <div className="mt-4 rounded-xl border border-dashed border-line bg-slate-50 p-6 text-center text-sm text-slate-500">
          Graph data is not available for this scan.
        </div>
      ) : (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <article className="rounded-xl border border-line bg-white p-4">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Nodes</h4>
            <ul className="mt-3 space-y-2 text-sm text-slate-700">
              {nodes.map((node, index) => (
                <li key={`${node.id || node.label || "node"}-${index}`} className="rounded-lg border border-line px-3 py-2">
                  <span className="font-medium text-slate-900">{node.label || node.id || `Node ${index + 1}`}</span>
                  {node.type ? <span className="ml-2 text-xs text-slate-500">({node.type})</span> : null}
                </li>
              ))}
            </ul>
          </article>

          <article className="rounded-xl border border-line bg-white p-4">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Edges</h4>
            <ul className="mt-3 space-y-2 text-sm text-slate-700">
              {edges.map((edge, index) => (
                <li key={`${edge.source || "s"}-${edge.target || "t"}-${index}`} className="rounded-lg border border-line px-3 py-2">
                  <span className="font-medium text-slate-900">{edge.source || "Unknown"}</span>
                  <span className="mx-2 text-slate-400">→</span>
                  <span className="font-medium text-slate-900">{edge.target || "Unknown"}</span>
                  {edge.label ? <span className="ml-2 text-xs text-slate-500">{edge.label}</span> : null}
                </li>
              ))}
            </ul>
          </article>
        </div>
      )}
    </section>
  );
}

export default GraphPanel;
