function Spinner() {
  return (
    <span
      className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-slate-700"
      aria-hidden="true"
    />
  );
}

function ProgressBar() {
  return (
    <div className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-slate-200">
      <div className="h-full w-1/3 animate-[pulse_1.2s_ease-in-out_infinite] rounded-full bg-slate-700" />
    </div>
  );
}

function StatusPill({ status }) {
  const normalized = status?.toLowerCase() || "idle";

  const mapping = {
    idle: "bg-slate-100 text-slate-700",
    running: "bg-blue-100 text-blue-700",
    completed: "bg-emerald-100 text-emerald-700",
    failed: "bg-red-100 text-red-700",
    error: "bg-red-100 text-red-700"
  };

  const classes = mapping[normalized] || mapping.idle;

  return <span className={`rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${classes}`}>{normalized}</span>;
}

function ToolPill({ tool }) {
  const colorByState = {
    pending: "bg-slate-100 text-slate-600",
    running: "bg-blue-100 text-blue-700",
    completed: "bg-emerald-100 text-emerald-700",
    failed: "bg-red-100 text-red-700"
  };

  const stateClass = colorByState[tool.status] || colorByState.pending;
  return (
    <span className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${stateClass}`}>
      {tool.label}: {tool.status}
    </span>
  );
}

function StatusBar({ status, scanId, isScanning, isFinalizing, toolProgress = [], elapsedSeconds = 0 }) {
  const showProgress = isScanning || isFinalizing;
  const statusMessage = isFinalizing
    ? "Scan completed. Fetching consolidated results, report, and graph."
    : isScanning
      ? "Scan in progress. Polling status every 3 seconds."
      : "Ready to start a new scan.";

  return (
    <section className="rounded-2xl border border-line bg-card p-4 shadow-soft">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <StatusPill status={status} />
            {showProgress ? <Spinner /> : null}
            <p className="text-sm text-slate-600">{statusMessage}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {toolProgress.map((tool) => (
              <ToolPill key={tool.id} tool={tool} />
            ))}
            {(isScanning || isFinalizing || status === "completed") && elapsedSeconds > 0 ? (
              <span className="text-xs text-slate-500">Elapsed: {elapsedSeconds}s</span>
            ) : null}
          </div>
          {showProgress ? <ProgressBar /> : null}
        </div>
        <p className="text-xs text-slate-500">Scan ID: {scanId || "N/A"}</p>
      </div>
    </section>
  );
}

export default StatusBar;
