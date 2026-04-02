function HeaderBar({ target, onTargetChange, onStartScan, isScanning }) {
  return (
    <header className="rounded-2xl border border-line bg-card p-5 shadow-panel">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">MCP VAPT Scanner</h1>
          <p className="mt-1 text-sm text-slate-500">Launch automated Nmap, SQLMap, and ZAP scans from one workflow.</p>
        </div>

        <div className="flex w-full flex-col gap-3 sm:flex-row lg:max-w-3xl">
          <input
            type="url"
            value={target}
            onChange={(event) => onTargetChange(event.target.value)}
            placeholder="https://target.example.com"
            className="h-11 w-full rounded-xl border border-line bg-white px-4 text-sm outline-none transition focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
          />
          <button
            type="button"
            onClick={onStartScan}
            disabled={isScanning || !target.trim()}
            className="h-11 min-w-36 rounded-xl bg-slate-900 px-6 text-sm font-medium text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-400"
          >
            {isScanning ? "Scanning..." : "Start Scan"}
          </button>
        </div>
      </div>
    </header>
  );
}

export default HeaderBar;
