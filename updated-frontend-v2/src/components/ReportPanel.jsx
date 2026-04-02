function ReportPanel({ reportData }) {
  return (
    <section className="rounded-2xl border border-line bg-card p-4 shadow-soft">
      <h3 className="text-sm font-semibold text-ink">Structured Report</h3>
      <p className="mt-1 text-sm text-slate-500">Consolidated scan report from all enabled tools.</p>

      <div className="mt-4 overflow-x-auto rounded-xl border border-line bg-slate-50 p-4">
        <pre className="text-xs leading-relaxed text-slate-700">{JSON.stringify(reportData, null, 2)}</pre>
      </div>
    </section>
  );
}

export default ReportPanel;
