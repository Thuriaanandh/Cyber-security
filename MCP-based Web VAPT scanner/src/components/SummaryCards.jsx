const cardConfig = [
  { key: "totalFindings", label: "Total Vulnerabilities", color: "text-slate-900" },
  { key: "high", label: "High", color: "text-red-600" },
  { key: "medium", label: "Medium", color: "text-orange-600" },
  { key: "low", label: "Low", color: "text-yellow-600" },
  { key: "openPorts", label: "Open Ports", color: "text-slate-900" },
  { key: "riskScore", label: "Risk Score", color: "text-blue-600" }
];

function SummaryCards({ totals }) {
  return (
    <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {cardConfig.map((card) => (
        <article key={card.key} className="rounded-2xl border border-line bg-card p-4 shadow-soft transition hover:translate-y-[-1px]">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{card.label}</p>
          <p className={`mt-2 text-2xl font-semibold ${card.color}`}>{totals?.[card.key] ?? 0}</p>
        </article>
      ))}
    </section>
  );
}

export default SummaryCards;
