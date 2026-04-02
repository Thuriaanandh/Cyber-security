import { severityBadgeClass } from "../utils/scanTransformers";

function FindingsTable({ title, findings }) {
  return (
    <section className="overflow-hidden rounded-2xl border border-line bg-card shadow-soft">
      <div className="border-b border-line px-4 py-3">
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-line text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Vulnerability</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">URL</th>
              <th className="px-4 py-3">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line bg-white text-slate-700">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-slate-500">
                  No findings available.
                </td>
              </tr>
            ) : (
              findings.map((finding, index) => (
                <tr key={`${finding.vulnerability}-${index}`}>
                  <td className="px-4 py-3 font-medium text-slate-900">{finding.vulnerability}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full px-2 py-1 text-xs font-medium capitalize ${severityBadgeClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="max-w-xs truncate px-4 py-3" title={finding.url}>
                    {finding.url}
                  </td>
                  <td className="max-w-md px-4 py-3">{finding.description}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function WebFindingsSection({ webFindings }) {
  const combinedFindings = [...webFindings.sqlmapFindings, ...webFindings.zapFindings];

  return (
    <div className="space-y-4">
      <FindingsTable title="Web Findings (SQLMap + ZAP Combined)" findings={combinedFindings} />
      <FindingsTable title="SQLMap Findings" findings={webFindings.sqlmapFindings} />
      <FindingsTable title="ZAP Findings" findings={webFindings.zapFindings} />
    </div>
  );
}

export default WebFindingsSection;
