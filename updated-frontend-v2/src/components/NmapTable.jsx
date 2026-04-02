function NmapTable({ ports }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-card shadow-soft">
      <div className="border-b border-line px-4 py-3">
        <h3 className="text-sm font-semibold text-ink">Nmap Results</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-line text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Port</th>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line bg-white text-slate-700">
            {ports.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-4 py-6 text-center text-slate-500">
                  No open port data available.
                </td>
              </tr>
            ) : (
              ports.map((port, index) => (
                <tr key={`${port.port}-${index}`}>
                  <td className="px-4 py-3 font-medium text-slate-900">{port.port}</td>
                  <td className="px-4 py-3">{port.service}</td>
                  <td className="px-4 py-3">{port.state}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default NmapTable;
