function Tabs({ activeTab, onTabChange }) {
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "network", label: "Network (Nmap)" },
    { id: "web", label: "Web (SQLMap + ZAP)" },
    { id: "graph", label: "Graph" },
    { id: "report", label: "Report" }
  ];

  return (
    <div className="flex flex-wrap gap-2 rounded-2xl border border-line bg-card p-2 shadow-soft">
      {tabs.map((tab) => {
        const active = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            className={`rounded-xl px-4 py-2 text-sm font-medium transition ${
              active ? "bg-slate-900 text-white shadow-sm" : "bg-white text-slate-600 hover:bg-slate-100"
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

export default Tabs;
