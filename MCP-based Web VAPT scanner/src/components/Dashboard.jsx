import { useMemo, useState } from "react";
import NmapTable from "./NmapTable";
import GraphPanel from "./GraphPanel";
import ReportPanel from "./ReportPanel";
import Tabs from "./Tabs";
import WebFindingsSection from "./WebFindingsSection";

function Overview({ model }) {
  return (
    <section className="grid gap-4 md:grid-cols-2">
      <article className="rounded-2xl border border-line bg-card p-4 shadow-soft">
        <h3 className="text-sm font-semibold text-ink">Target URL</h3>
        <p className="mt-2 text-sm text-slate-600">{model.target || "N/A"}</p>
      </article>

      <article className="rounded-2xl border border-line bg-card p-4 shadow-soft">
        <h3 className="text-sm font-semibold text-ink">Scan Duration</h3>
        <p className="mt-2 text-sm text-slate-600">{model.duration}</p>
      </article>

      <article className="rounded-2xl border border-line bg-card p-4 shadow-soft">
        <h3 className="text-sm font-semibold text-ink">Total Findings</h3>
        <p className="mt-2 text-sm text-slate-600">{model.totals.totalFindings}</p>
      </article>

      <article className="rounded-2xl border border-line bg-card p-4 shadow-soft">
        <h3 className="text-sm font-semibold text-ink">Summary</h3>
        <p className="mt-2 text-sm text-slate-600">{model.summaryText}</p>
      </article>
    </section>
  );
}

function Dashboard({ model }) {
  const [activeTab, setActiveTab] = useState("overview");

  const content = useMemo(() => {
    if (activeTab === "overview") {
      return <Overview model={model} />;
    }
    if (activeTab === "network") {
      return <NmapTable ports={model.ports} />;
    }
    if (activeTab === "web") {
      return <WebFindingsSection webFindings={model.webFindings} />;
    }
    if (activeTab === "graph") {
      return <GraphPanel graphData={model.graph} />;
    }
    return <ReportPanel reportData={model.report} />;
  }, [activeTab, model]);

  return (
    <section className="space-y-4">
      <Tabs activeTab={activeTab} onTabChange={setActiveTab} />
      <div className="animate-fade-in">{content}</div>
    </section>
  );
}

export default Dashboard;
