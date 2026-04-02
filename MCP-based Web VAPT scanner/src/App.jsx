import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API_BASE = "http://127.0.0.1:8000";
const API_KEY  = import.meta.env.VITE_API_KEY || "vapt-prod-key-9f8d7a6b123";

async function apiFetch(path, opts = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...opts,
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY, ...(opts.headers || {}) },
    });
  } catch { throw new Error("Cannot reach backend at http://127.0.0.1:8000"); }
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { body = text; }
  if (!res.ok) throw new Error(`${res.status}: ${body?.detail || body || "Request failed"}`);
  return body;
}

const api = {
  start:   (t)  => apiFetch("/api/v1/scan/start", { method: "POST", body: JSON.stringify({ target: t, requested_tools: ["nmap","sqlmap","zap"] }) }),
  status:  (id) => apiFetch(`/api/v1/scan/status/${id}`),
  results: (id) => apiFetch(`/api/v1/scan/results/${id}`),
  report:  (id) => apiFetch(`/api/v1/scan/report/${id}`),
  graph:   (id) => apiFetch(`/api/v1/scan/graph/${id}`),
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function normStatus(v) {
  const s = String(v || "").toLowerCase();
  if (/complet|done|success|finish/.test(s)) return "completed";
  if (/fail|error|abort/.test(s))            return "error";
  if (/run|progress|active|queue/.test(s))   return "running";
  return "pending";
}

// ─── COLOURS ──────────────────────────────────────────────────────────────────
const SEV_COLOR  = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22c55e", info:"#3b82f6" };
const NODE_COLOR = { vulnerability:"#ef4444", host:"#60a5fa", service:"#a78bfa", target:"#f97316", asset:"#f97316", endpoint:"#a78bfa", unknown:"#6b7280" };

// ─── D3 FORCE GRAPH ───────────────────────────────────────────────────────────
function ForceGraph({ nodes, edges, vulnMap }) {
  const svgRef  = useRef(null);
  const [d3, setD3] = useState(null);

  useEffect(() => {
    import("https://cdn.jsdelivr.net/npm/d3@7/+esm").then(setD3);
  }, []);

  useEffect(() => {
    if (!d3 || !svgRef.current || nodes.length === 0) return;

    const el = svgRef.current;
    const W  = el.clientWidth  || 800;
    const H  = el.clientHeight || 520;
    d3.select(el).selectAll("*").remove();

    const svg = d3.select(el).attr("viewBox", `0 0 ${W} ${H}`);
    const defs = svg.append("defs");

    // Arrow marker
    defs.append("marker").attr("id","arr").attr("viewBox","0 -5 10 10")
      .attr("refX",22).attr("refY",0).attr("markerWidth",5).attr("markerHeight",5).attr("orient","auto")
      .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#334155");

    // Glow
    const glow = defs.append("filter").attr("id","glow");
    glow.append("feGaussianBlur").attr("stdDeviation","3").attr("result","b");
    const fm = glow.append("feMerge");
    fm.append("feMergeNode").attr("in","b");
    fm.append("feMergeNode").attr("in","SourceGraphic");

    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.2,5]).on("zoom",(ev) => g.attr("transform",ev.transform)));

    const simNodes = nodes.map(n => ({ ...n }));
    const nodeById = new Map(simNodes.map(n => [n.id, n]));
    const simEdges = edges
      .filter(e => nodeById.has(String(e.source)) && nodeById.has(String(e.target)))
      .map(e => ({ ...e }));

    const getColor = (d) => {
      const v = vulnMap.get(d.id);
      if (v) return SEV_COLOR[v.severity] || SEV_COLOR.info;
      const t = (d.type || "unknown").toLowerCase();
      return NODE_COLOR[t] || NODE_COLOR.unknown;
    };

    const getR = (d) => {
      const t = (d.type || "").toLowerCase();
      if (t === "target" || t === "asset") return 26;
      if (t === "endpoint" || t === "service") return 18;
      return 15;
    };

    const getLetter = (d) => {
      const t = (d.type || "").toLowerCase();
      if (t === "target" || t === "asset") return "T";
      if (t === "endpoint" || t === "service") return "S";
      if (t === "vulnerability") return "V";
      if (t === "host") return "H";
      return "?";
    };

    const sim = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink(simEdges).id(d => d.id).distance(d => {
        const s = (d.source.type || "").toLowerCase(), t = (d.target.type || "").toLowerCase();
        if (s === "target" || s === "asset") return 160;
        if (s === "host") return 130;
        return 100;
      }).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-350))
      .force("center",    d3.forceCenter(W/2, H/2))
      .force("collision", d3.forceCollide(d => getR(d) + 10));

    // Edge type → stroke style
    const edgeStroke = { dependency:"#1e293b", privilege_escalation:"#7c3aed44", lateral_movement:"#0284c744" };

    const link = g.append("g").selectAll("line").data(simEdges).enter().append("line")
      .attr("stroke", d => {
        const ed = d.data || {};
        return edgeStroke[ed.type] || "#1e293b";
      })
      .attr("stroke-width", d => {
        const t = (d.data?.type || "");
        return t === "dependency" ? 2 : 1.5;
      })
      .attr("stroke-dasharray", d => {
        const t = (d.data?.type || "");
        if (t === "privilege_escalation") return "6 3";
        if (t === "lateral_movement")     return "3 3";
        return null;
      })
      .attr("marker-end","url(#arr)");

    const node = g.append("g").selectAll("g").data(simNodes).enter().append("g")
      .attr("cursor","grab")
      .call(d3.drag()
        .on("start",(ev,d) => { if(!ev.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
        .on("drag", (ev,d) => { d.fx=ev.x; d.fy=ev.y; })
        .on("end",  (ev,d) => { if(!ev.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

    // Pulse ring for target
    node.append("circle")
      .attr("r",  d => getR(d) + 8)
      .attr("fill",   d => getColor(d) + "18")
      .attr("stroke", d => getColor(d) + "44")
      .attr("stroke-width", 1);

    node.append("circle")
      .attr("r",       getR)
      .attr("fill",    d => getColor(d) + "25")
      .attr("stroke",  getColor)
      .attr("stroke-width", 2)
      .attr("filter",  d => (d.type === "target" || d.type === "asset") ? "url(#glow)" : null);

    node.append("text")
      .attr("text-anchor","middle").attr("dominant-baseline","central")
      .attr("font-size", d => getR(d) * 0.75)
      .attr("font-weight","700")
      .attr("fill", getColor)
      .text(getLetter);

    node.append("text")
      .attr("text-anchor","middle")
      .attr("y",  d => getR(d) + 13)
      .attr("font-size",9).attr("fill","#64748b")
      .text(d => { const l = d.label||d.id||""; return l.length>22 ? l.slice(0,22)+"…" : l; });

    // Tooltip
    const tip = document.createElement("div");
    Object.assign(tip.style, {
      position:"fixed", background:"#0f172a", border:"1px solid #1e293b",
      color:"#e2e8f0", fontSize:"11px", padding:"8px 12px", borderRadius:"8px",
      pointerEvents:"none", opacity:"0", zIndex:"9999", maxWidth:"250px", transition:"opacity .12s",
      lineHeight:"1.5",
    });
    document.body.appendChild(tip);

    node.on("mouseenter",(ev,d) => {
      const v = vulnMap.get(d.id);
      const c = getColor(d);
      let html = `<strong style="color:${c}">${d.label||d.id}</strong><br/><span style="color:#475569">type: ${d.type}</span>`;
      if (v) {
        html += `<br/><span style="color:${SEV_COLOR[v.severity]||c}">severity: ${v.severity}</span>`;
        if (v.description) html += `<br/><span style="color:#64748b;font-size:10px">${v.description.slice(0,100)}</span>`;
      }
      tip.innerHTML = html; tip.style.opacity="1";
      tip.style.left=`${ev.clientX+14}px`; tip.style.top=`${ev.clientY-8}px`;
    }).on("mousemove", ev => {
      tip.style.left=`${ev.clientX+14}px`; tip.style.top=`${ev.clientY-8}px`;
    }).on("mouseleave", () => { tip.style.opacity="0"; });

    sim.on("tick", () => {
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
          .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      node.attr("transform",d=>`translate(${d.x},${d.y})`);
    });

    return () => { sim.stop(); tip.remove(); };
  }, [d3, nodes, edges, vulnMap]);

  if (!d3)             return <div className="flex h-full items-center justify-center text-slate-700 text-xs font-mono animate-pulse">Loading D3…</div>;
  if (nodes.length===0) return <div className="flex h-full items-center justify-center text-slate-600 text-sm">No graph data</div>;
  return <svg ref={svgRef} className="w-full h-full" />;
}

// ─── RADAR CHART (SVG, no lib) ────────────────────────────────────────────────
function RadarChart({ data, size = 260 }) {
  // data: [{ label, value (0–100), color }]
  const cx = size / 2, cy = size / 2;
  const r  = size * 0.36;
  const levels = [20, 40, 60, 80, 100];
  const n = data.length;
  if (n === 0) return null;

  const angle = (i) => (Math.PI * 2 * i) / n - Math.PI / 2;
  const pt    = (i, pct) => {
    const a = angle(i), rv = (pct / 100) * r;
    return [cx + rv * Math.cos(a), cy + rv * Math.sin(a)];
  };

  const polygon = data.map((d, i) => pt(i, d.value)).map(([x,y]) => `${x},${y}`).join(" ");

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Grid rings */}
      {levels.map(l => (
        <polygon key={l}
          points={Array.from({length:n},(_,i) => pt(i,l)).map(([x,y])=>`${x},${y}`).join(" ")}
          fill="none" stroke="#1e293b" strokeWidth="1"
        />
      ))}
      {/* Axis lines */}
      {data.map((_, i) => {
        const [x,y] = pt(i, 100);
        return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="#1e293b" strokeWidth="1" />;
      })}
      {/* Data polygon */}
      <polygon points={polygon} fill="#f97316" fillOpacity="0.18" stroke="#f97316" strokeWidth="2" />
      {/* Data points */}
      {data.map((d,i) => {
        const [x,y] = pt(i, d.value);
        return <circle key={i} cx={x} cy={y} r="4" fill={d.color || "#f97316"} />;
      })}
      {/* Labels */}
      {data.map((d,i) => {
        const [x,y] = pt(i, 118);
        const anchor = x < cx - 4 ? "end" : x > cx + 4 ? "start" : "middle";
        return (
          <text key={i} x={x} y={y} textAnchor={anchor} fontSize="11" fill="#94a3b8" fontWeight="600">
            {d.label}
          </text>
        );
      })}
    </svg>
  );
}

// ─── BAR CHART (SVG, no lib) ──────────────────────────────────────────────────
function BarChart({ data, width = 340, height = 180 }) {
  // data: [{ label, value, color }]
  if (!data || data.length === 0) return null;
  const pad  = { top: 10, right: 10, bottom: 34, left: 36 };
  const iW   = width  - pad.left - pad.right;
  const iH   = height - pad.top  - pad.bottom;
  const max  = Math.max(...data.map(d => d.value), 1);
  const bW   = iW / data.length;
  const gap  = bW * 0.25;

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      {/* Y-axis ticks */}
      {[0,0.25,0.5,0.75,1].map(t => {
        const yy = pad.top + iH * (1 - t);
        const val = Math.round(max * t);
        return (
          <g key={t}>
            <line x1={pad.left} y1={yy} x2={pad.left + iW} y2={yy} stroke="#1e293b" strokeWidth="1" />
            <text x={pad.left - 6} y={yy + 4} textAnchor="end" fontSize="9" fill="#475569">{val}</text>
          </g>
        );
      })}
      {/* Bars */}
      {data.map((d, i) => {
        const bH  = (d.value / max) * iH;
        const x   = pad.left + i * bW + gap / 2;
        const y   = pad.top + iH - bH;
        return (
          <g key={i}>
            <rect x={x} y={y} width={bW - gap} height={bH}
              fill={d.color || "#f97316"} fillOpacity="0.85" rx="3" />
            {d.value > 0 && (
              <text x={x + (bW - gap)/2} y={y - 4} textAnchor="middle" fontSize="9" fill={d.color || "#f97316"} fontWeight="700">
                {d.value}
              </text>
            )}
            <text x={x + (bW-gap)/2} y={pad.top+iH+14} textAnchor="middle" fontSize="9" fill="#64748b">
              {d.label.length > 7 ? d.label.slice(0,6)+"…" : d.label}
            </text>
          </g>
        );
      })}
      {/* Axes */}
      <line x1={pad.left} y1={pad.top} x2={pad.left} y2={pad.top+iH} stroke="#334155" strokeWidth="1.5" />
      <line x1={pad.left} y1={pad.top+iH} x2={pad.left+iW} y2={pad.top+iH} stroke="#334155" strokeWidth="1.5" />
    </svg>
  );
}

// ─── MINI COMPONENTS ──────────────────────────────────────────────────────────
function SevBadge({ sev }) {
  const c = {
    critical:"bg-red-500/20 text-red-400 ring-red-500/40",
    high:    "bg-orange-500/20 text-orange-400 ring-orange-500/40",
    medium:  "bg-yellow-500/20 text-yellow-400 ring-yellow-500/40",
    low:     "bg-green-500/20 text-green-400 ring-green-500/40",
    info:    "bg-blue-500/20 text-blue-400 ring-blue-500/40",
  }[sev] || "bg-slate-700 text-slate-400 ring-slate-600";
  return <span className={`inline-flex items-center px-2 py-0.5 text-[10px] font-bold rounded ring-1 uppercase tracking-wide ${c}`}>{sev}</span>;
}

function ToolPill({ name, status }) {
  const s = normStatus(status);
  const c = {
    completed: "bg-emerald-500/10 ring-emerald-500/30 text-emerald-400",
    running:   "bg-amber-500/10 ring-amber-500/30 text-amber-400",
    error:     "bg-red-500/10 ring-red-500/30 text-red-400",
    pending:   "bg-slate-800 ring-slate-700 text-slate-500",
  }[s] || "bg-slate-800 ring-slate-700 text-slate-500";
  const dot = { completed:"bg-emerald-400", running:"bg-amber-400 animate-pulse", error:"bg-red-400", pending:"bg-slate-600" }[s] || "bg-slate-600";
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ring-1 ${c}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dot}`} />
      <span className="text-xs font-mono font-semibold">{name}</span>
    </div>
  );
}

// Fixed StatCard — no overlap, truncation handled
function StatCard({ label, value, color }) {
  return (
    <div className="rounded-xl bg-slate-800/60 ring-1 ring-slate-700/80 p-3 flex flex-col gap-1 min-w-0">
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest truncate">{label}</p>
      <p className={`text-xl font-bold tabular-nums leading-tight ${color || "text-white"}`}>
        {value ?? "—"}
      </p>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [target,      setTarget]      = useState("");
  const [scanId,      setScanId]      = useState("");
  const [phase,       setPhase]       = useState("idle");
  const [error,       setError]       = useState("");
  const [toolStatus,  setToolStatus]  = useState({});
  const [pollCount,   setPollCount]   = useState(0);
  const [startedAt,   setStartedAt]   = useState(null);
  const [elapsed,     setElapsed]     = useState(0);
  const [vulns,       setVulns]       = useState([]);
  const [reportData,  setReportData]  = useState(null);
  const [graphNodes,  setGraphNodes]  = useState([]);
  const [graphEdges,  setGraphEdges]  = useState([]);
  const [activeTab,   setActiveTab]   = useState("findings");
  const [logLines,    setLogLines]    = useState([]);
  const [sevFilter,   setSevFilter]   = useState("all");

  const pollRef  = useRef(null);
  const busyRef  = useRef(false);
  const logEnd   = useRef(null);

  const addLog = useCallback((msg, type="info") => {
    const t = new Date().toLocaleTimeString();
    setLogLines(prev => [...prev.slice(-120), { msg, type, t }]);
  }, []);

  useEffect(() => { logEnd.current?.scrollIntoView({ behavior:"smooth" }); }, [logLines]);

  useEffect(() => {
    if (phase !== "running" || !startedAt) return;
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    return () => clearInterval(id);
  }, [phase, startedAt]);

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  const fetchArtifacts = useCallback(async (id) => {
    addLog("Fetching results from backend…");
    for (let i = 0; i < 10; i++) {
      try {
        const [res, rep, gr] = await Promise.all([api.results(id), api.report(id), api.graph(id)]);
        setVulns(res?.vulnerabilities || []);
        setReportData(rep?.report || rep || {});
        setGraphNodes(gr?.nodes || []);
        setGraphEdges(gr?.edges || []);
        addLog(`✓ ${res?.vulnerabilities?.length||0} findings · ${gr?.nodes?.length||0} graph nodes`, "success");
        setPhase("completed");
        setActiveTab("findings");
        return;
      } catch (e) {
        addLog(`Attempt ${i+1} failed: ${e.message}`, "warn");
        await sleep(2000);
      }
    }
    setError("Could not load results after retries.");
    setPhase("error");
  }, [addLog]);

  const pollOnce = useCallback(async (id) => {
    if (busyRef.current) return;
    busyRef.current = true;
    try {
      const st      = await api.status(id);
      const overall = normStatus(st?.scan_status || st?.orchestrator_state || st?.status);
      const tools   = st?.tool_status || st?.tools || {};
      setToolStatus(tools);
      setPollCount(c => c + 1);
      if (overall === "completed" || overall === "error") {
        stopPoll();
        addLog(`Scan ${overall === "completed" ? "✓ completed" : "✗ errored"}`, overall === "completed" ? "success" : "warn");
        await fetchArtifacts(id);
      }
    } catch (e) {
      stopPoll(); setPhase("error"); setError(e.message); addLog(e.message, "error");
    } finally { busyRef.current = false; }
  }, [addLog, fetchArtifacts, stopPoll]);

  const handleStart = async () => {
    const t = target.trim();
    if (!t) { setError("Enter a target URL"); return; }
    try { new URL(t); } catch { setError("Invalid URL — include http:// or https://"); return; }

    stopPoll();
    setVulns([]); setReportData(null); setGraphNodes([]); setGraphEdges([]);
    setToolStatus({}); setPollCount(0); setError("");
    setLogLines([{ msg:`Starting scan → ${t}`, type:"info", t:new Date().toLocaleTimeString() }]);
    setPhase("running"); setStartedAt(Date.now()); setElapsed(0);

    try {
      const data = await api.start(t);
      const id   = data?.scan_id || data?.id || "";
      if (!id) throw new Error("No scan_id returned");
      setScanId(id);
      addLog(`Scan ID: ${id.slice(0,8)}…`, "success");
      await pollOnce(id);
      pollRef.current = setInterval(() => pollOnce(id), 4000);
    } catch (e) {
      stopPoll(); setPhase("error"); setError(e.message); addLog(e.message, "error");
    }
  };

  // ── derived ─────────────────────────────────────────────────────────────────
  const sevCounts = useMemo(() => {
    const c = { critical:0, high:0, medium:0, low:0, info:0 };
    vulns.forEach(v => { if (c[v.severity] !== undefined) c[v.severity]++; });
    return c;
  }, [vulns]);

  const vulnMap = useMemo(() => {
    const m = new Map();
    vulns.forEach(v => m.set(v.id, v));
    return m;
  }, [vulns]);

  const filteredVulns = useMemo(() =>
    sevFilter === "all" ? vulns : vulns.filter(v => v.severity === sevFilter),
    [vulns, sevFilter]);

  const toolEntries = useMemo(() => {
    const keys = Object.keys(toolStatus).length ? Object.keys(toolStatus) : ["nmap","sqlmap","zap"];
    return keys.map(k => ({ name:k.toUpperCase(), status:toolStatus[k] || "pending" }));
  }, [toolStatus]);

  // Bar chart data — vuln types from findings
  const barData = useMemo(() => {
    const counts = {};
    vulns.forEach(v => { counts[v.type] = (counts[v.type]||0) + 1; });
    return Object.entries(counts)
      .sort((a,b) => b[1]-a[1])
      .slice(0,8)
      .map(([label, value]) => ({ label, value, color: SEV_COLOR[vulns.find(v=>v.type===label)?.severity] || "#f97316" }));
  }, [vulns]);

  // Radar chart data — severity distribution as % of max
  const radarData = useMemo(() => {
    const total = Math.max(vulns.length, 1);
    return [
      { label:"Critical", value: Math.round((sevCounts.critical/total)*100), color:SEV_COLOR.critical },
      { label:"High",     value: Math.round((sevCounts.high/total)*100),     color:SEV_COLOR.high },
      { label:"Medium",   value: Math.round((sevCounts.medium/total)*100),   color:SEV_COLOR.medium },
      { label:"Low",      value: Math.round((sevCounts.low/total)*100),      color:SEV_COLOR.low },
      { label:"Info",     value: Math.round((sevCounts.info/total)*100),     color:SEV_COLOR.info },
    ];
  }, [sevCounts, vulns.length]);

  const riskScore   = reportData?.risk_score;
  const execSummary = reportData?.executive_summary;
  const techSummary = reportData?.technical_summary;
  const remPlan     = reportData?.remediation_plan || [];
  const elapsedStr  = `${Math.floor(elapsed/60)}m ${String(elapsed%60).padStart(2,"0")}s`;

  const TABS = [
    { id:"findings",  label:"Findings",      count: vulns.length },
    { id:"charts",    label:"Charts"                              },
    { id:"graph",     label:"Attack Graph",  count: graphNodes.length },
    { id:"report",    label:"Report"                             },
    { id:"log",       label:"Live Log",      count: logLines.length },
  ];

  return (
    <div className="min-h-screen bg-[#070d18] text-slate-100" style={{fontFamily:"'Inter',system-ui,sans-serif"}}>

      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#0a1220]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-5 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-red-600 to-orange-500 flex items-center justify-center shadow-lg shadow-red-900/40 flex-shrink-0">
              <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
              </svg>
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-sm leading-tight">VAPT Console</span>
              <span className="text-[10px] text-slate-600 font-mono leading-tight hidden sm:block">Nmap · SQLMap · OWASP ZAP · AI</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {phase === "running" && (
              <span className="flex items-center gap-1.5 text-xs font-mono text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                {elapsedStr} · {pollCount} polls
              </span>
            )}
            {scanId && <span className="text-xs text-slate-600 font-mono hidden md:block">{scanId.slice(0,8)}…</span>}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-5 py-5 space-y-4">

        {/* ── SCAN INPUT ── */}
        <div className="rounded-2xl bg-[#0c1524] ring-1 ring-slate-800 p-5">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-3">Target URL</p>
          <div className="flex gap-3">
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && phase !== "running" && handleStart()}
              placeholder="https://example.com"
              disabled={phase === "running"}
              className="flex-1 min-w-0 bg-slate-800/70 border border-slate-700 rounded-xl px-4 py-2.5 text-sm font-mono text-slate-100 placeholder-slate-600 outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-600/50 disabled:opacity-40 transition"
            />
            <button
              onClick={handleStart}
              disabled={phase === "running"}
              className="flex-shrink-0 px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-r from-red-600 to-orange-500 text-white shadow-lg shadow-red-900/30 hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {phase === "running" ? "Scanning…" : "▶ Scan"}
            </button>
          </div>

          {(phase === "running" || phase === "completed") && (
            <div className="mt-3 flex flex-wrap gap-2">
              {toolEntries.map(t => <ToolPill key={t.name} name={t.name} status={t.status}/>)}
            </div>
          )}
          {error && (
            <div className="mt-3 rounded-xl bg-red-900/20 ring-1 ring-red-800/60 px-4 py-2.5 text-sm text-red-400">{error}</div>
          )}
        </div>

        {/* ── STAT CARDS ── */}
        {phase === "completed" && (
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            <StatCard label="Risk Score" value={typeof riskScore === "number" ? riskScore.toFixed(2) : riskScore} color="text-orange-400"/>
            <StatCard label="Critical"   value={sevCounts.critical} color="text-red-400"/>
            <StatCard label="High"       value={sevCounts.high}     color="text-orange-400"/>
            <StatCard label="Medium"     value={sevCounts.medium}   color="text-yellow-400"/>
            <StatCard label="Low"        value={sevCounts.low}      color="text-green-400"/>
            <StatCard label="Info"       value={sevCounts.info}     color="text-blue-400"/>
          </div>
        )}

        {/* ── TAB PANEL ── */}
        {(phase === "completed" || phase === "running") && (
          <div className="rounded-2xl bg-[#0c1524] ring-1 ring-slate-800 overflow-hidden">
            <div className="flex border-b border-slate-800 overflow-x-auto">
              {TABS.map(tab => (
                <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-5 py-3.5 text-sm font-medium whitespace-nowrap transition-colors ${activeTab===tab.id ? "text-orange-400 border-b-2 border-orange-500 bg-orange-500/5" : "text-slate-500 hover:text-slate-300"}`}
                >
                  {tab.label}
                  {tab.count !== undefined && tab.count > 0 && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400">{tab.count}</span>
                  )}
                </button>
              ))}
            </div>

            <div className="p-5">

              {/* ── FINDINGS ── */}
              {activeTab === "findings" && (
                <div>
                  {vulns.length > 0 && (
                    <div className="flex flex-wrap gap-2 mb-4">
                      {["all","critical","high","medium","low","info"].map(s => (
                        <button key={s} onClick={() => setSevFilter(s)}
                          className={`px-3 py-1 rounded-full text-xs font-semibold transition-all ${sevFilter===s ? "bg-orange-500 text-white shadow-md" : "bg-slate-800 text-slate-400 hover:bg-slate-700"}`}
                        >
                          {s==="all" ? `All (${vulns.length})` : `${s} (${sevCounts[s]})`}
                        </button>
                      ))}
                    </div>
                  )}
                  {filteredVulns.length === 0
                    ? <p className="text-slate-600 text-sm py-8 text-center">No findings yet.</p>
                    : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="text-left text-[10px] text-slate-600 uppercase tracking-widest border-b border-slate-800">
                              <th className="pb-2.5 pr-4 font-semibold">Type</th>
                              <th className="pb-2.5 pr-4 font-semibold">Severity</th>
                              <th className="pb-2.5 pr-4 font-semibold">Location</th>
                              <th className="pb-2.5 pr-4 font-semibold">Tool</th>
                              <th className="pb-2.5 font-semibold">Description</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/50">
                            {filteredVulns.map(v => (
                              <tr key={v.id} className="hover:bg-slate-800/30 transition-colors">
                                <td className="py-3 pr-4 font-mono text-[11px] text-slate-400">{v.type}</td>
                                <td className="py-3 pr-4"><SevBadge sev={v.severity}/></td>
                                <td className="py-3 pr-4 font-mono text-[11px] text-slate-500 max-w-[140px] truncate">{v.location||"—"}</td>
                                <td className="py-3 pr-4 text-xs text-slate-600">{v.source_tool}</td>
                                <td className="py-3 text-xs text-slate-500 max-w-xs truncate">{v.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )
                  }
                </div>
              )}

              {/* ── CHARTS ── */}
              {activeTab === "charts" && (
                <div>
                  {vulns.length === 0
                    ? <p className="text-slate-600 text-sm py-8 text-center">No data yet.</p>
                    : (
                      <div className="grid gap-6 lg:grid-cols-2">
                        {/* Radar */}
                        <div className="rounded-xl bg-slate-900/60 ring-1 ring-slate-700/60 p-5">
                          <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">Severity Distribution</p>
                          <p className="text-[10px] text-slate-600 mb-4">Proportion of findings per severity level</p>
                          <div className="flex justify-center">
                            <RadarChart data={radarData} size={240}/>
                          </div>
                          <div className="mt-3 flex flex-wrap justify-center gap-3">
                            {radarData.map(d => (
                              <span key={d.label} className="flex items-center gap-1.5 text-[10px] text-slate-500">
                                <span className="w-2 h-2 rounded-full" style={{background:d.color}}/>
                                {d.label}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Bar */}
                        <div className="rounded-xl bg-slate-900/60 ring-1 ring-slate-700/60 p-5">
                          <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">Vulnerability Type Distribution</p>
                          <p className="text-[10px] text-slate-600 mb-4">Count of findings by type</p>
                          <div className="flex justify-center overflow-x-auto">
                            <BarChart data={barData} width={320} height={190}/>
                          </div>
                        </div>

                        {/* Severity count bar */}
                        <div className="rounded-xl bg-slate-900/60 ring-1 ring-slate-700/60 p-5 lg:col-span-2">
                          <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">Findings by Severity</p>
                          <p className="text-[10px] text-slate-600 mb-4">Raw count per severity level</p>
                          <div className="flex justify-center">
                            <BarChart
                              data={[
                                { label:"Critical", value:sevCounts.critical, color:SEV_COLOR.critical },
                                { label:"High",     value:sevCounts.high,     color:SEV_COLOR.high },
                                { label:"Medium",   value:sevCounts.medium,   color:SEV_COLOR.medium },
                                { label:"Low",      value:sevCounts.low,      color:SEV_COLOR.low },
                                { label:"Info",     value:sevCounts.info,     color:SEV_COLOR.info },
                              ]}
                              width={380} height={190}
                            />
                          </div>
                        </div>
                      </div>
                    )
                  }
                </div>
              )}

              {/* ── ATTACK GRAPH ── */}
              {activeTab === "graph" && (
                <div>
                  <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                    <div>
                      <h3 className="text-sm font-semibold text-slate-300">Interactive Attack Graph</h3>
                      <p className="text-[10px] text-slate-600 mt-0.5">
                        {graphNodes.length} nodes · {graphEdges.length} edges — drag to rearrange · scroll to zoom · hover for details
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                      {Object.entries(NODE_COLOR).slice(0,5).map(([k,c]) => (
                        <span key={k} className="flex items-center gap-1 text-[10px] text-slate-500">
                          <span className="w-2.5 h-2.5 rounded-full border-2 flex-shrink-0" style={{borderColor:c, background:c+"33"}}/>
                          {k}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-xl bg-slate-950 ring-1 ring-slate-800/60 overflow-hidden" style={{height:520}}>
                    <ForceGraph nodes={graphNodes} edges={graphEdges} vulnMap={vulnMap}/>
                  </div>

                  {/* Edge legend */}
                  <div className="mt-3 flex flex-wrap gap-4 text-[10px] text-slate-600">
                    <span className="flex items-center gap-1.5"><span className="w-6 border-t-2 border-slate-600"/>dependency</span>
                    <span className="flex items-center gap-1.5"><span className="w-6 border-t-2 border-purple-600 border-dashed"/>priv escalation</span>
                    <span className="flex items-center gap-1.5"><span className="w-6 border-t border-blue-600 border-dotted"/>lateral movement</span>
                  </div>

                  {/* Severity colours for vuln nodes */}
                  <div className="mt-2 flex flex-wrap gap-4">
                    {Object.entries(SEV_COLOR).map(([s,c]) => (
                      <span key={s} className="flex items-center gap-1 text-[10px] text-slate-500">
                        <span className="w-2.5 h-2.5 rounded-full border-2 flex-shrink-0" style={{borderColor:c, background:c+"33"}}/>
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ── REPORT ── */}
              {activeTab === "report" && (
                <div className="space-y-4">
                  {execSummary && (
                    <div className="rounded-xl bg-slate-800/40 ring-1 ring-slate-700/60 p-4">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Executive Summary</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{execSummary}</p>
                    </div>
                  )}
                  {techSummary && (
                    <div className="rounded-xl bg-slate-800/40 ring-1 ring-slate-700/60 p-4">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Technical Summary</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{techSummary}</p>
                    </div>
                  )}
                  {remPlan.length > 0 && (
                    <div className="rounded-xl bg-slate-800/40 ring-1 ring-slate-700/60 p-4">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Remediation Plan</p>
                      <div className="space-y-2">
                        {remPlan.map((item,i) => (
                          <div key={i} className="flex gap-3">
                            <span className="text-orange-500 font-bold text-sm flex-shrink-0">{i+1}.</span>
                            <p className="text-sm text-slate-300">{typeof item==="string" ? item : JSON.stringify(item)}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {!execSummary && !techSummary && remPlan.length===0 && (
                    <p className="text-slate-600 text-sm py-8 text-center">Report not available.</p>
                  )}
                </div>
              )}

              {/* ── LIVE LOG ── */}
              {activeTab === "log" && (
                <div className="bg-slate-950 rounded-xl ring-1 ring-slate-800 p-4 h-80 overflow-y-auto font-mono text-[11px]">
                  {logLines.length===0 && <p className="text-slate-700">Waiting…</p>}
                  {logLines.map((l,i) => {
                    const c = { info:"text-slate-400", success:"text-emerald-400", warn:"text-amber-400", error:"text-red-400" }[l.type]||"text-slate-400";
                    return (
                      <div key={i} className={`flex gap-2 py-0.5 ${c}`}>
                        <span className="text-slate-700 shrink-0 select-none">{l.t}</span>
                        <span>{l.msg}</span>
                      </div>
                    );
                  })}
                  <div ref={logEnd}/>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── IDLE ── */}
        {phase === "idle" && (
          <div className="rounded-2xl bg-[#0c1524]/60 ring-1 ring-slate-800 p-14 text-center">
            <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-red-600/20 to-orange-500/20 ring-1 ring-red-500/20 flex items-center justify-center mb-4">
              <svg className="w-8 h-8 text-orange-500" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
              </svg>
            </div>
            <h2 className="text-slate-300 font-semibold mb-1.5">Ready to Scan</h2>
            <p className="text-slate-600 text-sm max-w-sm mx-auto">Enter a real target URL. The backend will run Nmap, SQLMap, and OWASP ZAP and visualise results.</p>
            <div className="mt-5 flex flex-wrap gap-2 justify-center">
              {["Nmap port scan","SQLMap injection","ZAP spider","Force-directed attack graph","Radar + bar charts"].map(f => (
                <span key={f} className="px-3 py-1 rounded-full text-xs bg-slate-800/80 text-slate-500 ring-1 ring-slate-700">{f}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
