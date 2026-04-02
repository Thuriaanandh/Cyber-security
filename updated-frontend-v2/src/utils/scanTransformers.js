const SEVERITY_ORDER = ["high", "medium", "low", "info"];

function asArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value == null) {
    return [];
  }
  return [value];
}

function normalizeSeverity(rawSeverity) {
  if (!rawSeverity) {
    return "info";
  }
  const value = String(rawSeverity).toLowerCase();
  if (value.includes("high") || value.includes("critical")) {
    return "high";
  }
  if (value.includes("medium") || value.includes("moderate")) {
    return "medium";
  }
  if (value.includes("low")) {
    return "low";
  }
  return "info";
}

function findCandidateArrays(payload, preferredKeys) {
  if (!payload || typeof payload !== "object") {
    return [];
  }

  const arrays = [];

  for (const key of preferredKeys) {
    if (Array.isArray(payload[key])) {
      arrays.push(payload[key]);
    }
  }

  for (const [key, value] of Object.entries(payload)) {
    if (arrays.includes(value)) {
      continue;
    }
    if (Array.isArray(value) && key.toLowerCase() !== "requested_tools") {
      arrays.push(value);
    }
  }

  return arrays;
}

function extractPortRows(resultsPayload) {
  const nmapData =
    resultsPayload?.nmap ||
    resultsPayload?.tools?.nmap ||
    resultsPayload?.results?.nmap ||
    resultsPayload?.data?.nmap ||
    {};

  const candidates = [
    ...findCandidateArrays(nmapData, ["open_ports", "ports", "results"]),
    ...findCandidateArrays(resultsPayload, ["open_ports", "ports"])
  ];

  const rows = [];

  for (const candidate of candidates) {
    for (const item of asArray(candidate)) {
      if (item && typeof item === "object") {
        const port = item.port || item.port_number || item.number || item.id;
        const service =
          item.service ||
          item.name ||
          item.protocol ||
          item.product ||
          item.banner ||
          "Unknown";
        const state = item.state || item.status || "open";

        if (port != null) {
          rows.push({
            port: String(port),
            service: String(service),
            state: String(state)
          });
        }
      }
    }
  }

  const unique = new Map();
  for (const row of rows) {
    unique.set(`${row.port}-${row.service}-${row.state}`, row);
  }

  return Array.from(unique.values());
}

function extractFindingRows(toolPayload, sourceName) {
  const candidates = findCandidateArrays(toolPayload, [
    "findings",
    "vulnerabilities",
    "issues",
    "alerts",
    "results"
  ]);

  const findings = [];

  for (const candidate of candidates) {
    for (const item of asArray(candidate)) {
      if (!item || typeof item !== "object") {
        continue;
      }

      findings.push({
        source: sourceName,
        vulnerability:
          item.vulnerability ||
          item.title ||
          item.name ||
          item.type ||
          "Unlabeled finding",
        severity: normalizeSeverity(item.severity || item.risk || item.level),
        url: item.url || item.endpoint || item.path || "N/A",
        description: item.description || item.detail || item.evidence || "No description provided"
      });
    }
  }

  return findings;
}

function extractWebFindings(resultsPayload) {
  const sqlmapData =
    resultsPayload?.sqlmap ||
    resultsPayload?.tools?.sqlmap ||
    resultsPayload?.results?.sqlmap ||
    resultsPayload?.data?.sqlmap ||
    {};

  const zapData =
    resultsPayload?.zap ||
    resultsPayload?.tools?.zap ||
    resultsPayload?.results?.zap ||
    resultsPayload?.data?.zap ||
    {};

  const sqlmapFindings = extractFindingRows(sqlmapData, "SQLMap");
  const zapFindings = extractFindingRows(zapData, "ZAP");

  return {
    sqlmapFindings,
    zapFindings,
    allFindings: [...sqlmapFindings, ...zapFindings]
  };
}

function severityCount(findings, level) {
  return findings.filter((finding) => finding.severity === level).length;
}

export function buildDashboardModel({ target, startedAt, completedAt, statusPayload, resultsPayload, reportPayload, graphPayload }) {
  const portRows = extractPortRows(resultsPayload);
  const webFindings = extractWebFindings(resultsPayload);

  const totalFindings = webFindings.allFindings.length;
  const high = severityCount(webFindings.allFindings, "high");
  const medium = severityCount(webFindings.allFindings, "medium");
  const low = severityCount(webFindings.allFindings, "low");
  const info = severityCount(webFindings.allFindings, "info");

  const weightedRisk = Math.min(100, high * 12 + medium * 7 + low * 3 + info);
  const reportRiskScore =
    reportPayload?.risk_score ||
    reportPayload?.summary?.risk_score ||
    reportPayload?.summary?.riskScore ||
    statusPayload?.risk_score;

  const riskScore = Number.isFinite(Number(reportRiskScore)) ? Number(reportRiskScore) : weightedRisk;

  const effectiveStartedAt = startedAt || statusPayload?.started_at || statusPayload?.created_at;
  const effectiveCompletedAt = completedAt || statusPayload?.completed_at || reportPayload?.generated_at;

  let duration = "N/A";
  if (effectiveStartedAt && effectiveCompletedAt) {
    const durationMs = Math.max(0, new Date(effectiveCompletedAt) - new Date(effectiveStartedAt));
    duration = `${Math.round(durationMs / 1000)}s`;
  }

  const summaryText =
    reportPayload?.summary?.text ||
    reportPayload?.summary ||
    statusPayload?.summary ||
    "Scan completed. Review findings across network and web vectors.";

  return {
    target,
    status: statusPayload?.status || "completed",
    duration,
    summaryText: typeof summaryText === "string" ? summaryText : JSON.stringify(summaryText),
    totals: {
      totalFindings,
      high,
      medium,
      low,
      info,
      openPorts: portRows.length,
      riskScore
    },
    ports: portRows,
    webFindings,
    graph: graphPayload,
    report: reportPayload,
    raw: {
      statusPayload,
      resultsPayload,
      reportPayload,
      graphPayload
    },
    severityOrder: SEVERITY_ORDER
  };
}

export function severityBadgeClass(severity) {
  const normalized = normalizeSeverity(severity);
  if (normalized === "high") {
    return "bg-red-100 text-red-700";
  }
  if (normalized === "medium") {
    return "bg-orange-100 text-orange-700";
  }
  if (normalized === "low") {
    return "bg-yellow-100 text-yellow-700";
  }
  return "bg-blue-100 text-blue-700";
}
