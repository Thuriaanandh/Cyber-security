import { esc } from './target.js';

export function prettyAST(node, prefix = '', isLast = true) {
  const conn = isLast ? '&#9492;&#9472;&#9472; ' : '&#9500;&#9472;&#9472; ';
  const child = prefix + (isLast ? '&nbsp;&nbsp;&nbsp;&nbsp;' : '&#9474;&nbsp;&nbsp;&nbsp;');
  if (!node) return `${prefix}${conn}<span class="ast-err">[missing]</span>\n`;

  if (node.type === 'Decl') {
    let h = `<span class="ast-node">${prefix}<span class="ast-kw">DECL</span> <span class="ast-type">${esc(node.varType)}</span> <span class="ast-id">${esc(node.name)}</span>\n</span>`;
    if (node.init) h += prettyAST(node.init, child, true);
    return h;
  }
  if (node.type === 'Assign') {
    return `<span class="ast-node">${prefix}<span class="ast-assign">ASSIGN</span> &#8594; <span class="ast-id">${esc(node.target)}</span>\n</span>` + prettyAST(node.expr, child, true);
  }
  if (node.type === 'BinOp') {
    return `<span class="ast-node">${prefix}${conn}<span class="ast-op">BinOp(${esc(node.op)})</span>\n</span>` + prettyAST(node.left, child, false) + prettyAST(node.right, child, true);
  }
  if (node.type === 'Num') return `<span class="ast-node">${prefix}${conn}<span class="ast-num">Num(${node.value})</span>\n</span>`;
  if (node.type === 'StringLit') return `<span class="ast-node">${prefix}${conn}<span style="color:var(--cyan)">Str("${esc(node.value)}")</span>\n</span>`;
  if (node.type === 'Var') return `<span class="ast-node">${prefix}${conn}<span class="ast-id">Var(${esc(node.name)})</span>\n</span>`;
  if (node.type === 'ErrorStmt') return `<span class="ast-node">${prefix}${conn}<span class="ast-err">&#9888; ERROR: ${esc(node.msg)}</span>\n</span>`;
  return '';
}

export function buildUnifiedParseTreeLayout(stmts) {
  function toTree(node) {
    if (!node) return { label: '?', children: [], isError: true };
    if (node.type === 'Decl') {
      const ch = [{ label: node.varType, children: [], isLeaf: true, isKw: true }, { label: node.name, children: [], isLeaf: true, isId: true }];
      if (node.init) ch.push(toTree(node.init));
      return { label: 'DECL', children: ch, isRoot: true };
    }
    if (node.type === 'Assign') {
      return { label: '=', children: [{ label: node.target, children: [], isLeaf: true, isId: true }, toTree(node.expr)], isRoot: true, isOp: true };
    }
    if (node.type === 'BinOp') {
      return { label: node.op, children: [toTree(node.left), toTree(node.right)], isOp: true };
    }
    if (node.type === 'Num') return { label: String(node.value), children: [], isLeaf: true, isNum: true };
    if (node.type === 'Var') return { label: node.name, children: [], isLeaf: true, isId: true };
    if (node.type === 'ErrorStmt') return { label: 'ERR', children: [{ label: (node.msg || '').substring(0, 16) + '…', children: [], isError: true }], isError: true };
    return { label: '?', children: [], isError: true };
  }

  const programRoot = { label: 'PROGRAM', children: stmts.map(s => toTree(s)), isProgram: true };
  const NODE_W = 72, NODE_H = 40, H_GAP = 24, V_GAP = 65;

  function measure(n) {
    if (!n.children.length) { n.w = NODE_W; return; }
    n.children.forEach(measure);
    const totalW = n.children.reduce((s, c) => s + c.w, 0) + H_GAP * (n.children.length - 1);
    n.w = Math.max(NODE_W, totalW);
  }

  function place(n, x, y) {
    n.x = x + n.w / 2;
    n.y = y;
    let cx = x;
    n.children.forEach(c => { place(c, cx, y + V_GAP); cx += c.w + H_GAP; });
  }

  function allNodes(n, arr = []) { arr.push(n); n.children.forEach(c => allNodes(c, arr)); return arr; }

  measure(programRoot);
  place(programRoot, 0, 0);
  const nodes = allNodes(programRoot);

  const minX = Math.min(...nodes.map(n => n.x - NODE_W / 2));
  const maxX = Math.max(...nodes.map(n => n.x + NODE_W / 2));
  const maxY = Math.max(...nodes.map(n => n.y));
  const W = maxX - minX + 40;
  const H = maxY + NODE_H + 40;
  const OX = -minX + 20;
  const OY = NODE_H / 2 + 14;

  function edges(n, arr = []) {
    n.children.forEach(c => { arr.push({ x1: n.x + OX, y1: n.y + OY, x2: c.x + OX, y2: c.y + OY }); edges(c, arr); });
    return arr;
  }

  return { nodes, edges: edges(programRoot), W: Math.max(W, 200), H: Math.max(H, 100), OX, OY, NODE_W, NODE_H };
}

export function renderParseTreeSVG(layout) {
  const { nodes, edges, W, H, OX, OY, NODE_W, NODE_H } = layout;
  const rx = NODE_W / 2, ry = NODE_H / 2;

  const edgeSVG = edges.map(e => {
    const x1 = e.x1, y1 = e.y1 + ry, x2 = e.x2, y2 = e.y2 - ry;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    return `<path d="M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}" fill="none" stroke="#d1d5db" stroke-width="1.5" marker-end="url(#arrowhead)"/>`;
  }).join('');

  const nodeSVG = nodes.map(n => {
    const cx = n.x + OX, cy = n.y + OY;
    let fill = '#ffffff', stroke = '#d1d5db', textCol = '#374151', strokeW = 1.5;
    
    // Light theme adapted node colors
    if (n.isProgram) { stroke = '#06b6d4'; fill = '#cffafe'; textCol = '#0891b2'; strokeW = 2; }
    else if (n.isRoot) { stroke = '#8b5cf6'; fill = '#ede9fe'; textCol = '#6d28d9'; strokeW = 2; }
    else if (n.isOp) { stroke = '#f59e0b'; fill = '#fef3c7'; textCol = '#b45309'; }
    else if (n.isNum) { stroke = '#10b981'; fill = '#d1fae5'; textCol = '#047857'; }
    else if (n.isId) { stroke = '#3b82f6'; fill = '#dbeafe'; textCol = '#1d4ed8'; }
    else if (n.isKw) { stroke = '#ef4444'; fill = '#fee2e2'; textCol = '#b91c1c'; }
    else if (n.isError) { stroke = '#ef4444'; fill = '#fef2f2'; textCol = '#991b1b'; }
    
    const lbl = n.label.length > 9 ? n.label.substring(0, 8) + '…' : n.label;
    return `<rect x="${cx - rx}" y="${cy - ry}" width="${NODE_W}" height="${NODE_H}" rx="8" fill="${fill}" stroke="${stroke}" stroke-width="${strokeW}" />
      <text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" font-family="'Inter',sans-serif" font-size="12" fill="${textCol}" font-weight="600">${esc(lbl)}</text>`;
  }).join('');

  return `<svg width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" style="max-width:100%;display:block;margin:0 auto">
    <defs>
      <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
        <polygon points="0 0, 8 4, 0 8" fill="#9ca3af"/>
      </marker>
    </defs>
    ${edgeSVG}
    ${nodeSVG}
  </svg>`;
}

export function buildDAG(stmts) {
  const pool = new Map();
  let idSeq = 0;

  function key(node) {
    if (node.type === 'Num') return `N:${node.value}`;
    if (node.type === 'Var') return `V:${node.name}`;
    if (node.type === 'BinOp') {
      const lk = key(node.left), rk = key(node.right);
      return `B:${node.op}(${lk},${rk})`;
    }
    return 'ERR';
  }

  function intern(node) {
    const k = key(node);
    if (pool.has(k)) return pool.get(k).id;
    const id = idSeq++;
    let label, ntype, children = [];
    if (node.type === 'Num') { label = String(node.value); ntype = 'num'; }
    else if (node.type === 'Var') { label = node.name; ntype = 'id'; }
    else if (node.type === 'BinOp') {
      label = node.op; ntype = 'op';
      children = [intern(node.left), intern(node.right)];
    } else { label = '?'; ntype = 'err'; }
    pool.set(k, { id, label, ntype, children, k });
    return id;
  }

  const roots = [];
  stmts.forEach(s => {
    if (s.type === 'ErrorStmt') return;
    let exprNode = null, rootLabel = '';
    if (s.type === 'Decl' && s.init) { exprNode = s.init; rootLabel = `${s.varType} ${s.name}`; }
    if (s.type === 'Assign') { exprNode = s.expr; rootLabel = `${s.target} =`; }
    if (exprNode) {
      const exprId = intern(exprNode);
      const rid = idSeq++;
      pool.set(`ROOT:${rid}`, { id: rid, label: rootLabel, ntype: 'root', children: [exprId] });
      roots.push(rid);
    }
  });

  return { pool, roots };
}

export function layoutDAG(pool, roots) {
  const nodes = [...pool.values()];
  const byId = new Map(nodes.map(n => [n.id, n]));
  const depth = new Map();
  roots.forEach(r => depth.set(r, 0));
  const queue = [...roots];
  const visited = new Set();
  let qi = 0;
  while (qi < queue.length) {
    const id = queue[qi++];
    if (visited.has(id)) continue;
    visited.add(id);
    const n = byId.get(id); if (!n) continue;
    n.children.forEach(cid => {
      const cd = (depth.get(id) || 0) + 1;
      if (!depth.has(cid) || depth.get(cid) < cd) depth.set(cid, cd);
      queue.push(cid);
    });
  }

  const layers = new Map();
  nodes.forEach(n => {
    const d = depth.has(n.id) ? depth.get(n.id) : 0;
    if (!layers.has(d)) layers.set(d, []);
    layers.get(d).push(n);
  });

  const NODE_W = 60, NODE_H = 36, H_GAP = 30, V_GAP = 70;
  let maxD = Math.max(-1, ...layers.keys());
  for (let d = 0; d <= maxD; d++) {
    const layerNodes = layers.get(d) || [];
    const totalW = layerNodes.length * NODE_W + (layerNodes.length - 1) * H_GAP;
    let sx = -totalW / 2 + NODE_W / 2;
    layerNodes.forEach(n => { n.x = sx; n.y = d * V_GAP; sx += NODE_W + H_GAP; });
  }

  const edges = [];
  nodes.forEach(n => {
    n.children.forEach(cid => {
      const cn = byId.get(cid);
      if (cn) edges.push({ x1: n.x, y1: n.y, x2: cn.x, y2: cn.y, id: `${n.id}-${cid}` });
    });
  });

  const PAD = 40;
  const minX = Math.min(0, ...nodes.map(n => n.x - NODE_W / 2 - PAD));
  const maxX = Math.max(0, ...nodes.map(n => n.x + NODE_W / 2 + PAD));
  const minY = Math.min(0, ...nodes.map(n => n.y - NODE_H / 2 - PAD));
  const maxY = Math.max(0, ...nodes.map(n => n.y + NODE_H / 2 + PAD));
  return { nodes, edges, W: maxX - minX, H: maxY - minY, OX: -minX, OY: -minY, NODE_W, NODE_H };
}

export function renderDAGSVG(layout) {
  const { nodes, edges, W, H, OX, OY, NODE_W, NODE_H } = layout;
  const rx = NODE_W / 2, ry = NODE_H / 2;

  const edgeSVG = edges.map(e => {
    const x1 = e.x1 + OX, y1 = e.y1 + ry + OY, x2 = e.x2 + OX, y2 = e.y2 - ry + OY;
    const path = `M${x1},${y1} Q${x1},${y1 + 20} ${(x1 + x2) / 2},${(y1 + y2) / 2} T${x2},${y2}`;
    return `<path d="${path}" fill="none" stroke="#d1d5db" stroke-width="1.5" marker-end="url(#arrowhead)"/>`;
  }).join('');

  const nodeSVG = nodes.map(n => {
    const cx = n.x + OX, cy = n.y + OY;
    let fill = '#ffffff', stroke = '#d1d5db', textCol = '#374151', strokeW = 1.5;
    
    if (n.ntype === 'root') { stroke = '#8b5cf6'; fill = '#ede9fe'; textCol = '#6d28d9'; strokeW = 2; }
    else if (n.ntype === 'op') { stroke = '#f59e0b'; fill = '#fef3c7'; textCol = '#b45309'; }
    else if (n.ntype === 'num') { stroke = '#10b981'; fill = '#d1fae5'; textCol = '#047857'; }
    else if (n.ntype === 'id') { stroke = '#3b82f6'; fill = '#dbeafe'; textCol = '#1d4ed8'; }
    else { stroke = '#ef4444'; fill = '#fef2f2'; textCol = '#991b1b'; }

    const isShared = nodes.filter(parent => parent.children.includes(n.id)).length > 1;
    let glow = '';
    if (isShared) {
      glow = `<rect x="${cx - rx - 4}" y="${cy - ry - 4}" width="${NODE_W + 8}" height="${NODE_H + 8}" rx="12" fill="none" stroke="#06b6d4" stroke-width="3" opacity="0.3"/>`;
      stroke = '#0891b2';
      strokeW = 2;
    }

    const lbl = n.label.length > 9 ? n.label.substring(0, 8) + '…' : n.label;
    return `${glow}<rect x="${cx - rx}" y="${cy - ry}" width="${NODE_W}" height="${NODE_H}" rx="8" fill="${fill}" stroke="${stroke}" stroke-width="${strokeW}" />
      <text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" font-family="'Inter',sans-serif" font-size="12" fill="${textCol}" font-weight="600">${esc(lbl)}</text>`;
  }).join('');

  return `<svg width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" style="max-width:100%;display:block;margin:0 auto">
    <defs>
      <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
        <polygon points="0 0, 8 4, 0 8" fill="#9ca3af"/>
      </marker>
    </defs>
    ${edgeSVG}
    ${nodeSVG}
  </svg>`;
}
