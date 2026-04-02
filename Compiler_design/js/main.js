import { lexer, buildTokenGroups, TT } from './lexer.js';
import { parser } from './parser.js';
import { semantic } from './semantic.js';
import { generateTAC } from './tac.js';
import { optimize } from './optimize.js';
import { generateASM, scanConstants } from './target.js';
import { prettyAST, buildUnifiedParseTreeLayout, renderParseTreeSVG, buildDAG, layoutDAG, renderDAGSVG } from './visualizer.js';
import { esc } from './utils.js';

const EXAMPLES = {
  ex1: `int a = 5;\nint b = 4;\nint c = 2;\na = (b + c) * 2;`,
  ex2: `int x = (2 + 3) * 4;\nint y = 10;\ny = (10 + 5) * (2 - 1);`,
  ex3: `int a = 5;\nint b = 4;\nint c = 2;\nint d = 3;\na = (b + c) * d;\nb = a - c / 2;\nc = a * b + d;`,
  ex4: `int a = 5;\nint b = 4;\na = (b + c *;`,
  ex5: `int a = 5;\na = b + 3;`,
  ex6: `int a = "hello";\nint b = 5;`,
  ex7: `int a = 5.7;\nint b = 3;\nfloat c = 2.5;`,
};

window.setEx = function(k) { 
  document.getElementById('code-input').value = EXAMPLES[k]; 
  compile(); 
};

window.clearAll = function() { 
  document.getElementById('code-input').value = ''; 
  resetUI(); 
};

function isStrictMode() { return document.getElementById('strict-mode-cb').checked; }

window.updateStrictBadge = function() {
  const on = isStrictMode();
  const badge = document.getElementById('strict-mode-badge');
  badge.textContent = on ? 'ON' : 'OFF';
  badge.className = 'strict-badge ' + (on ? 'on' : 'off');
};

function resetUI() {
  for (let i = 1; i <= 6; i++) {
    document.getElementById('pl' + i).classList.remove('active', 'has-error');
    const c = document.getElementById('card' + i);
    c.classList.remove('visible', 'phase-disabled');
    document.getElementById('body' + i).innerHTML = '<div class="placeholder-msg">Awaiting input&hellip;</div>';
  }
  document.getElementById('errors-panel').classList.remove('show');
  document.getElementById('errors-list').innerHTML = '';
  document.getElementById('const-scanner').classList.remove('visible');
  document.getElementById('cs-body').innerHTML = '<div class="placeholder-msg">Awaiting input&hellip;</div>';
  document.getElementById('final-tac-card').classList.remove('visible');
  document.getElementById('final-tac-body').innerHTML = '<div class="placeholder-msg">Awaiting compilation&hellip;</div>';
  document.getElementById('ptree-card').classList.remove('visible');
  document.getElementById('ptree-body').innerHTML = '<div class="placeholder-msg">Awaiting compilation&hellip;</div>';
  document.getElementById('dag-card').classList.remove('visible');
  document.getElementById('dag-body').innerHTML = '<div class="placeholder-msg">Awaiting compilation&hellip;</div>';
  document.getElementById('termination-banner').classList.remove('show');
}

function showCard(n) { document.getElementById('card' + n).classList.add('visible'); }

function pushErrors(errs, pipeId) {
  if (!errs.length) return;
  const panel = document.getElementById('errors-panel');
  const list = document.getElementById('errors-list');
  const badge = document.getElementById('err-count');
  
  const prev = parseInt(badge.textContent) || 0;
  badge.textContent = prev + errs.length;
  
  list.innerHTML += errs.map(e => {
    const isWarn = e.type === 'WARNING';
    return `
    <div class="error-item${isWarn ? ' warn-item' : ''}">
      <span class="err-line-badge">Line ${e.line}</span>
      <div class="err-main">
        <div class="err-msg">${isWarn ? '&#9888;' : '&#9888;'} ${isWarn ? '[WARNING] ' : ''}${esc(e.msg)}</div>
        ${e.hint ? `<div class="err-hint">&#128161; ${esc(e.hint)}</div>` : ''}
        ${e.src ? `<div class="err-src">Near token: <span class="err-token">${esc(e.src)}</span></div>` : ''}
      </div>
    </div>`;
  }).join('');
  
  panel.classList.add('show');
  document.getElementById('pl' + pipeId).classList.add('has-error');
}

function cOp(v) {
  const e = esc(v);
  if (/^t\d+$/.test(v)) return `<span class="c-tmp">${e}</span>`;
  if (/^-?[\d.]+$/.test(v)) return `<span class="c-num">${e}</span>`;
  return `<span class="c-var">${e}</span>`;
}

function renderTAC(instrs, stmts) {
  if (!instrs.length) return '<div class="placeholder-msg" style="padding:6px 0">No instructions generated.</div>';
  let h = '<div class="code-block">', lastSi = -1;
  instrs.forEach((ins, i) => {
    if (ins.si !== lastSi) {
      if (lastSi !== -1) h += '<div class="code-sep"></div>';
      if (stmts) {
        const s = stmts[ins.si];
        if (s) {
          const lbl = s.type === 'Decl' ? `decl ${s.varType} ${s.name}` : `assign ${s.target}`;
          h += `<div class="code-sep-label">&#9472; Line ${s.line}: ${esc(lbl)}</div>`;
        }
      }
      lastSi = ins.si;
    }
    let t;
    if (ins.op) t = `${cOp(ins.result)} <span class="c-op">=</span> ${cOp(ins.arg1)} <span class="c-op">${esc(ins.op)}</span> ${cOp(ins.arg2)}`;
    else t = `${cOp(ins.result)} <span class="c-op">=</span> ${cOp(ins.arg1)}`;
    if (ins.cmt) t += `  <span class="c-cmt">// ${esc(ins.cmt)}</span>`;
    h += `<div class="code-line"><span class="code-lnum">${i + 1}</span><span class="code-text">${t}</span></div>`;
  });
  return h + '</div>';
}

function renderASMHtml(lines) {
  if (!lines.length) return '<div class="placeholder-msg" style="padding:6px 0">No instructions.</div>';
  const kc = { LOAD: '#3b82f6', LOADI: '#3b82f6', STORE: '#ea580c', ADD: '#10b981', ADDI: '#10b981', SUB: '#10b981', SUBI: '#10b981', MUL: '#f59e0b', MULI: '#f59e0b', DIV: '#ef4444', DIVI: '#ef4444' };
  let h = '<div class="code-block">', lastSi = -1;
  lines.forEach((l, i) => {
    if (l.si !== lastSi && lastSi !== -1) h += '<div class="code-sep"></div>';
    lastSi = l.si;
    const col = kc[l.op] || '#6b7280';
    const isN = /^-?[\d.]+$/.test(l.arg);
    const aH = isN ? `<span class="c-num">${esc(l.arg)}</span>` : `<span class="c-var">${esc(l.arg)}</span>`;
    h += `<div class="code-line"><span class="code-lnum">${i + 1}</span><span class="code-text"><span style="color:${col};font-weight:700">${l.op}</span>&nbsp;&nbsp;${aH}</span></div>`;
  });
  return h + '</div>';
}

window.compile = function() {
  const src = document.getElementById('code-input').value;
  resetUI();
  if (!src.trim()) return;

  // Phase 1: LEXER
  const { tokens, errors: lexErr } = lexer(src);
  if (lexErr.length) pushErrors(lexErr, 1);
  document.getElementById('pl1').classList.add('active');

  const filtered = tokens.filter(t => t.type !== TT.EOF);
  const rows = filtered.map(t =>
    `<tr><td class="tok-line">${t.line}</td><td class="tok-value">${esc(t.value)}</td><td><span class="tok-type tt-${t.type}">${t.type}</span></td></tr>`
  ).join('');
  const maxLine = filtered.reduce((m, t) => Math.max(m, t.line), 1);

  const { groups, ORDER } = buildTokenGroups(tokens);
  const catRows = ORDER.filter(k => groups[k].values.length > 0).map(k => {
    const g = groups[k];
    const vals = g.values.map(v => `<span class="tok-type tt-${k}" style="margin:2px 2px;display:inline-block">${esc(v)}</span>`).join(' ');
    const lines = [...g.lines].sort((a, b) => a - b).join(', ');
    return `<tr><td><span class="tok-type tt-${k}">${k}</span></td><td class="cat-values">${vals}</td><td class="cat-lines">${lines}</td></tr>`;
  }).join('');

  document.getElementById('body1').innerHTML = `
    <div class="lexer-tables-wrap">
      <div class="token-table-col">
        <div class="token-cat-label">Token Stream</div>
        <table class="token-table">
          <thead><tr><th>Line</th><th>Lexeme</th><th>Type</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="token-table-col">
        <div class="token-cat-label">&#x25B6; Token Category Table</div>
        <table class="cat-table">
          <thead><tr><th>Type</th><th>Values</th><th>Lines</th></tr></thead>
          <tbody>${catRows}</tbody>
        </table>
      </div>
    </div>
    <div class="token-count">Tokens: <strong>${filtered.length}</strong> &nbsp;&middot;&nbsp; Lines: <strong>${maxLine}</strong></div>`;
  showCard(1);

  // Phase 2: PARSER
  const { stmts, errors: parseErr } = parser(tokens);
  if (parseErr.length) pushErrors(parseErr, 2);
  document.getElementById('pl2').classList.add('active');

  const treeHtml = stmts.length ? stmts.map((stmt, i) => {
    const lbl = stmt.type === 'ErrorStmt'
      ? `<span style="color:var(--red)">&#9888; Error Statement</span>`
      : stmt.type === 'Decl'
        ? `<span class="ast-kw">${esc(stmt.varType)}</span> <span class="ast-id">${esc(stmt.name)}</span>`
        : `<span class="ast-id">${esc(stmt.target)}</span> <span style="color:var(--orange)">=</span> &hellip;`;
    return `<div class="stmt-block">
      <div class="stmt-block-label">Stmt ${i + 1} &middot; Line ${stmt.line} &middot; ${esc(stmt.type)} &nbsp; ${lbl}</div>
      <div class="ast-tree">${prettyAST(stmt)}</div>
    </div>`;
  }).join('') : '<div class="placeholder-msg">No statements parsed.</div>';
  document.getElementById('body2').innerHTML = treeHtml;
  showCard(2);

  const validStmts = stmts.filter(s => s.type !== 'ErrorStmt');

  // CONST SCANNER
  const constFound = scanConstants(validStmts);
  const csBody = document.getElementById('cs-body');
  if (!constFound.length) {
    csBody.innerHTML = `<div style="display:flex;gap:10px;align-items:center;font-size:12px;color:var(--text-dim)"><span style="font-size:18px">&#x2205;</span><span>No constant sub-expressions found &mdash; all operands involve variables at runtime.</span></div>`;
  } else {
    const pills = constFound.map(f => `
      <div class="ce-pill">
        <span class="ce-pill-expr">${esc(f.exprStr)}</span>
        <span class="ce-pill-arrow">&#x2192;</span>
        <span class="ce-pill-val">${f.value}</span>
        <span class="ce-pill-line">line&nbsp;${f.line}</span>
      </div>`).join('');
    csBody.innerHTML = `<div style="font-size:12px;color:var(--text-dim);margin-bottom:12px;font-weight:600">${constFound.length} constant expression${constFound.length > 1 ? 's' : ''} detected:</div><div class="ce-pill-row">${pills}</div>`;
  }
  document.getElementById('const-scanner').classList.add('visible');

  // Phase 3: SEMANTIC
  const { symbolTable, checks, semErrors } = semantic(stmts, isStrictMode());
  if (semErrors.length) pushErrors(semErrors, 3);
  document.getElementById('pl3').classList.add('active');

  const symRows = Object.entries(symbolTable).map(([nm, info]) =>
    `<tr>
      <td style="color:var(--text-bright);font-weight:700">${esc(nm)}</td>
      <td><span class="sym-type-badge stype-${info.type}">${esc(info.type)}</span></td>
      <td>${info.value !== undefined ? `<span class="sym-val">${info.value}</span>` : '<span class="sym-undef">runtime</span>'}</td>
      <td style="color:var(--text-dim)">${info.line}</td>
    </tr>`
  ).join('');

  const checksHtml = checks.map(c => `
    <div class="sem-check">
      <div class="sem-icon sem-${c.icon === 'err' ? 'err' : c.icon === 'warn' ? 'warn' : c.icon === 'info' ? 'info' : 'ok'}">${c.icon === 'err' ? '&#x2715;' : c.icon === 'warn' ? '!' : c.icon === 'info' ? 'i' : '&#10003;'}</div>
      <div class="sem-text">${c.text}</div>
    </div>`).join('');

  document.getElementById('body3').innerHTML =
    (symRows ? `<table class="sym-table"><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Decl. Line</th></tr></thead><tbody>${symRows}</tbody></table>` : '')
    + checksHtml;
  showCard(3);

  const fatalErrors = semErrors.filter(e => e.type === 'TYPE_ERROR');
  const STRICT = isStrictMode();

  if (fatalErrors.length > 0 && STRICT) {
    document.getElementById('termination-banner').classList.add('show');
    [4, 5, 6].forEach(n => {
      const card = document.getElementById('card' + n);
      card.classList.add('visible', 'phase-disabled');
      document.getElementById('body' + n).innerHTML =
        `<div class="placeholder-msg" style="color:var(--red);opacity:.8;font-weight:600">&#x26D4; Skipped — semantic errors must be resolved first.</div>`;
    });
    ['final-tac-body', 'ptree-body', 'dag-body'].forEach(id => {
      document.getElementById(id).innerHTML =
        `<div class="placeholder-msg" style="color:var(--red);opacity:.8;font-weight:600">&#x26D4; Not generated — compilation terminated after Phase 3.</div>`;
    });
    setTimeout(() => {
      document.getElementById('final-tac-card').classList.add('visible');
      document.getElementById('ptree-card').classList.add('visible');
      document.getElementById('dag-card').classList.add('visible');
    }, 300);
    return;
  }

  if (fatalErrors.length > 0 && !STRICT) {
    document.getElementById('body3').innerHTML +=
      `<div style="margin-top:16px;padding:12px 16px;border-radius:10px;background:#fef3c7;border:1px solid #fde68a;font-size:12px;color:#b45309;font-weight:600">
        &#9888; Lenient mode: compilation continues despite type errors. Invalid nodes may produce incorrect output.
      </div>`;
  }

  // Phase 4: TAC
  const rawInstrs = generateTAC(validStmts);
  document.getElementById('pl4').classList.add('active');
  document.getElementById('body4').innerHTML = renderTAC(rawInstrs, validStmts);
  showCard(4);

  // Phase 5: OPTIMIZE
  const { optInstrs, foldedStmts, applied } = optimize(validStmts, rawInstrs);
  document.getElementById('pl5').classList.add('active');

  const appliedHtml = applied.map(a =>
    `<div class="sem-check"><div class="sem-icon sem-info">&#9889;</div><div class="sem-text"><em>${esc(a)}</em></div></div>`
  ).join('');
  document.getElementById('body5').innerHTML = appliedHtml + renderTAC(optInstrs, foldedStmts);
  showCard(5);

  // Phase 6: TARGET
  const asmLines = generateASM(optInstrs);
  document.getElementById('pl6').classList.add('active');
  document.getElementById('body6').innerHTML = renderASMHtml(asmLines) + `
    <div style="margin-top:16px;display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--text-dim);font-weight:500">
      <span><span style="color:var(--accent);font-weight:700">LOAD/LOADI</span> load to ACC</span>
      <span><span style="color:var(--green);font-weight:700">ADD/SUB</span> arithmetic</span>
      <span><span style="color:var(--yellow);font-weight:700">MUL</span> multiply</span>
      <span><span style="color:var(--red);font-weight:700">DIV</span> divide</span>
      <span><span style="color:var(--orange);font-weight:700">STORE</span> write result</span>
    </div>`;
  showCard(6);

  // FINAL TAC SUMMARY
  const saved = rawInstrs.length - optInstrs.length;
  const saveBadge = saved > 0
    ? `<span style="font-size:11px;font-weight:700;padding:4px 12px;border-radius:8px;background:var(--green-glow);color:var(--green)">&#8722;${saved} instruction${saved > 1 ? 's' : ''} saved</span>`
    : `<span style="font-size:11px;font-weight:700;padding:4px 12px;border-radius:8px;background:var(--accent-glow);color:var(--accent)">Already optimal</span>`;

  const rawTemps = new Set(rawInstrs.filter(i => i.op).map(i => i.result));
  const optTemps = new Set(optInstrs.filter(i => i.op).map(i => i.result));
  const foldedSet = new Set([...rawTemps].filter(r => !optTemps.has(r)));

  function renderColFinal(instrs, stmts_, markFolded) {
    if (!instrs.length) return '<div class="placeholder-msg" style="padding:6px 0">None</div>';
    let h = '<div class="code-block">', lastSi = -1;
    instrs.forEach((ins, i) => {
      if (ins.si !== lastSi) {
        if (lastSi !== -1) h += '<div class="code-sep"></div>';
        if (stmts_) {
          const s = stmts_[ins.si];
          if (s) { const lbl = s.type === 'Decl' ? `decl ${s.varType} ${s.name}` : `assign ${s.target}`; h += `<div class="code-sep-label">&#9472; Line ${s.line}: ${esc(lbl)}</div>`; }
        }
        lastSi = ins.si;
      }
      const wf = markFolded && ins.op && foldedSet.has(ins.result);
      let t;
      if (ins.op) t = `${cOp(ins.result)} <span class="c-op">=</span> ${cOp(ins.arg1)} <span class="c-op">${esc(ins.op)}</span> ${cOp(ins.arg2)}`;
      else t = `${cOp(ins.result)} <span class="c-op">=</span> ${cOp(ins.arg1)}`;
      const fo = wf ? ' style="opacity:.4;text-decoration:line-through"' : '';
      const fb = wf ? `<span style="margin-left:12px;font-size:10px;font-weight:800;padding:2px 8px;border-radius:6px;background:var(--orange-glow);color:var(--orange)">FOLDED</span>` : '';
      h += `<div class="code-line"${fo}><span class="code-lnum">${i + 1}</span><span class="code-text">${t}</span>${fb}</div>`;
    });
    return h + '</div>';
  }

  document.getElementById('final-tac-body').innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap">
      <div style="font-size:13px;font-weight:500;color:var(--text-dim)">${validStmts.length} statement${validStmts.length !== 1 ? 's' : ''} compiled</div>
      ${saveBadge}
    </div>
    <div class="tac-columns">
      <div><div class="tac-col-label raw">&#x25CF; Raw TAC &mdash; ${rawInstrs.length} instr.</div>${renderColFinal(rawInstrs, validStmts, false)}</div>
      <div><div class="tac-col-label opt">&#x25CF; Optimised TAC &mdash; ${optInstrs.length} instr.</div>${renderColFinal(optInstrs, foldedStmts, true)}</div>
    </div>
    <div class="tac-legend">
      <span><span class="ldot" style="background:var(--orange)"></span>t1,t2&hellip; temporaries</span>
      <span><span class="ldot" style="background:var(--accent)"></span>named variables</span>
      <span><span class="ldot" style="background:var(--green)"></span>numeric constants</span>
      <span><span class="ldot" style="background:var(--yellow)"></span>operators</span>
    </div>`;
  setTimeout(() => document.getElementById('final-tac-card').classList.add('visible'), 380);

  // VISUALIZERS
  {
    const ptBody = document.getElementById('ptree-body');
    if (!stmts.length) {
      ptBody.innerHTML = '<div class="placeholder-msg">No statements to visualise.</div>';
    } else {
      const hasErr = stmts.some(s => s.type === 'ErrorStmt');
      const layout = buildUnifiedParseTreeLayout(stmts);
      const svgStr = renderParseTreeSVG(layout);
      const stmtCount = stmts.length;
      const errCount = stmts.filter(s => s.type === 'ErrorStmt').length;
      ptBody.innerHTML = `
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;flex-wrap:wrap">
          <span style="font-size:13px;font-weight:500;color:var(--text-dim)">${stmtCount} statement${stmtCount !== 1 ? 's' : ''} &nbsp;&middot;&nbsp; <span style="color:var(--purple);font-weight:700">${layout.nodes.length} nodes</span></span>
          ${errCount ? `<span style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:6px;background:var(--red-glow);color:var(--red)">${errCount} parse error${errCount > 1 ? 's' : ''}</span>` : ''}
        </div>
        <div class="ptree-svg-wrap">${svgStr}</div>`;
      if (hasErr) {
        ptBody.innerHTML += `<div class="ptree-err-note"><span class="pte-icon">&#9888;</span>
          <span><strong>Parse error(s) detected:</strong> Error nodes are shown in red. The tree shows the partial structure built before each error was encountered.</span>
        </div>`;
      }
      ptBody.innerHTML += `<div style="display:flex;flex-wrap:wrap;gap:16px;font-size:12px;font-weight:500;color:var(--text-dim);margin-top:16px">
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#cffafe" stroke="#06b6d4" stroke-width="2"/></svg> Program Root</span>
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#ede9fe" stroke="#8b5cf6" stroke-width="2"/></svg> Statement Root</span>
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#fef3c7" stroke="#f59e0b" stroke-width="1.5"/></svg> Operator</span>
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#dbeafe" stroke="#3b82f6" stroke-width="1.5"/></svg> Identifier</span>
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#d1fae5" stroke="#10b981" stroke-width="1.5"/></svg> Number</span>
        <span><svg width="14" height="14"><rect x="1" y="1" width="12" height="12" rx="3" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5"/></svg> Error node</span>
      </div>`;
    }
    setTimeout(() => document.getElementById('ptree-card').classList.add('visible'), 420);
  }

  {
    const dagBody = document.getElementById('dag-body');
    if (!validStmts.length) {
      dagBody.innerHTML = '<div class="placeholder-msg">No valid statements — DAG not generated.</div>';
    } else {
      const { pool, roots } = buildDAG(foldedStmts);
      const layout = layoutDAG(pool, roots);
      const svgStr = renderDAGSVG(layout);
      const nodeArr = [...pool.values()];
      const sharedCount = nodeArr.filter(n => nodeArr.some(other => other.id !== n.id && other.children.includes(n.id))).length;
      const savedNodes = validStmts.reduce((acc, s) => {
        function countNodes(n) { if (!n) return 0; if (n.type === 'Num' || n.type === 'Var') return 1; if (n.type === 'BinOp') return 1 + countNodes(n.left) + countNodes(n.right); return 0; }
        if (s.type === 'Decl' && s.init) return acc + countNodes(s.init);
        if (s.type === 'Assign') return acc + countNodes(s.expr);
        return acc;
      }, validStmts.length) - nodeArr.length;
      
      dagBody.innerHTML = `
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;flex-wrap:wrap">
          <span style="font-size:13px;font-weight:500;color:var(--text-dim)">
            <span style="color:var(--text-bright);font-weight:800">${nodeArr.length}</span> nodes &nbsp;&middot;&nbsp; 
            <span style="color:var(--text-bright);font-weight:800">${layout.edges.length}</span> edges
          </span>
          ${sharedCount ? `<span style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:6px;background:var(--cyan-glow);color:var(--cyan)">&#9830; ${sharedCount} shared subexpression${sharedCount !== 1 ? 's' : ''}</span>` : ''}
          ${savedNodes > 0 ? `<span style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:6px;background:var(--green-glow);color:var(--green)">&#8722;${savedNodes} node${savedNodes !== 1 ? 's' : ''} eliminated</span>` : `<span style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:6px;background:var(--accent-glow);color:var(--accent)">No redundancy</span>`}
        </div>
        <div class="dag-svg-wrap">${svgStr}</div>
        <div class="dag-legend">
          <span><span class="dl-dot" style="background:#8b5cf6"></span>Root/Assignment</span>
          <span><span class="dl-dot" style="background:#f59e0b"></span>Operator</span>
          <span><span class="dl-dot" style="background:#0891b2;border:2px solid #06b6d4;box-shadow:0 0 6px rgba(6,182,212,.5)"></span>Shared subexpr</span>
          <span><span class="dl-dot" style="background:#3b82f6"></span>Identifier</span>
          <span><span class="dl-dot" style="background:#10b981"></span>Number</span>
        </div>`;
    }
    setTimeout(() => document.getElementById('dag-card').classList.add('visible'), 480);
  }
};
