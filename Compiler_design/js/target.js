export function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function scanConstants(stmts) {
  const found = [];
  function nStr(n) {
    if (!n) return '';
    if (n.type === 'Num') return String(n.value);
    if (n.type === 'Var') return n.name;
    if (n.type === 'BinOp') return `(${nStr(n.left)} ${n.op} ${nStr(n.right)})`;
    return '?';
  }
  function ev(n) {
    if (!n) return null;
    if (n.type === 'Num') return n.value;
    if (n.type === 'Var') return null;
    if (n.type === 'BinOp') {
      const l = ev(n.left), r = ev(n.right);
      if (l === null || r === null) return null;
      switch (n.op) { case '+': return l + r; case '-': return l - r; case '*': return l * r; case '/': return r !== 0 ? Math.trunc(l / r) : NaN; }
    }
    return null;
  }
  function walk(node, line) {
    if (!node || node.type === 'Num' || node.type === 'Var') return;
    if (node.type === 'BinOp') {
      walk(node.left, line); walk(node.right, line);
      const v = ev(node);
      if (v !== null && !isNaN(v)) {
        const s = nStr(node);
        if (!found.some(f => f.exprStr === s && f.line === line)) found.push({ exprStr: s, value: v, line });
      }
    }
  }
  stmts.forEach(s => {
    if (s.type === 'Decl' && s.init) walk(s.init, s.line);
    if (s.type === 'Assign') walk(s.expr, s.line);
  });
  return found;
}

export function generateASM(optInstrs) {
  const lines = [];
  const isN = s => /^-?[\d.]+$/.test(s);
  for (const ins of optInstrs) {
    if (ins.op) {
      lines.push({ op: isN(ins.arg1) ? 'LOADI' : 'LOAD', arg: ins.arg1, si: ins.si });
      const b = { '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV' }[ins.op];
      lines.push({ op: b + (isN(ins.arg2) ? 'I' : ''), arg: ins.arg2, si: ins.si });
      lines.push({ op: 'STORE', arg: ins.result, si: ins.si });
    } else {
      if (ins.arg1 !== ins.result) {
        lines.push({ op: isN(ins.arg1) ? 'LOADI' : 'LOAD', arg: ins.arg1, si: ins.si });
        lines.push({ op: 'STORE', arg: ins.result, si: ins.si });
      }
    }
  }
  return lines;
}
