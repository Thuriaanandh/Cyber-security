import { generateTAC } from './tac.js';

export function optimize(stmts, rawInstrs) {
  const applied = [];

  function fold(node) {
    if (!node || node.type === 'Num' || node.type === 'Var') return node;
    if (node.type === 'BinOp') {
      const l = fold(node.left), r = fold(node.right);
      if (l.type === 'Num' && r.type === 'Num') {
        let v;
        switch (node.op) { 
          case '+': v = l.value + r.value; break; 
          case '-': v = l.value - r.value; break; 
          case '*': v = l.value * r.value; break; 
          case '/': v = r.value !== 0 ? Math.trunc(l.value / r.value) : NaN; break; 
        }
        applied.push(`Constant fold: ${l.value} ${node.op} ${r.value} → ${v}`);
        return { type: 'Num', value: v };
      }
      return { ...node, left: l, right: r };
    }
    return node;
  }

  const foldedStmts = stmts.map(s => {
    if (s.type === 'Decl') return { ...s, init: fold(s.init) };
    if (s.type === 'Assign') return { ...s, expr: fold(s.expr) };
    return s;
  });

  let optInstrs = generateTAC(foldedStmts).filter(ins => {
    if (!ins.op && ins.result === ins.arg1) { 
      applied.push(`Dead copy removed: ${ins.result} = ${ins.arg1}`); 
      return false; 
    }
    return true;
  });

  const saved = rawInstrs.length - optInstrs.length;
  if (saved > 0) applied.push(`${saved} instruction${saved > 1 ? 's' : ''} eliminated`);
  if (!applied.length) applied.push('No optimisations applicable — already optimal.');

  return { optInstrs, foldedStmts, applied };
}
