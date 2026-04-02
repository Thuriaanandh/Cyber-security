export function generateTAC(stmts) {
  let tmp = 1;
  const instrs = [];

  function newT() { return `t${tmp++}`; }

  function gen(node, si) {
    if (node.type === 'Num') return String(node.value);
    if (node.type === 'StringLit') return `"${node.value}"`;
    if (node.type === 'Var') return node.name;
    if (node.type === 'BinOp') {
      const l = gen(node.left, si), r = gen(node.right, si), t = newT();
      instrs.push({ result: t, arg1: l, op: node.op, arg2: r, si });
      return t;
    }
    return '?';
  }

  stmts.forEach((stmt, si) => {
    if (stmt.type === 'ErrorStmt') return;
    if (stmt.type === 'Decl' && stmt.init) {
      const r = gen(stmt.init, si);
      instrs.push({ result: stmt.name, arg1: r, op: null, arg2: null, si, cmt: 'init' });
    }
    if (stmt.type === 'Assign') {
      const r = gen(stmt.expr, si);
      instrs.push({ result: stmt.target, arg1: r, op: null, arg2: null, si });
    }
  });
  return instrs;
}
