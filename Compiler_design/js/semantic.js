import { esc } from './utils.js';

function inferType(node, symbolTable) {
  if (!node) return null;
  if (node.type === 'Num') return Number.isInteger(node.value) ? 'int' : 'float';
  if (node.type === 'StringLit') return 'string';
  if (node.type === 'Var') {
    const s = symbolTable[node.name];
    return s ? s.type : null;
  }
  if (node.type === 'BinOp') {
    const l = inferType(node.left, symbolTable);
    const r = inferType(node.right, symbolTable);
    return promoteType(l, r);
  }
  return null;
}

function promoteType(a, b) {
  if (a === 'string' || b === 'string') return 'string';
  if (a === null || b === null) return a || b;
  const rank = { int: 0, float: 1, double: 2 };
  const ra = rank[a] ?? -1, rb = rank[b] ?? -1;
  return ra >= rb ? a : b;
}

export function semantic(stmts, isStrictMode) {
  const symbolTable = {}, checks = [], semErrors = [];

  function evalNode(node) {
    if (!node) return null;
    if (node.type === 'Num') return node.value;
    if (node.type === 'StringLit') return null;
    if (node.type === 'Var') { const s = symbolTable[node.name]; return (s && s.value !== undefined) ? s.value : null; }
    if (node.type === 'BinOp') {
      const l = evalNode(node.left), r = evalNode(node.right);
      if (l === null || r === null) return null;
      switch (node.op) { 
        case '+': return l + r; 
        case '-': return l - r; 
        case '*': return l * r; 
        case '/': return r !== 0 ? Math.trunc(l / r) : NaN; 
      }
    }
    return null;
  }

  function checkVars(node, line) {
    if (!node) return;
    if (node.type === 'Var') {
      if (!symbolTable[node.name]) {
        semErrors.push({ line, type: 'TYPE_ERROR', msg: `Undeclared variable '${node.name}'`, hint: `'${node.name}' is used before being declared. Add 'int ${node.name} = …;' before line ${line}.`, src: node.name });
        checks.push({ icon: 'err', text: `Line ${line}: <em>${esc(node.name)}</em> used but never declared` });
      }
    }
    if (node.type === 'BinOp') { checkVars(node.left, line); checkVars(node.right, line); }
  }

  for (const stmt of stmts) {
    if (stmt.type === 'ErrorStmt') continue;
    if (stmt.type === 'Decl') {
      if (symbolTable[stmt.name]) {
        semErrors.push({ line: stmt.line, type: 'TYPE_ERROR', msg: `Redeclaration of '${stmt.name}'`, hint: `'${stmt.name}' was already declared. Remove the duplicate 'int ${stmt.name}' on line ${stmt.line}.`, src: stmt.name });
        checks.push({ icon: 'err', text: `Line ${stmt.line}: <em>${esc(stmt.name)}</em> redeclared` });
      } else {
        let val = undefined;
        if (stmt.init) {
          checkVars(stmt.init, stmt.line);
          const declaredType = stmt.varType;
          const valueType = inferType(stmt.init, symbolTable);

          if (valueType === 'string' && declaredType !== 'char') {
            semErrors.push({
              line: stmt.line, type: 'TYPE_ERROR',
              msg: `Type mismatch: cannot assign 'string' to '${declaredType}'`,
              hint: `'${declaredType}' variables cannot hold string values. Use a char array or remove the string literal.`,
              src: stmt.name
            });
            checks.push({ icon: 'err', text: `Line ${stmt.line}: <em>${esc(stmt.name)}</em> — type mismatch (<em>string</em> → <em>${esc(declaredType)}</em>)` });
          } else if (declaredType === 'int' && valueType === 'float') {
            const warnOrErr = isStrictMode ? 'err' : 'warn';
            semErrors.push({
              line: stmt.line, type: isStrictMode ? 'TYPE_ERROR' : 'WARNING',
              msg: `Precision loss: float value assigned to 'int' (implicit truncation)`,
              hint: `Declare '${stmt.name}' as 'float' to preserve the decimal, or explicitly truncate with (int).`,
              src: stmt.name
            });
            checks.push({ icon: warnOrErr, text: `Line ${stmt.line}: <em>${esc(stmt.name)}</em> — precision loss (<em>float</em> → <em>int</em>)` });
          } else {
            const ev = evalNode(stmt.init); 
            if (ev !== null && !isNaN(ev)) val = ev;
          }
        }
        symbolTable[stmt.name] = { type: stmt.varType, value: val, line: stmt.line };
        if (!semErrors.some(e => e.src === stmt.name && e.line === stmt.line)) {
          checks.push({ icon: 'ok', text: `Line ${stmt.line}: declared <em>${esc(stmt.varType)} ${esc(stmt.name)}</em>${val !== undefined ? ' = ' + val : ''}` });
        }
      }
    }
    if (stmt.type === 'Assign') {
      if (!symbolTable[stmt.target]) {
        semErrors.push({ line: stmt.line, type: 'TYPE_ERROR', msg: `Assignment to undeclared variable '${stmt.target}'`, hint: `'${stmt.target}' was not declared. Add 'int ${stmt.target};' before line ${stmt.line}.`, src: stmt.target });
        checks.push({ icon: 'err', text: `Line ${stmt.line}: <em>${esc(stmt.target)}</em> assigned but never declared` });
      } else {
        checkVars(stmt.expr, stmt.line);
        const ev = evalNode(stmt.expr);
        if (ev !== null && !isNaN(ev)) {
          symbolTable[stmt.target].value = ev;
          checks.push({ icon: 'ok', text: `Line ${stmt.line}: <em>${esc(stmt.target)}</em> = ${ev} (constant-folded at compile time)` });
        } else {
          checks.push({ icon: 'ok', text: `Line ${stmt.line}: <em>${esc(stmt.target)}</em> assigned (runtime value)` });
        }
      }
    }
  }
  if (!checks.length) checks.push({ icon: 'info', text: 'No valid statements to analyse.' });
  return { symbolTable, checks, semErrors };
}
