export const TT = {
  KEYWORD: 'KEYWORD', IDENTIFIER: 'IDENTIFIER', CONSTANT: 'CONSTANT',
  OPERATOR: 'OPERATOR', ASSIGN: 'ASSIGN', LPAREN: 'LPAREN', RPAREN: 'RPAREN',
  SEMICOLON: 'SEMICOLON', STRING: 'STRING', EOF: 'EOF'
};

const KEYWORDS = new Set(['int', 'float', 'double', 'char', 'bool', 'void']);

export function lexer(src) {
  const tokens = [], errors = [];
  let i = 0, line = 1;

  while (i < src.length) {
    const ch = src[i];
    if (ch === '\n') { line++; i++; continue; }
    if (/\s/.test(ch)) { i++; continue; }

    // string literal
    if (ch === '"' || ch === "'") {
      const q = ch; let s = ''; i++;
      while (i < src.length && src[i] !== q && src[i] !== '\n') s += src[i++];
      if (i < src.length && src[i] === q) i++;
      tokens.push({ type: TT.STRING, value: s, line });
      continue;
    }

    // number
    if (/[0-9]/.test(ch)) {
      let n = '';
      while (i < src.length && /[0-9.]/.test(src[i])) n += src[i++];
      tokens.push({ type: TT.CONSTANT, value: n, line });
      continue;
    }

    // identifier / keyword
    if (/[a-zA-Z_]/.test(ch)) {
      let id = '';
      while (i < src.length && /[a-zA-Z0-9_]/.test(src[i])) id += src[i++];
      tokens.push({ type: KEYWORDS.has(id) ? TT.KEYWORD : TT.IDENTIFIER, value: id, line });
      continue;
    }

    if (ch === '=') { tokens.push({ type: TT.ASSIGN, value: '=', line }); i++; continue; }
    if ('+-*/'.includes(ch)) { tokens.push({ type: TT.OPERATOR, value: ch, line }); i++; continue; }
    if (ch === '(') { tokens.push({ type: TT.LPAREN, value: '(', line }); i++; continue; }
    if (ch === ')') { tokens.push({ type: TT.RPAREN, value: ')', line }); i++; continue; }
    if (ch === ';') { tokens.push({ type: TT.SEMICOLON, value: ';', line }); i++; continue; }

    errors.push({
      line, msg: `Unknown character '${ch}'`,
      hint: `The character '${ch}' is not part of the supported language. Remove it.`,
      src: ch
    });
    i++;
  }
  tokens.push({ type: TT.EOF, value: 'EOF', line });
  return { tokens, errors };
}

export function buildTokenGroups(tokens) {
  const groups = {};
  const ORDER = ['KEYWORD', 'IDENTIFIER', 'CONSTANT', 'STRING', 'OPERATOR', 'ASSIGN', 'LPAREN', 'RPAREN', 'SEMICOLON'];
  ORDER.forEach(k => groups[k] = { values: [], lines: new Set() });

  tokens.forEach(t => {
    if (t.type === TT.EOF) return;
    const g = groups[t.type];
    if (!g) return;
    if (!g.values.includes(t.value)) g.values.push(t.value);
    g.lines.add(t.line);
  });
  return { groups, ORDER };
}
