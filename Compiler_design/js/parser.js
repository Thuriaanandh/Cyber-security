import { TT } from './lexer.js';

export function parser(tokens) {
  let pos = 0;
  const stmts = [], errors = [];

  function peek() { return tokens[pos] || { type: TT.EOF, value: 'EOF', line: 0 }; }
  function advance() { return tokens[pos++]; }
  function check(type, val) { const t = peek(); return t.type === type && (val === undefined || t.value === val); }

  function expect(type, val) {
    if (check(type, val)) return advance();
    const t = peek();
    const got = t.type === TT.EOF ? 'end of input' : `'${t.value}' (${t.type})`;
    const exp = val ? `'${val}'` : type;
    throw { msg: `Expected ${exp} but got ${got}`, token: t, hint: hint(type, val, t) };
  }

  function hint(eType, eVal, got) {
    if (eType === TT.SEMICOLON) return `Every statement must end with ';'. Add ';' after '${got.value}'.`;
    if (eType === TT.RPAREN) return `Missing closing ')'. Check your parentheses are balanced.`;
    if (eType === TT.IDENTIFIER) return `A variable name was expected here, but got '${got.value}'.`;
    if (eType === TT.ASSIGN) return `Assignment '=' expected. Did you forget '='?`;
    return `Unexpected '${got.value}'. Check expression syntax.`;
  }

  function sync() {
    while (peek().type !== TT.SEMICOLON && peek().type !== TT.EOF) advance();
    if (peek().type === TT.SEMICOLON) advance();
  }

  function parseExpr() {
    let node = parseTerm();
    while (check(TT.OPERATOR) && '+-'.includes(peek().value)) {
      const op = advance().value;
      node = { type: 'BinOp', op, left: node, right: parseTerm() };
    }
    return node;
  }

  function parseTerm() {
    let node = parseFactor();
    while (check(TT.OPERATOR) && '*/'.includes(peek().value)) {
      const op = advance().value;
      node = { type: 'BinOp', op, left: node, right: parseFactor() };
    }
    return node;
  }

  function parseFactor() {
    const t = peek();
    if (t.type === TT.EOF) throw { msg: 'Unexpected end of expression', token: t, hint: 'Expression is incomplete — an operand or closing parenthesis is missing.' };
    if (t.type === TT.SEMICOLON) throw { msg: `Unexpected ';' in expression`, token: t, hint: 'An operand was expected before the semicolon.' };
    
    if (t.type === TT.LPAREN) {
      advance();
      const node = parseExpr();
      expect(TT.RPAREN, ')');
      return node;
    }
    
    if (t.type === TT.CONSTANT) { advance(); return { type: 'Num', value: Number(t.value), line: t.line }; }
    if (t.type === TT.IDENTIFIER) { advance(); return { type: 'Var', name: t.value, line: t.line }; }
    if (t.type === TT.STRING) { advance(); return { type: 'StringLit', value: t.value, line: t.line }; }
    
    if (t.type === TT.OPERATOR) throw { msg: `Unexpected operator '${t.value}' — an operand was expected`, token: t, hint: `Remove the stray '${t.value}' or insert a missing operand before it.` };
    throw { msg: `Unexpected token '${t.value}'`, token: t, hint: `'${t.value}' cannot appear here in an expression.` };
  }

  function parseStatement() {
    const t = peek();
    
    // Declaration
    if (t.type === TT.KEYWORD) {
      const kw = advance();
      try {
        const id = expect(TT.IDENTIFIER);
        let init = null;
        if (check(TT.ASSIGN)) { advance(); init = parseExpr(); }
        expect(TT.SEMICOLON, ';');
        return { type: 'Decl', varType: kw.value, name: id.value, init, line: kw.line };
      } catch (e) {
        errors.push({ line: (e.token || t).line, msg: e.msg, hint: e.hint, src: (e.token || t).value });
        sync();
        return { type: 'ErrorStmt', line: t.line, msg: e.msg };
      }
    }
    
    // Assignment
    if (t.type === TT.IDENTIFIER) {
      const id = advance();
      try {
        expect(TT.ASSIGN, '=');
        const expr = parseExpr();
        expect(TT.SEMICOLON, ';');
        return { type: 'Assign', target: id.value, expr, line: id.line };
      } catch (e) {
        errors.push({ line: (e.token || t).line, msg: e.msg, hint: e.hint, src: (e.token || t).value });
        sync();
        return { type: 'ErrorStmt', line: t.line, msg: e.msg };
      }
    }
    
    // Unknown
    errors.push({ line: t.line, msg: `Unexpected token '${t.value}' at line ${t.line}`, hint: `Statements must start with a type keyword (int, float…) or a variable name.`, src: t.value });
    advance(); sync();
    return { type: 'ErrorStmt', line: t.line, msg: `Unexpected '${t.value}'` };
  }

  while (peek().type !== TT.EOF) stmts.push(parseStatement());
  
  return { stmts, errors };
}
