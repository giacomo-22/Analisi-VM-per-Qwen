// Deobfuscatore sec-cpt — PASSO 1: inlining dei proxy di espressione (binary/unary/logical/conditional).
// Adattato da SteakEnthusiast "Binary & Unary Expression Proxy Functions". Differenza chiave:
// invece di valutare solo le chiamate ad argomenti COSTANTI, INLINA il corpo sostituendo i
// parametri con gli argomenti -> collassa anche m7(a,b) -> a!==b con argomenti variabili.
// Analisi OFFLINE: non eseguiamo lo script nel browser, quindi gli integrity-check non scattano.
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");

const INPUT = process.argv[2] || "seccpt_script_195092028.js";
const OUTPUT = process.argv[3] || "seccpt_deobf.js";

const src = fs.readFileSync(INPUT, "utf8");
console.log(`[in] ${INPUT}  ${src.length} bytes`);
const ast = parser.parse(src, { errorRecovery: true });

// --- raccogli i proxy: NAME = function(params){ return <expr semplice>; }  oppure function NAME(...)
// expr "semplice" = Binary/Unary/Logical/Conditional, che referenzia SOLO i propri parametri
// (niente variabili di chiusura, niente side-effect, niente chiamate).
const PROXY_TYPES = new Set(["BinaryExpression", "UnaryExpression", "LogicalExpression", "ConditionalExpression"]);

function returnsSimpleExpr(fnNode) {
  const b = fnNode.body;
  if (!t.isBlockStatement(b) || b.body.length !== 1) return null;
  const ret = b.body[0];
  if (!t.isReturnStatement(ret) || !ret.argument) return null;
  if (!PROXY_TYPES.has(ret.argument.type)) return null;
  return ret.argument;
}

// verifica che l'espressione usi solo i parametri dati (per nome) + letterali/operatori
function usesOnlyParams(expr, paramNames) {
  let ok = true;
  const allowed = new Set(paramNames);
  traverse(
    t.file(t.program([t.expressionStatement(expr)])),
    {
      Identifier(p) {
        // ignora chiavi di membri non-computed (a.b) e nomi non-referenze
        if (p.parentPath.isMemberExpression({ property: p.node }) && !p.parent.computed) return;
        if (!allowed.has(p.node.name)) ok = false;
      },
      CallExpression() { ok = false; },
      // niente assegnamenti/update dentro l'espressione
      AssignmentExpression() { ok = false; },
      UpdateExpression() { ok = false; },
    }
  );
  return ok;
}

const proxies = new Map(); // name -> { params:[...], expr }
traverse(ast, {
  // function NAME(params){return ...}
  FunctionDeclaration(path) {
    const id = path.node.id;
    if (!id) return;
    const expr = returnsSimpleExpr(path.node);
    if (!expr) return;
    const params = path.node.params;
    if (!params.every((p) => t.isIdentifier(p))) return;
    const names = params.map((p) => p.name);
    if (!usesOnlyParams(expr, names)) return;
    const binding = path.scope.getBinding(id.name);
    if (!binding || !binding.constant) return;
    proxies.set(id.name, { params: names, expr, declPath: path });
  },
  // var NAME = function(params){return ...}
  VariableDeclarator(path) {
    const id = path.node.id;
    const init = path.node.init;
    if (!t.isIdentifier(id) || !init || !t.isFunctionExpression(init)) return;
    const expr = returnsSimpleExpr(init);
    if (!expr) return;
    const params = init.params;
    if (!params.every((p) => t.isIdentifier(p))) return;
    const names = params.map((p) => p.name);
    if (!usesOnlyParams(expr, names)) return;
    const binding = path.scope.getBinding(id.name);
    if (!binding || !binding.constant) return;
    proxies.set(id.name, { params: names, expr, declPath: path });
  },
});

console.log(`[proxy] trovati ${proxies.size} proxy di espressione:`);
let shown = 0;
for (const [name, info] of proxies) {
  if (shown++ < 25) {
    const body = generate(info.expr).code;
    console.log(`   ${name}(${info.params.join(",")}) => ${body}`);
  }
}

// --- inlining dei call-site ---
function substitute(expr, params, args) {
  const map = new Map(params.map((p, i) => [p, args[i]]));
  const clone = t.cloneNode(expr, true);
  const file = t.file(t.program([t.expressionStatement(clone)]));
  traverse(file, {
    Identifier(p) {
      if (p.parentPath.isMemberExpression({ property: p.node }) && !p.parent.computed) return;
      if (map.has(p.node.name)) p.replaceWith(t.cloneNode(map.get(p.node.name), true));
    },
  });
  // ritorna l'espressione (dentro parentesi implicite dal tipo)
  return file.program.body[0].expression;
}

let inlined = 0, skipped = 0;
let changed = true, rounds = 0;
while (changed && rounds < 6) {
  changed = false;
  rounds++;
  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      if (!t.isIdentifier(callee)) return;
      const info = proxies.get(callee.name);
      if (!info) return;
      if (path.node.arguments.length !== info.params.length) { skipped++; return; }
      // non inlinare se qualche argomento e' spread
      if (path.node.arguments.some((a) => t.isSpreadElement(a))) { skipped++; return; }
      const repl = substitute(info.expr, info.params, path.node.arguments);
      path.replaceWith(repl);
      inlined++;
      changed = true;
    },
  });
}
console.log(`[inline] chiamate inlinate: ${inlined}  (skip: ${skipped}, round: ${rounds})`);

// rimuovi le dichiarazioni dei proxy ormai inutilizzate
let removed = 0;
for (const [name, info] of proxies) {
  const binding = info.declPath.scope.getBinding(name);
  if (binding && binding.referencePaths.filter((r) => !r.removed).length === 0) {
    try {
      if (t.isVariableDeclarator(info.declPath.node)) info.declPath.remove();
      else info.declPath.remove();
      removed++;
    } catch (e) {}
  }
}
console.log(`[clean] proxy rimossi: ${removed}`);

const out = generate(ast, { comments: false, compact: false }).code;
fs.writeFileSync(OUTPUT, out);
console.log(`[out] ${OUTPUT}  ${out.length} bytes`);
