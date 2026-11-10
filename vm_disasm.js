'use strict';
// Disassembler del dispatcher control-flow-flattening `sL` dello script Akamai.
// Step 1-2 del metodo: trova il dispatcher nell'AST, enumera i case dello switch,
// risolve i valori-stato delle label, stampa le semantiche di ogni blocco.
//
// Uso:
//   node vm_disasm.js                 # riassunto: #case, label risolte, primi N case
//   node vm_disasm.js --all           # tutti i case (puo' essere lungo)
//   node vm_disasm.js --func sL       # scegli la funzione dispatcher (default sL)
//   node vm_disasm.js --case <N>      # dump completo del case N

const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;

const args = process.argv.slice(2);
const FN = (args.includes('--func') ? args[args.indexOf('--func') + 1] : 'sL');
const ALL = args.includes('--all');
const CASE = args.includes('--case') ? parseInt(args[args.indexOf('--case') + 1], 10) : null;

const code = fs.readFileSync('current_script.js', 'utf8');
const ast = parser.parse(code, { errorRecovery: true });

// 1) trova la funzione dispatcher
let fnPath = null;
traverse(ast, {
  FunctionDeclaration(p) { if (p.node.id && p.node.id.name === FN) fnPath = p; },
  FunctionExpression(p) { if (p.node.id && p.node.id.name === FN) fnPath = p; },
});
if (!fnPath) { console.log(`funzione ${FN} non trovata`); process.exit(1); }

// 2) trova lo switch del dispatcher (il primo/piu' grande dentro la funzione)
let sw = null;
fnPath.traverse({ SwitchStatement(p) { if (!sw || p.node.cases.length > sw.cases.length) sw = p.node; } });
if (!sw) { console.log('nessuno switch dentro ' + FN); process.exit(1); }

// label dei case (identificatori) -> risolvi i valori numerici cercando le var in tutto l'AST
const labelNames = new Set();
for (const c of sw.cases) if (c.test && c.test.type === 'Identifier') labelNames.add(c.test.name);
const vals = {};
traverse(ast, {
  VariableDeclarator(p) {
    const id = p.node.id, init = p.node.init;
    if (id && id.type === 'Identifier' && labelNames.has(id.name) && init) {
      if (init.type === 'NumericLiteral') vals[id.name] = init.value;
      else if (init.type === 'UnaryExpression' && init.operator === '-' && init.argument.type === 'NumericLiteral') vals[id.name] = -init.argument.value;
    }
  },
});

function labelOf(c) {
  if (!c.test) return 'default';
  const src = generate(c.test).code;
  if (c.test.type === 'Identifier' && vals[c.test.name] !== undefined) return `${src}(=${vals[c.test.name]})`;
  return src;
}
function bodyOf(c, max) {
  const b = c.consequent.map((n) => generate(n).code).join(' ').replace(/\s+/g, ' ');
  return max ? b.slice(0, max) : b;
}

if (CASE !== null) {
  const c = sw.cases[CASE];
  console.log(`[case ${CASE}] ${labelOf(c)}:`);
  console.log(bodyOf(c));
  process.exit(0);
}

console.log(`dispatcher: ${FN}`);
console.log(`#case: ${sw.cases.length}`);
console.log(`label identificatori: ${labelNames.size}, risolte a numero: ${Object.keys(vals).length}`);
const n = ALL ? sw.cases.length : Math.min(12, sw.cases.length);
for (let i = 0; i < n; i++) {
  console.log(`\n[case ${i}] ${labelOf(sw.cases[i])}: ${bodyOf(sw.cases[i], 260)}`);
}
if (!ALL && sw.cases.length > n) console.log(`\n... (${sw.cases.length - n} case restanti; usa --all o --case N)`);
