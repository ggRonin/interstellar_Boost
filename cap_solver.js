// Решатель капчи Cap.js (format 2) для interstellar.dachain.io — без браузера.
//   node --permission cap_solver.js < input.json > solutions.json
// input:  {"challenges": [...] из /challenge, "hashwx": "<base64 hashwx.wasm>", "env": {...}}
// output: {"solutions": [...]} — тело для /redeem вместе с token.
//
// hashwx      — proof-of-work: тот же алгоритм, что в воркере виджета (wasm-модуль сайта).
// instrumentation — проверка окружения: присланный скрипт исполняется в vm на заглушках браузера
//                   (cap_env.js); он сам считает значения, мы их только передаём.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const { runInstrumentation } = require('./cap_env');

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

// ── hashwx ─────────────────────────────────────────────────────────────────
function makeHashwx(module) {
  const w = new WebAssembly.Instance(module, {}).exports;
  if (w._initialize) w._initialize();
  let compiled = true;
  let ctx = w.hashwx_alloc(1);
  if (ctx === -1 || ctx === 0) {
    compiled = false;
    ctx = w.hashwx_alloc(0);
  }
  if (ctx <= 0) throw new Error('hashwx_alloc failed');
  return {
    w, ctx, compiled,
    seedPtr: w.hashwx_seed(ctx),
    regPtr: compiled ? w.hashwx_registers(ctx) : 0,
    memPtr: compiled ? w.hashwx_memory(ctx) : 0,
  };
}

function solveHashwx(hx, { c, d, n }) {
  if (!/^[0-9a-f]{64}$/i.test(c) || !Number.isInteger(d) || d < 1 || !Number.isInteger(n) || n < 1) {
    throw new Error('malformed hashwx challenge payload');
  }
  const { w, ctx, compiled, seedPtr, regPtr, memPtr } = hx;
  const per = n >>> 0;
  const limit = ((1n << 64n) - 1n) / BigInt(d);
  const input = Buffer.alloc(40);
  Buffer.from(c, 'hex').copy(input, 0);
  for (let prog = 0; ; prog++) {
    input.writeBigUInt64LE(BigInt(prog), 32);
    new Uint8Array(w.memory.buffer, seedPtr, 32).set(sha256(input));
    w.hashwx_make(ctx, seedPtr);
    let exec = null;
    if (compiled) {
      const ptr = w.hashwx_module(ctx);
      const size = w.hashwx_module_size(ctx);
      const bytes = new Uint8Array(w.memory.buffer, ptr, size).slice();
      exec = new WebAssembly.Instance(new WebAssembly.Module(bytes), { env: { memory: w.memory } }).exports.exec;
    }
    const base = BigInt(prog) * BigInt(per);
    for (let i = 0; i < per; i++) {
      const nonce = base + BigInt(i);
      let h;
      if (compiled) {
        w.hashwx_exec_begin(ctx, nonce);
        exec(regPtr, memPtr);
        h = BigInt.asUintN(64, w.hashwx_exec_final(ctx));
      } else {
        h = BigInt.asUintN(64, w.hashwx_exec(ctx, nonce));
      }
      if (h <= limit) return nonce.toString();
    }
  }
}

// ── вход/выход ────────────────────────────────────────────────────────────
async function main() {
  // stdin читаем синхронно: с открытым потоком stdin onload в vm-контексте не доходит до конца
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const challenges = input.challenges;
  if (!Array.isArray(challenges)) throw new Error('challenges: ждали массив');

  let hx = null;
  const solutions = new Array(challenges.length);
  for (let i = 0; i < challenges.length; i++) {
    const ch = challenges[i];
    if (ch.protocol === 'hashwx') {
      if (!hx) hx = makeHashwx(new WebAssembly.Module(Buffer.from(input.hashwx, 'base64')));
      solutions[i] = { nonce: solveHashwx(hx, ch.payload) };
    } else if (ch.protocol === 'instrumentation') {
      const code = zlib.inflateRawSync(Buffer.from(ch.payload.blob, 'base64')).toString('utf8');
      const r = await runInstrumentation(code, input.env || {});
      solutions[i] = r.timeout ? { timeout: true } : r.blocked ? { blocked: true } : { instr: r.result };
    } else {
      throw new Error(`протокол ${ch.protocol} не поддерживается`);
    }
  }
  process.stdout.write(JSON.stringify({ solutions }));
}

main().then(() => process.exit(0), (e) => {
  process.stderr.write(String((e && e.stack) || e));
  process.exit(1);
});
