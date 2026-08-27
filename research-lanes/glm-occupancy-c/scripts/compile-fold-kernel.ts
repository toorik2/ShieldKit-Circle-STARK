import { compileFoldKernel } from "../src/chain/fold-kernel.ts";
try {
  const k = compileFoldKernel(0, 6);
  console.log(JSON.stringify({ ok: true, bytes: k.length }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, err: e instanceof Error ? e.message.slice(0, 400) : String(e) }));
  process.exitCode = 1;
}
