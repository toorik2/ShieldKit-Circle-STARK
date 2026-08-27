/** Compile the consensus chain locally and write hex files. No keys. No broadcast. */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { connectChipnet, listUnspent } from "../src/chain/electrum.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  compileSelfSendVout0,
} from "../src/chain/covenant-spend.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { successorFeeCoinSats } from "../src/chain/envelope.ts";
import { foldKernelCount } from "../src/chain/fold-kernel.ts";

const out = process.argv[2];
if (!out) throw new Error("usage: dump-consensus-raw <successor.hex>");

const dir = dirname(out);
mkdirSync(dir, { recursive: true });

const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
const v = circleFriPlugin.verify(mix.statement, mix.proof);
if (!v.ok) throw new Error(`verify: ${v.reason}`);
const wallet = await loadLabWallet();
const client = await connectChipnet();
try {
  const utxos = await listUnspent(client, wallet.address);
  let picked =
    utxos.find((u) => u.tx_pos === 0 && u.value > 200_000) ??
    utxos.find((u) => u.value > 200_000);
  if (!picked) {
    throw new Error(`no funded utxo; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`);
  }
  const files: Record<string, string> = {};
  let prepTxid: string | null = null;
  if (picked.tx_pos !== 0) {
    const prep = compileSelfSendVout0(wallet, picked);
    const prepPath = join(dir, "prep.hex");
    writeFileSync(prepPath, binToHex(prep.raw));
    files.prep = prepPath;
    prepTxid = prep.txid;
    picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
  }
  const genesis = compileCovenantSpend({
    wallet,
    utxo: picked,
    state: mix.oldState,
    proof: mix.proof,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  });
  const genesisPath = join(dir, "genesis.hex");
  writeFileSync(genesisPath, binToHex(genesis.raw));
  files.genesis = genesisPath;
  if (genesis.changeValue === undefined || genesis.changeValue < 200_000) {
    throw new Error(`change too small ${genesis.changeValue}`);
  }
  const funded = compileFundVerifierKernels(
    wallet,
    { tx_hash: genesis.txid, tx_pos: 1, value: genesis.changeValue },
    1_000,
    SLOT_KERNEL_COUNT_CONSENSUS,
    successorFeeCoinSats("consensus"),
  );
  const kernelsPath = join(dir, "kernels.hex");
  writeFileSync(kernelsPath, binToHex(funded.raw));
  files.kernels = kernelsPath;
  const successor = compileCovenantSuccessor({
    wallet,
    feeUtxo: { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue },
    pool: {
      tx_hash: genesis.txid,
      tx_pos: 0,
      value: utxoValueFor(mix.oldState),
      category: hexToBin(picked.tx_hash),
      commitment: encodePublicPaa1(mix.oldState),
    },
    newState: mix.newState,
    proof: mix.proof,
    statement: mix.statement,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
    kernelUtxos: funded.fri,
    extraKernels: funded.extra,
    note: mix.spent.note,
    change: mix.witness.created?.note,
  });
  writeFileSync(out, binToHex(successor.raw));
  files.successor = out;
  const meta = {
    network: "chipnet",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
    foldKernels: foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS),
    prep: prepTxid,
    genesis: genesis.txid,
    kernels: funded.txid,
    successor: successor.txid,
    txBytes: successor.txBytes,
    unlockingBytes: successor.unlockingBytes,
    hexPath: out,
    files,
    verify: v,
  };
  writeFileSync(join(dir, "consensus-meta.json"), `${JSON.stringify(meta, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(meta, null, 2)}\n`);
} finally {
  client.close();
}
