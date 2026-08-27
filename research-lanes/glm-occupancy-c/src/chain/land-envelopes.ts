/**
 * Land envelope A (100 KB), B (1 MB), and C (chained tape + last-hop pay)
 * on Chipnet, one after another. Not a Core 1p1c package.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { binToHex, decodeTransaction, hash256, hashTransaction, hexToBin } from "@bitauth/libauth";
import { writeI64LE } from "../pool/bytes.ts";
import type { Note } from "../pool/notes.ts";
import { loadLabWallet } from "./wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "./electrum.ts";
import { rpcConfigFromEnv } from "./bchn-rpc.ts";
import { start9NsenterRpc } from "./start9-nsenter-rpc.ts";
import { broadcastSized } from "./broadcast-tx.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "./covenant-spend.ts";
import {
  broadcastChained,
  compileChainedWithdraw,
  compileTapeFunder,
  compileTapeKernelGroups,
  QUERIES_PER_TAPE_HOP,
} from "./chained.ts";
import { tapeTipLockChain, tapeTipLockChainWithRoots } from "./tape-tip.ts";
import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { encodeFriProof, proveFri } from "../backends/circle/fri.ts";
import { mixChangedRootsAndReserve, runMixSuccessor, runBatchSuccessor } from "../pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../pool/state.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "./air-cqz.ts";
import { FRI_QUERIES } from "../backends/circle/params.ts";
import { successorFeeCoinSats, type TxEnvelope } from "./envelope.ts";
import { proofCargoLock } from "./proof-cargo.ts";

export type LandWhich = "standard" | "consensus" | "chained" | "all";

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

export async function broadcastRetry(
  client: Awaited<ReturnType<typeof connectChipnet>>,
  raw: Uint8Array,
  expectedTxid: string,
): Promise<{ txid: string; path: string }> {
  const sent = await broadcastSized({
    raw,
    electrum: async (hex) => {
      let last: Error | undefined;
      for (let i = 0; i < 3; i += 1) {
        try {
          return await broadcast(client, hex);
        } catch (e) {
          last = e instanceof Error ? e : new Error(String(e));
          const msg = last.message.toLowerCase();
          if (
            !msg.includes("missing") &&
            !msg.includes("orphan") &&
            !msg.includes("bad-txns-inputs") &&
            !msg.includes("timed out")
          ) {
            break;
          }
          await sleep(1200 * (i + 1));
        }
      }
      try {
        await getTx(client, expectedTxid);
        return expectedTxid;
      } catch {
        throw last ?? new Error("electrum broadcast failed");
      }
    },
    rpc:
      raw.length > 100_000
        ? process.env.BCHN_RPC_URL
          ? rpcConfigFromEnv()
          : start9NsenterRpc()
        : undefined,
  });
  return sent;
}

export async function waitForTxid(client: Awaited<ReturnType<typeof connectChipnet>>, txid: string): Promise<void> {
  for (let i = 0; i < 12; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1500);
    }
  }
}

function pickFunded(
  utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>,
  need: number,
) {
  const ok = utxos.filter((u) => u.value >= need).sort((a, b) => a.value - b.value);
  return ok[0];
}

async function landAB(
  envelope: "standard" | "consensus",
  slots: number,
  scratch: string,
): Promise<Record<string, unknown>> {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);
  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "connect";
  try {
    step = "listunspent";
    // Genesis change funds the kernels + fee coin. Full-completeness B is now
    // standard-size, so both envelopes use the 100_000 fee coin.
    const need = 400_000;
    const utxos = await listUnspent(client, wallet.address);
    let picked = pickFunded(utxos, need);
    if (!picked) {
      return {
        envelope,
        slots,
        ok: false,
        error: `no funded utxo >= ${need}; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`,
        address: wallet.address,
      };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > need + 50_000) {
      step = "split-off";
      const split = compileTapeFunder({
        wallet,
        utxo: picked,
        tapeSats: BigInt(need),
      });
      prepTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
      await waitForTxid(client, split.txid);
      picked = { tx_hash: split.txid, tx_pos: 0, value: need, height: 0 };
    }
    step = "genesis";
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: mix.oldState,
      proof: mix.proof,
      lockKind: envelope === "consensus" ? "p2s" : "p2sh32",
      envelope,
      slotKernels: slots,
    });
    const genesisTxid = (await broadcastRetry(client, genesis.raw, genesis.txid)).txid;
    await waitForTxid(client, genesisTxid);
    // Below this compileFundVerifierKernels throws at "kernels" instead of here,
    // with prep + genesis already on chain.
    const funderMin = envelope === "consensus" ? 200_000 : 122_532;
    if (genesis.changeValue === undefined || genesis.changeValue < funderMin) {
      return {
        envelope,
        slots,
        ok: false,
        genesis: genesisTxid,
        prep: prepTxid ?? null,
        error: `change too small ${genesis.changeValue} < ${funderMin}`,
      };
    }
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      1_000,
      slots,
      successorFeeCoinSats(envelope),
    );
    const kernelTxid = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
    await waitForTxid(client, kernelTxid);
    step = "successor";
    const successorArgs = {
      wallet,
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(mix.oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(mix.oldState),
      },
      newState: mix.newState,
      proof: mix.proof,
      statement: mix.statement,
      lockKind: envelope === "consensus" ? ("p2s" as const) : ("p2sh32" as const),
      envelope,
      slotKernels: slots,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
      note: mix.spent.note,
      change: mix.witness.created?.note,
    };
    let successor = compileCovenantSuccessor(successorArgs);
    for (let t = 0; t < 24 && successor.txBytes > 100_000; t += 1) {
      const raw = encodeFriProof(proveFri(mix.statement, mix.witness));
      const v2 = circleFriPlugin.verify(mix.statement, raw);
      if (!v2.ok) throw new Error(`reprove: ${v2.reason}`);
      successor = compileCovenantSuccessor({ ...successorArgs, proof: raw });
    }
    if (successor.txBytes > 100_000) {
      throw new Error(`successor unique-table ${successor.txBytes} > 100000 after retries`);
    }
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(scratch, `successor-${envelope}.hex`), binToHex(successor.raw));
    const decoded = decodeTransaction(successor.raw);
    const spent = mix.spent.note;
    const change = mix.witness.created?.note;
    const preimageScan =
      typeof decoded === "string"
        ? { error: decoded }
        : {
            unlockingCount: decoded.inputs.length,
            spentRho: false,
            spentOwner: false,
            spentAmount8: false,
            changeRho: false,
            changeOwner: false,
            changeAmount8: false,
          };
    if (typeof decoded !== "string") {
      const hit = (n: Note, field: "rho" | "ownerSecret" | "amount") => {
        const needle =
          field === "amount" ? Buffer.from(writeI64LE(n.amountSats)).toString("hex") : Buffer.from(n[field]).toString("hex");
        return decoded.inputs.some((i) => Buffer.from(i.unlockingBytecode).toString("hex").includes(needle));
      };
      preimageScan.spentRho = hit(spent, "rho");
      preimageScan.spentOwner = hit(spent, "ownerSecret");
      preimageScan.spentAmount8 = hit(spent, "amount");
      if (change) {
        preimageScan.changeRho = hit(change, "rho");
        preimageScan.changeOwner = hit(change, "ownerSecret");
        preimageScan.changeAmount8 = hit(change, "amount");
      }
    }
    if (
      typeof decoded !== "string" &&
      (preimageScan.spentRho ||
        preimageScan.spentOwner ||
        preimageScan.spentAmount8 ||
        preimageScan.changeRho ||
        preimageScan.changeOwner ||
        preimageScan.changeAmount8)
    ) {
      throw new Error(`preimage still in unlocking: ${JSON.stringify(preimageScan)}`);
    }
    const sent = await broadcastRetry(client, successor.raw, successor.txid);
    return {
      envelope,
      slots,
      ok: true,
      address: wallet.address,
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      kernels: kernelTxid,
      successor: sent.txid,
      txBytes: successor.txBytes,
      unlockingBytes: successor.unlockingBytes,
      preimageScan,
      broadcastPath: sent.path,
      explorer: {
        genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
        kernels: `https://chipnet.imaginary.cash/tx/${kernelTxid}`,
        successor: `https://chipnet.imaginary.cash/tx/${sent.txid}`,
      },
      verify: v,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`${envelope} ${step}: ${msg}`);
  } finally {
    client.close();
  }
}

async function landC(
  hops: number,
  scratch: string,
  /**
   * Option A' (FRI10-BATCH-EXIT.md): spend this many notes in one batch, one
   * note-auth kernel per tape hop. 1 keeps the FRI9 single-note path exactly as
   * it landed on 2026-08-21 - same tip chain, same covenant, same bytes.
   */
  batchNotes = 1,
): Promise<Record<string, unknown>> {
  const tapeHopsC = Math.ceil(FRI_QUERIES / QUERIES_PER_TAPE_HOP);
  if (batchNotes < 1 || batchNotes > tapeHopsC) {
    throw new Error(`batchNotes ${batchNotes} must be in 1..${tapeHopsC} (one per tape hop)`);
  }
  const batched =
    batchNotes > 1
      ? runBatchSuccessor({ depositCount: Math.max(6, batchNotes), noteCount: batchNotes })
      : undefined;
  const mix = batched ? undefined : runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  if (mix && !mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
  const oldState = batched ? batched.oldState : mix!.oldState;
  const newState = batched ? batched.newState : mix!.newState;
  const statement = batched ? batched.statement : mix!.statement;
  const proof = batched ? batched.proof : mix!.proof;
  // R_0..R_tapeHops. Hops past the notes hold the root still, so the terminal
  // value is the new state's root either way.
  const roots = batched ? [...batched.roots] : [];
  while (batched && roots.length < tapeHopsC + 1) roots.push(roots[roots.length - 1]!);
  const v = circleFriPlugin.verify(statement, proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);
  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "connect";
  try {
    step = "listunspent";
    // Genesis change has to clear tape (300000) + fee (2000) + the kernel funder
    // (19 kernels x 1000 + 100546 miner pad + 3520 fee + dust = 123612), on top of
    // the 44000 pool output. 400000 left the funder at 52800 and threw at "kernels"
    // with prep + genesis + split already on chain.
    const need = 700_000;
    const utxos = await listUnspent(client, wallet.address);
    let picked = pickFunded(utxos, need);
    if (!picked) {
      return {
        envelope: "chained",
        ok: false,
        error: `no funded utxo >= ${need}; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`,
        address: wallet.address,
      };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > need + 50_000) {
      step = "split-off";
      const split = compileTapeFunder({
        wallet,
        utxo: picked,
        tapeSats: BigInt(need),
      });
      prepTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
      await waitForTxid(client, split.txid);
      picked = { tx_hash: split.txid, tx_pos: 0, value: need, height: 0 };
    }
    step = "genesis";
    // Genesis is the CashToken category genesis, so it can mint the tape sibling
    // NFTs directly - no minting-capability token needed. They hold the OLD PAA1.
    const tapeHops = Math.ceil(FRI_QUERIES / QUERIES_PER_TAPE_HOP);
    // The pool covenant pins the terminal tip lock, and genesis commits the pool
    // covenant, so the digest has to be known here - before genesis, not at the
    // tape-funder step.
    //
    // hash256 of the WHOLE proof, not proof.slice(0, 32). The prefix is 4 constant
    // bytes + grindNonce + the first 24 bytes of traceRoot: statement-binding, but
    // truncated to ~2^96. Hashing commits to every layer root, query and auth.
    const tapeDigest = hash256(proof);
    // Under a batch each tip also pins its hop's output root, so a hop cannot
    // publish a root its note-auth kernel did not produce.
    const tipChain = batched
      ? tapeTipLockChainWithRoots(tapeDigest, roots.slice(1))
      : tapeTipLockChain(tapeDigest, tapeHops);
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: oldState,
      proof,
      lockKind: "p2sh32",
      envelope: "standard",
      slotKernels: SLOT_KERNEL_COUNT,
      // The pay hop carries a note-auth kernel at 4 slots, so the pool lock has to
      // expect it. The lock is committed here, at genesis. Under a batch the hops
      // carry the kernels instead and the pay hop carries none, so this flips.
      forceNoteAuth: !batched,
      tapeTipLock: tipChain[tapeHops],
      // Genesis is the only place the landing root can be committed, because the
      // covenant is what the pool NFT is locked to.
      finalNfRoot: batched ? roots[tapeHops] : undefined,
      siblingNfts: {
        count: tapeHops,
        lockingBytecode: proofCargoLock(),
        // Sibling g carries R_g, so hop g can advance it one step.
        commitments: batched
          ? Array.from({ length: tapeHops }, (_, g) =>
              encodePublicPaa1({ ...oldState, nullifierRoot: roots[g]! }),
            )
          : undefined,
      },
    });
    const genesisTxid = (await broadcastRetry(client, genesis.raw, genesis.txid)).txid;
    await waitForTxid(client, genesisTxid);
    const tapeCarriers = Array.from({ length: tapeHops }, (_, g) => ({
      tx_hash: genesisTxid,
      tx_pos: 2 + g,
      value: 1_000,
    }));
    // 300000 tape + 2000 fee + 123612 kernel funder. Below this the run dies at
    // "kernels" instead of here, after the tape split is already broadcast.
    if (genesis.changeValue === undefined || genesis.changeValue < 425_612) {
      return { envelope: "chained", ok: false, genesis: genesisTxid, error: `change too small ${genesis.changeValue}` };
    }
    step = "tape-funder";
    // The tape head must be L(digest, 0) or hop 0 cannot spend it.
    const split = compileTapeFunder({
      wallet,
      utxo: { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      tapeSats: 300_000n,
      tapeLockingBytecode: tipChain[0],
    });
    const splitTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
    await waitForTxid(client, split.txid);
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      split.funderUtxo,
      1_000,
      SLOT_KERNEL_COUNT,
      successorFeeCoinSats("standard"),
      true,
    );
    const kernelTxid = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
    await waitForTxid(client, kernelTxid);
    // Every tape hop needs its own kernels. Without these compileChainedWithdraw
    // falls back to dummy prevouts (44../aa..) and the chain is unbroadcastable.
    step = "tape-kernels";
    const tapeNeed = 2_400_000;
    const tapePick = pickFunded(await listUnspent(client, wallet.address), tapeNeed);
    if (!tapePick) {
      return {
        envelope: "chained",
        ok: false,
        genesis: genesisTxid,
        error: `no funded utxo >= ${tapeNeed} for ${tapeHops} tape kernel groups`,
        address: wallet.address,
      };
    }
    const tapeGroups = compileTapeKernelGroups({
      wallet,
      utxo: tapePick,
      tapeHops,
      carriers: tapeCarriers,
    });
    const tapeKernelsTxid = (await broadcastRetry(client, tapeGroups.raw, tapeGroups.txid)).txid;
    await waitForTxid(client, tapeGroups.txid);

    step = "compile-chain";
    const chain = compileChainedWithdraw({
      wallet,
      tapeKernels: tapeGroups.groups,
      tapeUtxo: split.tapeUtxo,
      hops,
      digest: tapeDigest,
      proof,
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(oldState),
      },
      newState,
      statement,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
      note: batched ? undefined : mix!.spent.note,
      change: batched ? undefined : mix!.witness.created?.note,
      ...(batched ? { batch: { spends: batched.spends, roots } } : {}),
    });
    mkdirSync(scratch, { recursive: true });
    for (const hop of chain.hops) {
      writeFileSync(join(scratch, `chained-hop-${hop.index}-${hop.role}.hex`), binToHex(hop.raw));
    }
    step = "broadcast-chain";
    const sent = await broadcastChained({
      hops: chain.hops,
      electrum: async (hex) => {
        // Same shape as broadcastRetry, including its getTx fallback: a timed-out
        // broadcast is not proof of rejection, and aborting here costs the whole
        // 19-hop chain.
        //
        // One FRESH connection per hop. The shared `client` has been open for
        // minutes doing proving and small broadcasts by the time the chain starts,
        // and an 83 KB frame on it times out every time - while the identical tx
        // goes through instantly on a new socket. That cost three full runs.
        const expectedTxid = hashTransaction(hexToBin(hex));
        let last: Error | undefined;
        for (let i = 0; i < 3; i += 1) {
          const hopClient = await connectChipnet();
          try {
            return await broadcast(hopClient, hex);
          } catch (e) {
            last = e instanceof Error ? e : new Error(String(e));
            const msg = last.message.toLowerCase();
            if (
              !msg.includes("missing") &&
              !msg.includes("orphan") &&
              !msg.includes("bad-txns-inputs") &&
              !msg.includes("timed out")
            ) {
              break;
            }
            await sleep(1200 * (i + 1));
          } finally {
            hopClient.close();
          }
        }
        const check = await connectChipnet();
        try {
          await getTx(check, expectedTxid);
          return expectedTxid;
        } catch {
          throw last ?? new Error("electrum broadcast failed");
        } finally {
          check.close();
        }
      },
      rpc: chain.hops.some((h) => h.raw.length > 100_000) ? rpcConfigFromEnv() : undefined,
    });
    const pay = sent[sent.length - 1]!;
    return {
      envelope: "chained",
      ok: true,
      address: wallet.address,
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      tapeFunder: splitTxid,
      tapeKernels: tapeKernelsTxid,
      kernels: kernelTxid,
      hops: sent,
      shape: {
        hopBytes: chain.hops.map((h) => ({ index: h.index, role: h.role, txBytes: h.txBytes, payoutCount: h.payoutCount })),
        totalBytes: chain.totalBytes,
        payIndex: chain.payIndex,
      },
      successor: pay.txid,
      explorer: {
        genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
        pay: `https://chipnet.imaginary.cash/tx/${pay.txid}`,
      },
      verify: v,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`chained ${step}: ${msg}`);
  } finally {
    client.close();
  }
}

export async function landChipnetEnvelopes(args: {
  which: LandWhich;
  hops: number;
  scratch: string;
}): Promise<Record<string, unknown>> {
  mkdirSync(args.scratch, { recursive: true });
  const report: Record<string, unknown> = {
    network: "chipnet",
    started: new Date().toISOString(),
    which: args.which,
    slotKernelsStandard: SLOT_KERNEL_COUNT,
    slotKernelsConsensus: SLOT_KERNEL_COUNT_CONSENSUS,
    chainedHops: args.hops,
    scenarios: {} as Record<string, unknown>,
  };
  const scenarios = report.scenarios as Record<string, unknown>;
  const run = async (name: string, fn: () => Promise<Record<string, unknown>>) => {
    try {
      scenarios[name] = await fn();
    } catch (e) {
      scenarios[name] = { envelope: name, ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  };
  if (args.which === "all" || args.which === "standard") {
    await run("standard", () => landAB("standard", SLOT_KERNEL_COUNT, args.scratch));
  }
  if (args.which === "all" || args.which === "consensus") {
    await run("consensus", () => landAB("consensus", SLOT_KERNEL_COUNT_CONSENSUS, args.scratch));
  }
  if (args.which === "all" || args.which === "chained") {
    await run("chained", () => landC(args.hops, args.scratch));
  }
  report.finished = new Date().toISOString();
  writeFileSync(join(args.scratch, "chipnet-land.log"), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

export type { TxEnvelope };
