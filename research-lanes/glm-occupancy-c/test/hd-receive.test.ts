import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertFreshPayoutAddress,
  createLabHd,
  deriveReceiveWallet,
  HD_RECEIVE_PATH_PREFIX,
  nextReceive,
} from "../src/chain/hd-receive.ts";

describe("HD receive chain (XO P2PKH, no reuse)", () => {
  it("each nextReceive is a new bchtest address on m/44'/145'/0'/0/i", () => {
    const seed = new Uint8Array(64).fill(7);
    let hd = createLabHd(seed);
    assert.equal(HD_RECEIVE_PATH_PREFIX, "m/44'/145'/0'/0");
    const a = nextReceive(hd);
    const b = nextReceive(a.hd);
    assert.match(a.wallet.address, /^bchtest:/);
    assert.match(b.wallet.address, /^bchtest:/);
    assert.notEqual(a.wallet.address, b.wallet.address);
    assert.equal(b.hd.receiveIndex, 2);
    assert.deepEqual(b.hd.usedAddresses, [a.wallet.address, b.wallet.address]);
    const again = deriveReceiveWallet(createLabHd(seed), 0);
    assert.equal(again.address, a.wallet.address);
    assert.throws(() => assertFreshPayoutAddress(a.wallet.address, b.hd.usedAddresses), /reuse/);
  });
});
