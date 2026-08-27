import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";
for (let i = 0; i < 7; i += 1) {
  const k = compileFriQueryKernel(i);
  console.log("layer", i, "redeem", k.length);
}
