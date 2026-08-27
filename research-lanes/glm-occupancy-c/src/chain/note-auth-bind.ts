import { commitAmount } from "../amounts/hash-commit.ts";
import { concatBytes, sha256, ZERO32 } from "../pool/bytes.ts";
import { commitNote, nullifierOf, type Note } from "../pool/notes.ts";
import type { PoolStatement } from "../pool/statement.ts";
import type { FriAuth } from "../backends/circle/air.ts";

export type NoteAuthOpens = {
  leaf: Uint8Array;
  nf: Uint8Array;
  amountCommit: Uint8Array;
  createdLeaf: Uint8Array;
};

/** SHA256(leaf || nf || amountCommit || createdLeaf). Matches OP_SHA256. */
export function noteAuthBindHash(args: NoteAuthOpens): Uint8Array {
  return sha256(concatBytes(args.leaf, args.nf, args.amountCommit, args.createdLeaf));
}

export function noteAuthPublicOpens(args: {
  note: Note;
  change?: Note;
  action: "DEPOSIT" | "WITHDRAW";
  poolInstanceId: Uint8Array;
}): NoteAuthOpens {
  const leaf = commitNote(args.note);
  const amountCommit = commitAmount(args.note.amountSats, args.note.rho);
  if (args.action === "DEPOSIT") {
    return { leaf, nf: new Uint8Array(ZERO32), amountCommit, createdLeaf: leaf };
  }
  return {
    leaf,
    nf: nullifierOf(args.note, args.poolInstanceId),
    amountCommit,
    createdLeaf: args.change ? commitNote(args.change) : new Uint8Array(ZERO32),
  };
}

/** Same tuple encodeAirPacked / proveFri grind seed use. */
export function noteAuthOpensFromStatement(statement: PoolStatement, auth: FriAuth): NoteAuthOpens {
  const amt =
    statement.action === "DEPOSIT" ? statement.amountCommitOut : statement.amountCommitIn;
  const spentLeaf = auth.leaf.length === 32 ? auth.leaf : statement.noteCommitment;
  const createdLeaf =
    statement.action === "DEPOSIT"
      ? statement.noteCommitment
      : auth.createdLeaf.length === 32
        ? auth.createdLeaf
        : new Uint8Array(ZERO32);
  return {
    leaf: statement.action === "DEPOSIT" ? statement.noteCommitment : spentLeaf,
    nf: statement.nullifier,
    amountCommit: amt.length === 32 ? amt : new Uint8Array(ZERO32),
    createdLeaf,
  };
}

export function noteAuthBindFromStatement(statement: PoolStatement, auth: FriAuth): Uint8Array {
  return noteAuthBindHash(noteAuthOpensFromStatement(statement, auth));
}
