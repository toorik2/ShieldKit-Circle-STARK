#!/usr/bin/env bash
set -euo pipefail

lane_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cache_root=${V17_BCHN_ASSAY_CACHE:-"${lane_root}/.local/bchn-v29-assay"}
binary="${cache_root}/build/bin/v17-bchn-v29-assay"
stamp="${cache_root}/built.stamp"
if [[ ! -x "$binary" || ! -f "$stamp" || \
      "${lane_root}/tools/bchn-v29-assay/bchn_v29_assay.cpp" -nt "$stamp" || \
      "${lane_root}/tools/bchn-v29-assay/inject.cmake" -nt "$stamp" ]]; then
  binary=$("${lane_root}/scripts/build-bchn-v29-assay.sh" | tail -n 1)
fi

# BCHN v29.0.0 VMB vector 67am0u, input 1. Its one-byte OP_DEFINE body
# distinguishes BCHN's activated cost (803) from libauth next.8's cost (802).
transaction=020000000201000000000000000000000000000000000000000000000000000000000000000000000064417dfb529d352908ee0a88a0074c216b09793d6aa8c94c7640bb4ced51eaefc75d0aef61f7685d0307491e2628da3d4f91e86329265a4a58ca27a41ec0b8910779c32103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7850000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000100000000000000000a6a08766d625f7465737400000000
source_outputs=0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac10270000000000000801000089008a0087

result=$("$binary" \
  --transaction "$transaction" \
  --source-outputs "$source_outputs" \
  --input-index 1 \
  --mode standard)

python3 - "$result" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
assert result["engine"] == "bchn"
assert result["engineVersion"] == "29.0.0"
assert result["scope"] == "script-input-only"
assert result["mode"] == "standard"
assert result["valid"] is True
assert result["metricsReliable"] is True
assert result["metrics"]["baseOpCost"] == 803
assert result["metrics"]["compositeOpCost"] == 803
assert result["metrics"]["opCostLimit"] == 32800
assert result["metrics"]["hashDigestIterations"] == 0
assert result["metrics"]["sigChecksInputLimit"] == 1
assert result["metrics"]["sigChecksTransactionLimit"] == 3000
print(json.dumps(result, separators=(",", ":")))
PY

# BCHN VMB vector a9k5xz, input 1: the active P2SH script introspects
# input 0's locking bytecode, whose serialized source output carries a
# CashToken prefix. This catches accidental use of BCHN's limited context.
token_transaction=0200000002010000000000000000000000000000000000000000000000000000000000000000000000025100000000000100000000000000000000000000000000000000000000000000000000000000010000001c17a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb870300c7870000000002e80300000000000039ef020000000000000000000000000000000000000000000000000000000000000020a9148756772161ff4b37f5047eb8fec993a67bb25cbf87e80300000000000039ef020000000000000000000000000000000000000000000000000000000000000020a9148756772161ff4b37f5047eb8fec993a67bb25cbf8700000000
token_source_outputs=02102700000000000039ef020000000000000000000000000000000000000000000000000000000000000020a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87102700000000000039ef020000000000000000000000000000000000000000000000000000000000000020a9148756772161ff4b37f5047eb8fec993a67bb25cbf87

token_result=$("$binary" \
  --transaction-file <(printf '%s\n' "$token_transaction") \
  --source-outputs-file <(printf '%s\n' "$token_source_outputs") \
  --input-index 1 \
  --mode consensus)

python3 - "$token_result" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
assert result["valid"] is True
assert result["mode"] == "consensus"
assert result["inputCount"] == 2
assert result["sourceOutputCount"] == 2
assert result["sourceOutputsBytes"] == 133
assert result["metrics"]["baseOpCost"] == 891
assert result["metrics"]["compositeOpCost"] == 1019
assert result["metrics"]["hashDigestIterations"] == 2
assert result["metrics"]["hashDigestIterationsLimit"] == 241
assert result["metrics"]["sigChecksInputLimit"] is None
assert result["metrics"]["sigChecksTransactionLimit"] == 3000
print(json.dumps(result, separators=(",", ":")))
PY
