// Offline BCHN v29.0.0 script-input assay for Sealed Creation Log v17.
//
// This adapter intentionally uses BCHN's internal full-context script API.
// It does not start a node, call RPC, inspect a chain, or perform transaction-
// level policy/token validation.

#include <policy/policy.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>
#include <version.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kBchnVersion = "29.0.0";
constexpr std::string_view kBchnTagCommit =
    "89a591f7c5b1fd110c0819377ad8f2647d656800";

// This is GetNextBlockScriptFlags after every pre-2027 upgrade represented in
// BCHN v29.0.0 is active. Keep this list source-readable: a generic "mandatory"
// policy constant omits several height-gated consensus flags.
constexpr uint32_t kMay2026ConsensusFlags =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_SIGPUSHONLY |
    SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_NULLFAIL | SCRIPT_ENABLE_SIGHASH_FORKID |
    SCRIPT_ENABLE_SCHNORR_MULTISIG | SCRIPT_ENFORCE_SIGCHECKS |
    SCRIPT_64_BIT_INTEGERS | SCRIPT_NATIVE_INTROSPECTION |
    SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS |
    SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026;

constexpr uint32_t kMay2026StandardFlags =
    kMay2026ConsensusFlags | STANDARD_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VM_LIMITS_STANDARD;

struct Arguments {
    std::string transactionHex;
    std::string sourceOutputsHex;
    unsigned inputIndex{};
    bool standard{};
};

[[noreturn]] void UsageError(const std::string &message) {
    throw std::invalid_argument(
        message +
        "\nusage: v17-bchn-v29-assay "
        "(--transaction HEX|--transaction-file HEX_FILE) "
        "(--source-outputs HEX|--source-outputs-file HEX_FILE) "
        "--input-index N [--mode consensus|standard]");
}

std::string ReadHexFile(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        UsageError("cannot open hex file: " + path);
    }
    std::string result{std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>()};
    result.erase(
        std::remove_if(result.begin(), result.end(), [](unsigned char byte) {
            return std::isspace(byte) != 0;
        }),
        result.end());
    return result;
}

unsigned ParseInputIndex(const std::string &text) {
    if (text.empty()) {
        UsageError("empty input index");
    }
    std::size_t consumed{};
    const auto parsed = std::stoull(text, &consumed, 10);
    if (consumed != text.size() ||
        parsed > std::numeric_limits<unsigned>::max()) {
        UsageError("invalid input index: " + text);
    }
    return static_cast<unsigned>(parsed);
}

Arguments ParseArguments(int argc, char **argv) {
    Arguments result;
    bool haveTransaction = false;
    bool haveSourceOutputs = false;
    bool haveInputIndex = false;
    std::string mode = "consensus";

    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        auto next = [&]() -> std::string {
            if (++i >= argc) {
                UsageError("missing value for " + option);
            }
            return argv[i];
        };
        if (option == "--transaction") {
            if (haveTransaction) UsageError("transaction was specified twice");
            result.transactionHex = next();
            haveTransaction = true;
        } else if (option == "--transaction-file") {
            if (haveTransaction) UsageError("transaction was specified twice");
            result.transactionHex = ReadHexFile(next());
            haveTransaction = true;
        } else if (option == "--source-outputs") {
            if (haveSourceOutputs) UsageError("source outputs were specified twice");
            result.sourceOutputsHex = next();
            haveSourceOutputs = true;
        } else if (option == "--source-outputs-file") {
            if (haveSourceOutputs) UsageError("source outputs were specified twice");
            result.sourceOutputsHex = ReadHexFile(next());
            haveSourceOutputs = true;
        } else if (option == "--input-index") {
            if (haveInputIndex) UsageError("input index was specified twice");
            result.inputIndex = ParseInputIndex(next());
            haveInputIndex = true;
        } else if (option == "--mode") {
            mode = next();
        } else if (option == "--help" || option == "-h") {
            std::cout
                << "usage: v17-bchn-v29-assay "
                   "(--transaction HEX|--transaction-file HEX_FILE) "
                   "(--source-outputs HEX|--source-outputs-file HEX_FILE) "
                   "--input-index N "
                   "[--mode consensus|standard]\n";
            std::exit(EXIT_SUCCESS);
        } else {
            UsageError("unknown option: " + option);
        }
    }

    if (!haveTransaction || !haveSourceOutputs || !haveInputIndex) {
        UsageError("transaction, source outputs, and input index are required");
    }
    if (mode != "consensus" && mode != "standard") {
        UsageError("mode must be consensus or standard");
    }
    result.standard = mode == "standard";
    return result;
}

std::vector<uint8_t> ParseStrictHex(const std::string &hex,
                                    const char *label) {
    if (hex.empty() || hex.size() % 2 != 0 || !IsHex(hex)) {
        UsageError(std::string(label) + " must be nonempty even-length hex");
    }
    return ParseHex(hex);
}

std::string JsonEscape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8);
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (byte < 0x20) {
                constexpr char digits[] = "0123456789abcdef";
                result += "\\u00";
                result += digits[byte >> 4];
                result += digits[byte & 0x0f];
            } else {
                result += static_cast<char>(byte);
            }
        }
    }
    return result;
}

template <typename T>
T DecodeExactly(const std::vector<uint8_t> &bytes, const char *label) {
    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
    T result;
    stream >> result;
    if (!stream.empty()) {
        throw std::runtime_error(std::string(label) +
                                 " has trailing serialized bytes");
    }
    return result;
}

void PrintNullableMetric(const char *name, const int64_t *value) {
    std::cout << "\"" << name << "\":";
    if (value == nullptr) {
        std::cout << "null";
    } else {
        std::cout << *value;
    }
}

int Run(const Arguments &args) {
    const auto transactionBytes =
        ParseStrictHex(args.transactionHex, "transaction");
    const auto sourceOutputBytes =
        ParseStrictHex(args.sourceOutputsHex, "source outputs");

    auto mutableTransaction =
        DecodeExactly<CMutableTransaction>(transactionBytes, "transaction");
    auto sourceOutputs = DecodeExactly<std::vector<CTxOut>>(
        sourceOutputBytes, "source outputs");

    if (mutableTransaction.vin.empty()) {
        throw std::runtime_error("transaction has no inputs");
    }
    if (sourceOutputs.size() != mutableTransaction.vin.size()) {
        throw std::runtime_error(
            "source-output count does not equal transaction input count");
    }
    if (args.inputIndex >= mutableTransaction.vin.size()) {
        throw std::runtime_error("input index is out of range");
    }

    const CTransaction transaction(std::move(mutableTransaction));
    std::vector<PSBTInput> psbtInputs(sourceOutputs.size());
    for (std::size_t i = 0; i < sourceOutputs.size(); ++i) {
        psbtInputs[i].utxo = std::move(sourceOutputs[i]);
    }

    const auto contexts = ScriptExecutionContext::createForAllInputs(
        transaction, psbtInputs);
    const auto &context = contexts.at(args.inputIndex);
    const PrecomputedTransactionData transactionData(context);
    const TransactionSignatureChecker checker(context, transactionData);
    const uint32_t flags = args.standard ? kMay2026StandardFlags
                                         : kMay2026ConsensusFlags;

    ScriptExecutionMetrics metrics;
    ScriptError scriptError = ScriptError::UNKNOWN;
    const bool valid = VerifyScript(context.scriptSig(),
                                    context.coinScriptPubKey(), flags, checker,
                                    metrics, &scriptError);

    const auto *limits = metrics.GetScriptLimits();
    const int64_t *opCostLimit = nullptr;
    const int64_t *hashIterationsLimit = nullptr;
    int64_t opCostLimitStorage{};
    int64_t hashIterationsLimitStorage{};
    if (limits != nullptr) {
        opCostLimitStorage = limits->GetOpCostLimit();
        hashIterationsLimitStorage = limits->GetHashItersLimit();
        opCostLimit = &opCostLimitStorage;
        hashIterationsLimit = &hashIterationsLimitStorage;
    }
    int64_t sigChecksInputLimitStorage{};
    const int64_t *sigChecksInputLimit = nullptr;
    if ((flags & SCRIPT_VERIFY_INPUT_SIGCHECKS) != 0) {
        sigChecksInputLimitStorage =
            static_cast<int64_t>((context.scriptSig().size() + 60) / 43);
        sigChecksInputLimit = &sigChecksInputLimitStorage;
    }

    std::cout << "{";
    std::cout << "\"engine\":\"bchn\",";
    std::cout << "\"engineVersion\":\"" << kBchnVersion << "\",";
    std::cout << "\"sourceTagCommit\":\"" << kBchnTagCommit << "\",";
    std::cout << "\"scope\":\"script-input-only\",";
    std::cout << "\"mode\":\""
              << (args.standard ? "standard" : "consensus") << "\",";
    std::cout << "\"flags\":" << flags << ",";
    std::cout << "\"inputIndex\":" << args.inputIndex << ",";
    std::cout << "\"inputCount\":" << transaction.vin.size() << ",";
    std::cout << "\"sourceOutputCount\":" << psbtInputs.size() << ",";
    std::cout << "\"transactionBytes\":" << transactionBytes.size() << ",";
    std::cout << "\"sourceOutputsBytes\":" << sourceOutputBytes.size()
              << ",";
    std::cout << "\"unlockingBytecodeBytes\":"
              << context.scriptSig().size() << ",";
    std::cout << "\"lockingBytecodeBytes\":"
              << context.coinScriptPubKey().size() << ",";
    std::cout << "\"valid\":" << (valid ? "true" : "false") << ",";
    std::cout << "\"scriptErrorCode\":"
              << static_cast<int>(scriptError) << ",";
    std::cout << "\"scriptError\":\""
              << JsonEscape(ScriptErrorString(scriptError)) << "\",";
    // BCHN's VerifyScript contract only promises final metrics on success.
    std::cout << "\"metricsReliable\":" << (valid ? "true" : "false")
              << ",";
    std::cout << "\"metrics\":{";
    std::cout << "\"baseOpCost\":" << metrics.GetBaseOpCost() << ",";
    std::cout << "\"compositeOpCost\":"
              << metrics.GetCompositeOpCost(flags) << ",";
    PrintNullableMetric("opCostLimit", opCostLimit);
    std::cout << ",\"hashDigestIterations\":"
              << metrics.GetHashDigestIterations() << ",";
    PrintNullableMetric("hashDigestIterationsLimit", hashIterationsLimit);
    std::cout << ",\"sigChecks\":" << metrics.GetSigChecks() << ",";
    PrintNullableMetric("sigChecksInputLimit", sigChecksInputLimit);
    // VerifyScript reports the input contribution. BCHN enforces this ceiling
    // only after accumulating every input at transaction-validation scope.
    std::cout << ",\"sigChecksTransactionLimit\":" << MAX_TX_SIGCHECKS;
    std::cout << "}}\n";
    return valid ? EXIT_SUCCESS : 1;
}

} // namespace

int main(int argc, char **argv) {
    try {
        return Run(ParseArguments(argc, argv));
    } catch (const std::exception &error) {
        std::cerr << "{\"harnessError\":\"" << JsonEscape(error.what())
                  << "\"}\n";
        return 2;
    }
}
