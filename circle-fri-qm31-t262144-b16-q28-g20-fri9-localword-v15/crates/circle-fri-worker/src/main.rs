use circle_fri_worker::{
    build_disk_matrix_commitment, build_local_word_reference_fixture,
    build_local_word_relation_matrices, check_local_sha_v14_interaction, circle_lde_qm31,
    compile_local_sha_copy_permutation,
    compile_local_sha_word_copy_permutation, compile_local_sha_word_copy_permutation_for_rows,
    decode_local_sha_program,
    decode_local_word_prover_bundle, decode_pool_air_program, decode_successor_prover_bundle,
    decode_vertical_successor_prover_bundle, encode_local_word_sealed_proof, encode_proof,
    encode_successor_fri_proof,
    encode_successor_sealed_proof, encode_vertical_successor_sealed_proof,
    evaluate_pool_air_program, execute_local_sha_program, local_sha_interaction_samples,
    local_sha_program_digest, local_sha_relation_frame_at, local_sha_table_multiplicities,
    local_sha_v14_interaction_samples, local_sha_wire_digest, local_sha_word_relation_frame_at,
    local_word_air_residuals, local_word_boundary_samples, local_word_composition_transcript,
    local_word_interaction_transcript, local_word_public_boundary_transcript,
    local_word_v14_air_composition_partials, local_word_v14_air_residuals,
    mix_local_word_air_residuals, mix_local_word_v14_air_residuals, pool_air_residual_digest,
    pool_composition_lde_bit_reversed, prove_bytes, prove_local_word_bundle,
    prove_successor_bundle, prove_successor_fri,
    prove_vertical_successor_bundle, statement_coeffs, trace_zerofier_at_bit_reversed,
    verify_successor_fri, verify_successor_sealed_proof, DiskColumnExtension,
    LocalShaCopyChallenges,
    LocalShaInteractionChallenges, LocalShaV14InteractionChallenges, LocalShaWordCopyChallenges,
    LocalWordBoundaryChallenges, PoolAirNode, PoolAirOracleLdes, SuccessorFriConfig,
    SuccessorTranscript, LOCAL_WORD_EVAL_LOG,
};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

/** Fixed non-security challenges for the fast bundle interaction falsifier. */
fn local_word_v14_preflight_challenges() -> LocalShaV14InteractionChallenges {
    LocalShaV14InteractionChallenges {
        lookup_gamma: [211, 223, 227, 229],
        lookup_tuple: [
            [233, 239, 241, 251],
            [257, 263, 269, 271],
            [277, 281, 283, 293],
            [307, 311, 313, 317],
            [331, 337, 347, 349],
            [353, 359, 367, 373],
        ],
        word_copy: LocalShaWordCopyChallenges {
            gamma: [13, 17, 19, 23],
            identity: [29, 31, 37, 41],
            limbs: std::array::from_fn(|limb| {
                let base = 18 * limb as u32;
                [43 + base, 47 + base, 53 + base, 59 + base]
            }),
        },
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("local-word-reference-fixture-binary") {
        local_word_reference_fixture_binary();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("vertical-successor-prove-binary") {
        vertical_successor_prove_binary();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("successor-prove-binary") {
        successor_prove_binary();
        return;
    }
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    let line = buf
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if line.is_empty() || line == "manifest" {
        println!("{}", manifest());
        return;
    }
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", json!({ "ok": false, "error": e.to_string() }));
            std::process::exit(1);
        }
    };
    match v.get("cmd").and_then(|c| c.as_str()).unwrap_or("") {
        "manifest" => println!("{}", manifest()),
        "coeffs" => {
            let hex = v.get("statementHex").and_then(|x| x.as_str()).unwrap_or("");
            let bytes = hex::decode(hex).unwrap_or_default();
            let coeffs = statement_coeffs(&bytes);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "family": "circle-fri-m31",
                    "sound": false,
                    "coeffs": coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                })
            );
        }
        "prove" => {
            let hex = v.get("statementHex").and_then(|x| x.as_str()).unwrap_or("");
            let bytes = match hex::decode(hex) {
                Ok(b) if !b.is_empty() => b,
                _ => {
                    println!("{}", json!({ "ok": false, "error": "statementHex" }));
                    std::process::exit(1);
                }
            };
            let proof = prove_bytes(&bytes);
            let encoded = encode_proof(&proof);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "family": "circle-fri-m31",
                    "sound": false,
                    "proofBytes": encoded.len(),
                    "proofHex": hex::encode(encoded),
                })
            );
        }
        "successor-fri-fixture" => {
            let seed: Vec<[u32; 4]> = (0..64)
                .map(|row| {
                    std::array::from_fn(|coordinate| (row * 23 + coordinate * 61 + 7) as u32)
                })
                .collect();
            let codeword = circle_lde_qm31(&seed, 3);
            let config = SuccessorFriConfig {
                log_blowup: 3,
                final_log_degree: 2,
                fold_log: 1,
                query_orbit_log: 1,
                queries: 12,
                grind_bits: 4,
            };
            let mut transcript = SuccessorTranscript::new(b"successor-fri-test");
            transcript.absorb("statement", b"fixed-public-statement");
            let proof = prove_successor_fri(&codeword, &mut transcript, config).unwrap();
            let encoded = encode_successor_fri_proof(&proof);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "proofHex": hex::encode(&encoded),
                    "proofBytes": encoded.len(),
                    "inputLog": 9,
                    "config": {
                        "logBlowup": config.log_blowup,
                        "finalLogDegree": config.final_log_degree,
                        "foldLog": config.fold_log,
                        "queries": config.queries,
                        "grindBits": config.grind_bits,
                    },
                })
            );
        }
        "successor-fri-production-measure" => {
            let seed: Vec<[u32; 4]> = (0..1usize << 15)
                .map(|row| {
                    std::array::from_fn(|coordinate| {
                        ((row as u64 * 7919 + coordinate as u64 * 104729 + 17)
                            % circle_fri_worker::M31) as u32
                    })
                })
                .collect();
            let codeword = circle_lde_qm31(&seed, 3);
            let config = SuccessorFriConfig::PRODUCTION;
            let mut prover_transcript = SuccessorTranscript::new(b"successor-production-measure");
            prover_transcript.absorb("statement", b"fixed-public-production-fixture");
            let proof = prove_successor_fri(&codeword, &mut prover_transcript, config).unwrap();
            let mut verifier_transcript = SuccessorTranscript::new(b"successor-production-measure");
            verifier_transcript.absorb("statement", b"fixed-public-production-fixture");
            verify_successor_fri(&proof, 18, &mut verifier_transcript, config).unwrap();
            let encoded = encode_successor_fri_proof(&proof);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "proofBytes": encoded.len(),
                    "layers": proof.layers.len(),
                    "grindNonce": proof.grind_nonce,
                    "openingCounts": proof.layers.iter().map(|layer| layer.values.len()).collect::<Vec<_>>(),
                    "siblingCounts": proof.layers.iter().map(|layer| layer.merkle.siblings.len()).collect::<Vec<_>>(),
                })
            );
        }
        "air-ir-eval" => {
            let program_hex = v
                .get("programHex")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let program_bytes = hex::decode(program_hex).unwrap_or_default();
            let program = decode_pool_air_program(&program_bytes).unwrap();
            let public_inputs: Vec<u32> = (0..program.public_input_count)
                .map(|index| ((index as u64 * 123_457 + 31) % circle_fri_worker::M31) as u32)
                .collect();
            let residuals =
                evaluate_pool_air_program(&program, &public_inputs, |oracle, column, offset| {
                    let offset_term =
                        (offset as i64 + 128).rem_euclid(circle_fri_worker::M31 as i64) as u64;
                    ((oracle as u64 * 1_000_003 + column as u64 * 7_919 + offset_term * 101 + 17)
                        % circle_fri_worker::M31) as u32
                });
            println!(
                "{}",
                json!({
                    "ok": true,
                    "profile": program.profile,
                    "nodes": program.nodes.len(),
                    "outputs": program.outputs.len(),
                    "residualDigest": hex::encode(pool_air_residual_digest(&residuals)),
                    "firstResiduals": residuals.iter().take(8).collect::<Vec<_>>(),
                })
            );
        }
        "air-ir-vector-eval" => {
            let program_hex = v
                .get("programHex")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let program_bytes = hex::decode(program_hex).unwrap_or_default();
            let program = decode_pool_air_program(&program_bytes).unwrap();
            let rows = 1usize << 8;
            let mut widths = [0usize; 4];
            for node in &program.nodes {
                if let PoolAirNode::Input { oracle, column, .. } = *node {
                    widths[oracle as usize] = widths[oracle as usize].max(column as usize + 1);
                }
            }
            let matrix = |oracle: usize| -> Vec<Vec<u32>> {
                (0..widths[oracle])
                    .map(|column| {
                        (0..rows)
                            .map(|row| {
                                ((oracle as u64 * 1_000_003
                                    + column as u64 * 7_919
                                    + row as u64 * 101
                                    + 17)
                                    % circle_fri_worker::M31) as u32
                            })
                            .collect()
                    })
                    .collect()
            };
            let sha = matrix(0);
            let sha_aux = matrix(1);
            let bus = matrix(2);
            let preprocessed = matrix(3);
            let public_inputs: Vec<u32> = (0..program.public_input_count)
                .map(|index| ((index as u64 * 123_457 + 31) % circle_fri_worker::M31) as u32)
                .collect();
            let composition = pool_composition_lde_bit_reversed(
                &program,
                &public_inputs,
                PoolAirOracleLdes {
                    sha: &sha,
                    sha_aux: &sha_aux,
                    bus: &bus,
                    preprocessed: &preprocessed,
                },
                3,
                [11u8; 32],
            );
            let coordinates: Vec<u32> = composition
                .iter()
                .flat_map(|value| value.iter().copied())
                .collect();
            println!(
                "{}",
                json!({
                    "ok": true,
                    "rows": composition.len(),
                    "compositionDigest": hex::encode(pool_air_residual_digest(&coordinates)),
                    "firstValues": composition.iter().take(2).collect::<Vec<_>>(),
                })
            );
        }
        "successor-zerofier-kat" => {
            let indices = [0usize, 1, 17, 12345, 524287, 1048575];
            println!(
                "{}",
                json!({
                    "ok": true,
                    "values": indices
                        .iter()
                        .map(|index| trace_zerofier_at_bit_reversed(*index, 20, 13).0)
                        .collect::<Vec<_>>(),
                })
            );
        }
        "local-sha-program-kat" => {
            let program_hex = v
                .get("programHex")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let program_bytes = hex::decode(program_hex).unwrap_or_default();
            let program = match decode_local_sha_program(&program_bytes) {
                Ok(program) => program,
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            };
            let inputs: Vec<u32> = match v.get("inputs").and_then(|value| value.as_array()) {
                Some(values) => values
                    .iter()
                    .map(|value| value.as_u64().and_then(|n| u32::try_from(n).ok()))
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let wires = match execute_local_sha_program(&program, &inputs) {
                Ok(wires) => wires,
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            };
            println!(
                "{}",
                json!({
                    "ok": true,
                    "rows": program.rows.len(),
                    "inputs": program.input_count,
                    "aliases": program.copy_aliases.len(),
                    "wordAliases": program.word_aliases.len(),
                    "programDigest": hex::encode(local_sha_program_digest(&program_bytes)),
                    "wireDigest": hex::encode(local_sha_wire_digest(&wires)),
                    "lastWire": wires.last().copied().unwrap_or(0),
                })
            );
        }
        "local-sha-relation-kat" => {
            let program_hex = v
                .get("programHex")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let program_bytes = hex::decode(program_hex).unwrap_or_default();
            let program = match decode_local_sha_program(&program_bytes) {
                Ok(program) => program,
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            };
            let inputs: Vec<u32> = match v.get("inputs").and_then(|value| value.as_array()) {
                Some(values) => values
                    .iter()
                    .map(|value| value.as_u64().and_then(|n| u32::try_from(n).ok()))
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let requested_rows: Vec<usize> = match v.get("rows").and_then(|value| value.as_array())
            {
                Some(values) => values
                    .iter()
                    .map(|value| value.as_u64().and_then(|n| usize::try_from(n).ok()))
                    .collect::<Option<Vec<_>>>()
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let result: Result<Value, String> = (|| {
                let wires = execute_local_sha_program(&program, &inputs)?;
                let multiplicities = local_sha_table_multiplicities(&program, &wires)?;
                let permutation = compile_local_sha_copy_permutation(&program)?;
                let frames = requested_rows
                    .iter()
                    .map(|row| {
                        local_sha_relation_frame_at(
                            &program,
                            &wires,
                            &permutation,
                            &multiplicities,
                            *row,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(json!({
                    "ok": true,
                    "rows": program.rows.len(),
                    "inputs": program.input_count,
                    "aliases": program.copy_aliases.len(),
                    "wordAliases": program.word_aliases.len(),
                    "programDigest": hex::encode(local_sha_program_digest(&program_bytes)),
                    "wireDigest": hex::encode(local_sha_wire_digest(&wires)),
                    "lastWire": wires.last().copied().unwrap_or(0),
                    "relationRows": program.rows.len().next_power_of_two(),
                    "tableRows": multiplicities.len(),
                    "multiplicitySum": multiplicities.iter().map(|value| *value as u64).sum::<u64>(),
                    "copySlots": permutation.identities.len(),
                    "copyActive": permutation.active_slots,
                    "frames": frames.iter().map(|frame| json!({
                        "row": frame.row,
                        "original": frame.original,
                        "preprocessed": frame.preprocessed,
                    })).collect::<Vec<_>>(),
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-sha-interaction-kat" => {
            let result: Result<Value, String> = (|| {
                let program_hex = v
                    .get("programHex")
                    .and_then(|value| value.as_str())
                    .ok_or("local SHA interaction programHex")?;
                let program_bytes =
                    hex::decode(program_hex).map_err(|_| "local SHA interaction programHex")?;
                let program = decode_local_sha_program(&program_bytes)?;
                let inputs = v
                    .get("inputs")
                    .and_then(|value| value.as_array())
                    .ok_or("local SHA interaction inputs")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or_else(|| "local SHA interaction input".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let sample_rows = v
                    .get("rows")
                    .and_then(|value| value.as_array())
                    .ok_or("local SHA interaction rows")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|n| usize::try_from(n).ok())
                            .ok_or_else(|| "local SHA interaction row".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let challenge_value = v
                    .get("challenges")
                    .ok_or("local SHA interaction challenges")?;
                let lookup = challenge_value
                    .get("lookup")
                    .ok_or("local SHA lookup challenges")?;
                let lookup_gamma = json_qm31(lookup.get("gamma").ok_or("local SHA lookup gamma")?)?;
                let lookup_tuple: [Value; 6] = lookup
                    .get("tuple")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local SHA lookup tuple")?;
                let lookup_tuple = lookup_tuple
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let copy_values: [Value; 2] = challenge_value
                    .get("copy")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local SHA copy challenges")?;
                let copy = copy_values
                    .map(|value| {
                        Ok(LocalShaCopyChallenges {
                            gamma: json_qm31(value.get("gamma").ok_or("local SHA copy gamma")?)?,
                            identity: json_qm31(
                                value.get("identity").ok_or("local SHA copy identity")?,
                            )?,
                            value: json_qm31(value.get("value").ok_or("local SHA copy value")?)?,
                        })
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, String>>()?
                    .try_into()
                    .unwrap();
                let wires = execute_local_sha_program(&program, &inputs)?;
                let multiplicities = local_sha_table_multiplicities(&program, &wires)?;
                let permutation = compile_local_sha_copy_permutation(&program)?;
                let interaction = local_sha_interaction_samples(
                    &program,
                    &wires,
                    &permutation,
                    &multiplicities,
                    &LocalShaInteractionChallenges {
                        lookup_gamma,
                        lookup_tuple,
                        copy,
                    },
                    &sample_rows,
                )?;
                Ok(json!({
                    "ok": true,
                    "relationRows": interaction.relation_rows,
                    "claimedSum": interaction.claimed_sum,
                    "samples": interaction.samples.iter().map(|sample| json!({
                        "row": sample.row,
                        "columns": sample.columns,
                    })).collect::<Vec<_>>(),
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-v14-kat" => {
            let result: Result<Value, String> = (|| {
                let program_bytes = hex::decode(
                    v.get("programHex")
                        .and_then(|value| value.as_str())
                        .ok_or("local-word v14 programHex")?,
                )
                .map_err(|_| "local-word v14 programHex")?;
                let program = decode_local_sha_program(&program_bytes)?;
                let inputs = v
                    .get("inputs")
                    .and_then(|value| value.as_array())
                    .ok_or("local-word v14 inputs")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|number| u32::try_from(number).ok())
                            .ok_or_else(|| "local-word v14 input".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let requested_rows = v
                    .get("rows")
                    .and_then(|value| value.as_array())
                    .ok_or("local-word v14 rows")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|number| usize::try_from(number).ok())
                            .ok_or_else(|| "local-word v14 row".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let challenge_value = v.get("challenges").ok_or("local-word v14 challenges")?;
                let lookup = challenge_value
                    .get("lookup")
                    .ok_or("local-word v14 lookup")?;
                let lookup_values: [Value; 6] = lookup
                    .get("tuple")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word v14 lookup tuple")?;
                let lookup_tuple = lookup_values
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let word_copy = challenge_value
                    .get("wordCopy")
                    .ok_or("local-word v14 word copy")?;
                let word_limb_values: [Value; 8] = word_copy
                    .get("limbs")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word v14 word limbs")?;
                let word_limbs = word_limb_values
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let interaction_challenges = LocalShaV14InteractionChallenges {
                    lookup_gamma: json_qm31(
                        lookup.get("gamma").ok_or("local-word v14 lookup gamma")?,
                    )?,
                    lookup_tuple,
                    word_copy: LocalShaWordCopyChallenges {
                        gamma: json_qm31(
                            word_copy.get("gamma").ok_or("local-word v14 copy gamma")?,
                        )?,
                        identity: json_qm31(
                            word_copy
                                .get("identity")
                                .ok_or("local-word v14 copy identity")?,
                        )?,
                        limbs: word_limbs,
                    },
                };
                let boundary = challenge_value
                    .get("boundary")
                    .ok_or("local-word v14 boundary")?;
                let boundary_limb_values: [Value; 8] = boundary
                    .get("limbs")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word v14 boundary limbs")?;
                let boundary_limbs = boundary_limb_values
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let boundary_challenges = LocalWordBoundaryChallenges {
                    gamma: json_qm31(
                        boundary
                            .get("gamma")
                            .ok_or("local-word v14 boundary gamma")?,
                    )?,
                    identity: json_qm31(
                        boundary
                            .get("identity")
                            .ok_or("local-word v14 boundary identity")?,
                    )?,
                    limbs: boundary_limbs,
                };
                let alpha = json_qm31(v.get("alpha").ok_or("local-word v14 alpha")?)?;

                let wires = execute_local_sha_program(&program, &inputs)?;
                let multiplicities = local_sha_table_multiplicities(&program, &wires)?;
                let permutation = compile_local_sha_word_copy_permutation(&program)?;
                let relation_rows = program.rows.len().max(1_841).next_power_of_two();
                if requested_rows.iter().any(|row| *row >= relation_rows) {
                    return Err("local-word v14 sample row".into());
                }
                let mut interaction_rows = requested_rows
                    .iter()
                    .flat_map(|row| {
                        [
                            *row,
                            if *row == 0 {
                                relation_rows - 1
                            } else {
                                row - 1
                            },
                        ]
                    })
                    .collect::<Vec<_>>();
                interaction_rows.sort_unstable();
                interaction_rows.dedup();
                let interaction = local_sha_v14_interaction_samples(
                    &program,
                    &wires,
                    &permutation,
                    &multiplicities,
                    &interaction_challenges,
                    &interaction_rows,
                )?;
                let samples = requested_rows
                    .iter()
                    .map(|row| {
                        let previous_row = if *row == 0 {
                            relation_rows - 1
                        } else {
                            row - 1
                        };
                        let current = interaction
                            .samples
                            .iter()
                            .find(|sample| sample.row == *row)
                            .ok_or("local-word v14 current sample")?;
                        let previous = interaction
                            .samples
                            .iter()
                            .find(|sample| sample.row == previous_row)
                            .ok_or("local-word v14 previous sample")?;
                        let frame = local_sha_word_relation_frame_at(
                            &program,
                            &wires,
                            &permutation,
                            &multiplicities,
                            *row,
                        )?;
                        let mut preprocessed = frame.preprocessed.clone();
                        preprocessed.extend([0, 0, u32::from(*row == 0)]);
                        let mut current_values = current.columns.clone();
                        current_values.extend([[0; 4], [0; 4]]);
                        let mut previous_values = previous.columns.clone();
                        previous_values.extend([[0; 4], [0; 4]]);
                        let residuals = local_word_v14_air_residuals(
                            &frame.original,
                            &preprocessed,
                            &current_values,
                            &previous_values,
                            &interaction_challenges,
                            &boundary_challenges,
                            [0; 4],
                        )?;
                        let mixed = mix_local_word_v14_air_residuals(&residuals, alpha)?;
                        let partials = local_word_v14_air_composition_partials(&residuals, alpha)?;
                        Ok(json!({
                            "row": row,
                            "original": frame.original,
                            "preprocessed": frame.preprocessed,
                            "interaction": current.columns,
                            "residuals": residuals,
                            "mixed": mixed,
                            "partials": partials,
                        }))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(json!({
                    "ok": true,
                    "relationRows": relation_rows,
                    "activeWordSlots": permutation.active_slots,
                    "lookupClaimedSum": interaction.lookup_claimed_sum,
                    "finalWordProduct": interaction.final_word_product,
                    "samples": samples,
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-bundle-kat" => {
            let result: Result<Value, String> = (|| {
                let bundle_hex = v
                    .get("bundleHex")
                    .and_then(|value| value.as_str())
                    .ok_or("local-word bundleHex")?;
                let bundle_bytes = hex::decode(bundle_hex).map_err(|_| "local-word bundleHex")?;
                let bundle = decode_local_word_prover_bundle(&bundle_bytes)?;
                let wires = execute_local_sha_program(&bundle.program, &bundle.inputs)?;
                let permutation = compile_local_sha_word_copy_permutation_for_rows(
                    &bundle.program,
                    bundle.relation_rows,
                )?;
                let multiplicities = local_sha_table_multiplicities(&bundle.program, &wires)?;
                check_local_sha_v14_interaction(
                    &bundle.program,
                    &wires,
                    &permutation,
                    &multiplicities,
                    &local_word_v14_preflight_challenges(),
                )?;
                Ok(json!({
                    "ok": true,
                    "profile": bundle.profile,
                    "relationRows": bundle.relation_rows,
                    "rows": bundle.program.rows.len(),
                    "inputs": bundle.inputs.len(),
                    "publicWords": bundle.public_words.len(),
                    "interactionPreflight": true,
                    "activeWordSlots": permutation.active_slots,
                    "bundleDigest": hex::encode(circle_fri_worker::local_sha_program_digest(&bundle_bytes)),
                    "descriptorDigest": hex::encode(circle_fri_worker::local_sha_program_digest(
                        &bundle.construction_descriptor,
                    )),
                    "programDigest": hex::encode(local_sha_program_digest(&bundle.program_bytes)),
                    "wireDigest": hex::encode(local_sha_wire_digest(&wires)),
                    "transcriptInitialBytes": bundle.transcript_initial.len(),
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-verifier-key" => {
            let result: Result<Value, String> = (|| {
                let bundle_hex = v
                    .get("bundleHex")
                    .and_then(|value| value.as_str())
                    .ok_or("local-word verifier-key bundleHex")?;
                let bundle_bytes =
                    hex::decode(bundle_hex).map_err(|_| "local-word verifier-key bundleHex")?;
                let bundle = decode_local_word_prover_bundle(&bundle_bytes)?;
                let wires = execute_local_sha_program(&bundle.program, &bundle.inputs)?;
                let permutation = compile_local_sha_word_copy_permutation_for_rows(
                    &bundle.program,
                    bundle.relation_rows,
                )?;
                let multiplicities = local_sha_table_multiplicities(&bundle.program, &wires)?;
                let relation = build_local_word_relation_matrices(
                    &bundle,
                    &wires,
                    &permutation,
                    &multiplicities,
                )?;
                let root = std::env::temp_dir().join(format!(
                    "shieldkit-local-word-verifier-key-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| format!("local-word verifier-key clock: {error}"))?
                        .as_nanos(),
                ));
                std::fs::create_dir(&root)
                    .map_err(|error| format!("create local-word verifier-key root: {error}"))?;
                let committed = build_disk_matrix_commitment(
                    "local-word:preprocessed",
                    &relation.preprocessed,
                    DiskColumnExtension::PublicRelation {
                        eval_log: LOCAL_WORD_EVAL_LOG,
                    },
                    &root.join("preprocessed"),
                );
                let value = committed.map(|commitment| json!({
                    "ok": true,
                    "profile": bundle.profile,
                    "publicWords": bundle.public_words.len(),
                    "constructionDigestHex": hex::encode(
                        circle_fri_worker::local_sha_program_digest(
                            &bundle.construction_descriptor,
                        ),
                    ),
                    "expectedPreprocessedRootHex": hex::encode(commitment.root),
                }));
                let cleanup = std::fs::remove_dir_all(&root)
                    .map_err(|error| format!("remove local-word verifier-key root: {error}"));
                match (value, cleanup) {
                    (Ok(value), Ok(())) => Ok(value),
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                }
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-prove" => {
            let result: Result<Value, String> = (|| {
                let bundle_hex = v
                    .get("bundleHex")
                    .and_then(|value| value.as_str())
                    .ok_or("local-word prove bundleHex")?;
                let bundle_bytes =
                    hex::decode(bundle_hex).map_err(|_| "local-word prove bundleHex")?;
                let bundle = decode_local_word_prover_bundle(&bundle_bytes)?;
                let root = std::env::temp_dir().join(format!(
                    "shieldkit-local-word-prove-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| format!("local-word prove clock: {error}"))?
                        .as_nanos(),
                ));
                std::fs::create_dir(&root)
                    .map_err(|error| format!("create local-word prove root: {error}"))?;
                let proved = prove_local_word_bundle(bundle, &root.join("prover"));
                let value = match proved {
                    Ok(proved) => {
                        let proof_bytes = encode_local_word_sealed_proof(&proved.proof)?;
                        Ok(json!({
                            "ok": true,
                            "profile": proved.proof.profile,
                            "proofHex": hex::encode(&proof_bytes),
                            "proofBytes": proof_bytes.len(),
                            "constructionDigestHex": hex::encode(proved.proof.construction_digest),
                            "expectedPreprocessedRootHex": hex::encode(proved.proof.preprocessed.root),
                            "publicWords": proved.proof.public_boundary_inverses.len(),
                            "quotientDegreeBound": proved.quotient_degree_bound,
                        }))
                    }
                    Err(error) => Err(error),
                };
                let cleanup = std::fs::remove_dir_all(&root)
                    .map_err(|error| format!("remove local-word prove root: {error}"));
                match (value, cleanup) {
                    (Ok(value), Ok(())) => Ok(value),
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                }
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-air-kat" => {
            let result: Result<Value, String> = (|| {
                let challenge_value = v.get("challenges").ok_or("local-word AIR challenges")?;
                let lookup = challenge_value
                    .get("lookup")
                    .ok_or("local-word AIR lookup")?;
                let lookup_tuple: [Value; 6] = lookup
                    .get("tuple")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word AIR lookup tuple")?;
                let lookup_tuple = lookup_tuple
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let copy_values: [Value; 2] = challenge_value
                    .get("copy")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word AIR copy")?;
                let copy = copy_values
                    .map(|value| {
                        Ok(LocalShaCopyChallenges {
                            gamma: json_qm31(
                                value.get("gamma").ok_or("local-word AIR copy gamma")?,
                            )?,
                            identity: json_qm31(
                                value
                                    .get("identity")
                                    .ok_or("local-word AIR copy identity")?,
                            )?,
                            value: json_qm31(
                                value.get("value").ok_or("local-word AIR copy value")?,
                            )?,
                        })
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, String>>()?
                    .try_into()
                    .unwrap();
                let interaction_challenges = LocalShaInteractionChallenges {
                    lookup_gamma: json_qm31(
                        lookup.get("gamma").ok_or("local-word AIR lookup gamma")?,
                    )?,
                    lookup_tuple,
                    copy,
                };
                let boundary_value = challenge_value
                    .get("boundary")
                    .ok_or("local-word AIR boundary")?;
                let limb_values: [Value; 8] = boundary_value
                    .get("limbs")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word AIR boundary limbs")?;
                let limbs = limb_values
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let boundary_challenges = LocalWordBoundaryChallenges {
                    gamma: json_qm31(
                        boundary_value
                            .get("gamma")
                            .ok_or("local-word AIR boundary gamma")?,
                    )?,
                    identity: json_qm31(
                        boundary_value
                            .get("identity")
                            .ok_or("local-word AIR boundary identity")?,
                    )?,
                    limbs,
                };
                let boundary_claimed_sum = json_qm31(
                    v.get("boundaryClaimedSum")
                        .ok_or("local-word AIR boundary claimed sum")?,
                )?;
                let alpha = json_qm31(v.get("alpha").ok_or("local-word AIR alpha")?)?;
                let m31_array = |value: &Value, label: &str| -> Result<Vec<u32>, String> {
                    value
                        .as_array()
                        .ok_or_else(|| label.to_string())?
                        .iter()
                        .map(|entry| {
                            entry
                                .as_u64()
                                .filter(|number| *number < circle_fri_worker::M31)
                                .map(|number| number as u32)
                                .ok_or_else(|| label.to_string())
                        })
                        .collect()
                };
                let qm31_array = |value: &Value, label: &str| -> Result<Vec<[u32; 4]>, String> {
                    value
                        .as_array()
                        .ok_or_else(|| label.to_string())?
                        .iter()
                        .map(json_qm31)
                        .collect()
                };
                let frames = v
                    .get("frames")
                    .and_then(|value| value.as_array())
                    .ok_or("local-word AIR frames")?;
                let samples = frames
                    .iter()
                    .map(|frame| {
                        let original = m31_array(
                            frame.get("original").ok_or("local-word AIR original")?,
                            "local-word AIR original",
                        )?;
                        let preprocessed = m31_array(
                            frame
                                .get("preprocessed")
                                .ok_or("local-word AIR preprocessed")?,
                            "local-word AIR preprocessed",
                        )?;
                        let interaction = qm31_array(
                            frame
                                .get("interaction")
                                .ok_or("local-word AIR interaction")?,
                            "local-word AIR interaction",
                        )?;
                        let interaction_previous = qm31_array(
                            frame
                                .get("interactionPrevious")
                                .ok_or("local-word AIR interaction previous")?,
                            "local-word AIR interaction previous",
                        )?;
                        let residuals = local_word_air_residuals(
                            &original,
                            &preprocessed,
                            &interaction,
                            &interaction_previous,
                            &interaction_challenges,
                            &boundary_challenges,
                            boundary_claimed_sum,
                        )?;
                        let mixed = mix_local_word_air_residuals(&residuals, alpha)?;
                        Ok(json!({ "residuals": residuals, "mixed": mixed }))
                    })
                    .collect::<Result<Vec<Value>, String>>()?;
                Ok(
                    json!({ "ok": true, "constraints": circle_fri_worker::LOCAL_WORD_AIR_CONSTRAINTS, "samples": samples }),
                )
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-boundary-kat" => {
            let result: Result<Value, String> = (|| {
                let bundle_hex = v
                    .get("bundleHex")
                    .and_then(|value| value.as_str())
                    .ok_or("local-word boundary bundleHex")?;
                let bundle_bytes =
                    hex::decode(bundle_hex).map_err(|_| "local-word boundary bundleHex")?;
                let bundle = decode_local_word_prover_bundle(&bundle_bytes)?;
                let rows = v
                    .get("rows")
                    .and_then(|value| value.as_array())
                    .ok_or("local-word boundary rows")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|n| usize::try_from(n).ok())
                            .ok_or_else(|| "local-word boundary row".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let challenge_value = v
                    .get("challenges")
                    .ok_or("local-word boundary challenges")?;
                let limb_values: [Value; 8] = challenge_value
                    .get("limbs")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word boundary limbs")?;
                let limbs = limb_values
                    .map(|value| json_qm31(&value))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap();
                let challenges = LocalWordBoundaryChallenges {
                    gamma: json_qm31(
                        challenge_value
                            .get("gamma")
                            .ok_or("local-word boundary gamma")?,
                    )?,
                    identity: json_qm31(
                        challenge_value
                            .get("identity")
                            .ok_or("local-word boundary identity")?,
                    )?,
                    limbs,
                };
                let wires = execute_local_sha_program(&bundle.program, &bundle.inputs)?;
                let boundary = local_word_boundary_samples(&bundle, &wires, &challenges, &rows)?;
                Ok(json!({
                    "ok": true,
                    "relationRows": boundary.relation_rows,
                    "claimedSum": boundary.claimed_sum,
                    "publicInverses": boundary.public_inverses,
                    "samples": boundary.samples.iter().map(|(row, values)| json!({
                        "row": row,
                        "values": values,
                    })).collect::<Vec<_>>(),
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        "local-word-transcript-kat" => {
            let result: Result<Value, String> = (|| {
                let initial = hex::decode(
                    v.get("initialHex")
                        .and_then(|value| value.as_str())
                        .ok_or("local-word transcript initial")?,
                )
                .map_err(|_| "local-word transcript initial")?;
                let digest32 = |name: &str| -> Result<[u8; 32], String> {
                    hex::decode(v.get(name).and_then(|value| value.as_str()).ok_or(name)?)
                        .map_err(|_| name.to_string())?
                        .try_into()
                        .map_err(|_| name.to_string())
                };
                let descriptor = digest32("descriptorHex")?;
                let preprocessed = digest32("preprocessedRootHex")?;
                let original = digest32("originalRootHex")?;
                let interaction_values: [Value; 2] = v
                    .get("interactionRootHexes")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .and_then(|values| values.try_into().ok())
                    .ok_or("local-word interaction roots")?;
                let interaction_roots: [[u8; 32]; 2] = interaction_values
                    .map(|value| {
                        hex::decode(value.as_str().ok_or("local-word interaction root")?)
                            .map_err(|_| "local-word interaction root".to_string())?
                            .try_into()
                            .map_err(|_| "local-word interaction root".to_string())
                    })
                    .into_iter()
                    .collect::<Result<Vec<[u8; 32]>, String>>()?
                    .try_into()
                    .unwrap();
                let (mut transcript, interaction, boundary) =
                    local_word_interaction_transcript(&initial, descriptor, preprocessed, original);
                let boundary_inverses = v
                    .get("boundaryInverses")
                    .and_then(|value| value.as_array())
                    .ok_or("local-word transcript boundary inverses")?
                    .iter()
                    .map(json_qm31)
                    .collect::<Result<Vec<_>, _>>()?;
                let interaction_digest =
                    local_word_public_boundary_transcript(&mut transcript, &boundary_inverses)?;
                let (constraint_alpha, composition_digest) = local_word_composition_transcript(
                    &mut transcript,
                    interaction_roots[0],
                    interaction_roots[1],
                );
                Ok(json!({
                    "ok": true,
                    "lookup": {
                        "gamma": interaction.lookup_gamma,
                        "tuple": interaction.lookup_tuple,
                    },
                    "copy": interaction.copy.iter().map(|copy| json!({
                        "gamma": copy.gamma,
                        "identity": copy.identity,
                        "value": copy.value,
                    })).collect::<Vec<_>>(),
                    "boundary": {
                        "gamma": boundary.gamma,
                        "identity": boundary.identity,
                        "limbs": boundary.limbs,
                    },
                    "interactionDigest": hex::encode(interaction_digest),
                    "constraintAlpha": constraint_alpha,
                    "compositionDigest": hex::encode(composition_digest),
                }))
            })();
            match result {
                Ok(value) => println!("{}", value),
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error }));
                    std::process::exit(1);
                }
            }
        }
        other => {
            println!(
                "{}",
                json!({ "ok": false, "error": format!("unknown cmd {other}") })
            );
            std::process::exit(1);
        }
    }
}

fn local_word_reference_fixture_binary() {
    match build_local_word_reference_fixture() {
        Ok(fixture) => {
            let zerofier_indices = [0usize, 1, 17, 1234, (1usize << fixture.eval_log) - 1];
            eprintln!(
                "{}",
                json!({
                    "profile": fixture.profile,
                    "transcriptInitialHex": hex::encode(&fixture.transcript_initial),
                    "constructionDescriptorHex": hex::encode(&fixture.construction_descriptor),
                    "publicWords": fixture.public_words.iter().map(|word| json!({
                        "id": word.id,
                        "row": word.row,
                        "expected": word.expected,
                    })).collect::<Vec<_>>(),
                    "expectedPreprocessedRootHex": hex::encode(fixture.expected_preprocessed_root),
                    "parameters": {
                        "relationLog": fixture.relation_log,
                        "evalLog": fixture.eval_log,
                        "quotientDegreeRows": fixture.quotient_degree_rows,
                        "fri": {
                            "logBlowup": fixture.fri.log_blowup,
                            "finalLogDegree": fixture.fri.final_log_degree,
                            "foldLog": fixture.fri.fold_log,
                            "queryOrbitLog": fixture.fri.query_orbit_log,
                            "queries": fixture.fri.queries,
                            "grindBits": fixture.fri.grind_bits,
                        },
                    },
                    "proofBytes": fixture.proof_bytes.len(),
                    "zerofierIndices": zerofier_indices,
                    "zerofierValues": zerofier_indices.iter().map(|index|
                        trace_zerofier_at_bit_reversed(
                            *index,
                            fixture.eval_log,
                            fixture.relation_log,
                        ).0
                    ).collect::<Vec<_>>(),
                }),
            );
            io::stdout().write_all(&fixture.proof_bytes).unwrap();
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn json_qm31(value: &Value) -> Result<[u32; 4], String> {
    let values: [Value; 4] = value
        .as_array()
        .cloned()
        .and_then(|values| values.try_into().ok())
        .ok_or("QM31 JSON width")?;
    values
        .map(|value| {
            value
                .as_u64()
                .filter(|coordinate| *coordinate < circle_fri_worker::M31)
                .and_then(|coordinate| u32::try_from(coordinate).ok())
                .ok_or_else(|| "QM31 JSON coordinate".to_string())
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "QM31 JSON".to_string())
}

fn vertical_successor_prove_binary() {
    let mut bundle_bytes = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut bundle_bytes) {
        eprintln!("{}", json!({ "ok": false, "error": error.to_string() }));
        std::process::exit(1);
    }
    let bundle = match decode_vertical_successor_prover_bundle(&bundle_bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("{}", json!({ "ok": false, "error": error }));
            std::process::exit(1);
        }
    };
    let result = match prove_vertical_successor_bundle(bundle) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", json!({ "ok": false, "error": error }));
            std::process::exit(1);
        }
    };
    let proof_bytes = encode_vertical_successor_sealed_proof(&result.proof);
    eprintln!(
        "{}",
        json!({
            "ok": true,
            "proofBytes": proof_bytes.len(),
            "quotientDegreeBound": result.quotient_degree_bound,
            "profile": result.proof.profile,
            "preprocessedRoot": hex::encode(result.proof.preprocessed.root),
            "openingCounts": {
                "preprocessed": result.proof.preprocessed.indices.len(),
                "sha": result.proof.sha.indices.len(),
                "boundary": result.proof.boundary.indices.len(),
                "interaction": result.proof.interaction.indices.len(),
                "quotient": result.proof.quotient.indices.len(),
                "friMask": result.proof.fri_mask.indices.len(),
            },
            "siblingCounts": {
                "preprocessed": result.proof.preprocessed.siblings.len(),
                "sha": result.proof.sha.siblings.len(),
                "boundary": result.proof.boundary.siblings.len(),
                "interaction": result.proof.interaction.siblings.len(),
                "quotient": result.proof.quotient.siblings.len(),
                "friMask": result.proof.fri_mask.siblings.len(),
                "friLayers": result.proof.fri.layers.iter().map(|layer| layer.merkle.siblings.len()).collect::<Vec<_>>(),
            },
        })
    );
    if let Err(error) = io::stdout().write_all(&proof_bytes) {
        eprintln!("{}", json!({ "ok": false, "error": error.to_string() }));
        std::process::exit(1);
    }
}

fn successor_prove_binary() {
    let mut bundle_bytes = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut bundle_bytes) {
        eprintln!("{}", json!({ "ok": false, "error": error.to_string() }));
        std::process::exit(1);
    }
    let bundle = match decode_successor_prover_bundle(&bundle_bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("{}", json!({ "ok": false, "error": error }));
            std::process::exit(1);
        }
    };
    let transcript_initial = bundle.transcript_initial.clone();
    let program_bytes = bundle.program_bytes.clone();
    let public_inputs = bundle.public_inputs.clone();
    let result = match prove_successor_bundle(bundle) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", json!({ "ok": false, "error": error }));
            std::process::exit(1);
        }
    };
    if let Err(error) = verify_successor_sealed_proof(
        &result.proof,
        &transcript_initial,
        &program_bytes,
        &public_inputs,
        result.proof.preprocessed.root,
    ) {
        eprintln!(
            "{}",
            json!({ "ok": false, "error": format!("self-verify: {error}") })
        );
        std::process::exit(1);
    }
    let proof_bytes = encode_successor_sealed_proof(&result.proof);
    eprintln!(
        "{}",
        json!({
            "ok": true,
            "proofBytes": proof_bytes.len(),
            "quotientDegreeBound": result.quotient_degree_bound,
            "profile": result.proof.profile,
            "preprocessedRoot": hex::encode(result.proof.preprocessed.root),
            "openingCounts": {
                "preprocessed": result.proof.preprocessed.indices.len(),
                "sha": result.proof.sha.indices.len(),
                "shaAux": result.proof.sha_aux.indices.len(),
                "bus": result.proof.bus.indices.len(),
                "quotient": result.proof.quotient.indices.len(),
                "friMask": result.proof.fri_mask.indices.len(),
            },
        })
    );
    if let Err(error) = io::stdout().write_all(&proof_bytes) {
        eprintln!("{}", json!({ "ok": false, "error": error.to_string() }));
        std::process::exit(1);
    }
}

fn manifest() -> String {
    json!({
        "family": "circle-fri-m31",
        "role": "prove-worker",
        "sound": false,
        "params": { "n": 32, "queries": 8, "field": "M31" },
        "sameAs": "Toorik designs/fri fri-worker: heavy prove only, TS verifies",
    })
    .to_string()
}
