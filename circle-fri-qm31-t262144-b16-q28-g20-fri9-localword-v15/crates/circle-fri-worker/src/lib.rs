//! Bench Circle FRI over M31. Matches the TypeScript plugin wire format.
//! sound: false (n=32, 8 queries). Hash-based = PQ family.

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use stwo::core::circle::Coset;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fft::ibutterfly;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::cpu::{
    fold_circle_into_line_cpu, fold_line_cpu, CpuCircleEvaluation, CpuCirclePoly,
};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::SecureEvaluation;
use stwo::prover::poly::{BitReversedOrder, NaturalOrder};

mod local_word_disk_oracle;
pub use local_word_disk_oracle::{
    build_disk_matrix_commitment, combine_disk_matrix_commitments,
    commit_disk_qm31_evaluation, DiskColumnExtension, DiskMatrixColumnReader,
    DiskMatrixCommitment, DiskQm31Evaluation, DiskQm31Writer,
};

pub const M31: u64 = 2_147_483_647;
pub const FRI_LOG_N: usize = 5;
pub const FRI_N: usize = 32;
pub const FRI_QUERIES: usize = 8;
pub const FRI_VERSION: u8 = 1;
pub const CIRCLE_GEN: Point = Point {
    x: 2,
    y: 1_268_011_823,
};

pub type Qm31Value = [u32; 4];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalShaOperation {
    Input { input: usize },
    Mask { input: usize },
    Constant { literal: u32 },
    RotateRight { a: usize, shift: u32 },
    Xor { a: usize, b: usize },
    And { a: usize, b: usize },
    Add { a: usize, b: usize },
    Nonzero { a: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaProgram {
    pub rows: Vec<LocalShaOperation>,
    pub input_count: usize,
    pub copy_aliases: Vec<(usize, u8, usize, u8)>,
    pub word_aliases: Vec<(usize, usize)>,
}

/** Decode canonical TypeScript SLWP v1 (legacy) or v2 constraint programs. */
pub fn decode_local_sha_program(bytes: &[u8]) -> Result<LocalShaProgram, String> {
    let mut cursor = AirCursor { bytes, offset: 0 };
    if cursor.take(4)? != b"SLWP" {
        return Err("local SHA program codec".into());
    }
    let version = cursor.u8()?;
    if version != 1 && version != 2 {
        return Err("local SHA program codec".into());
    }
    let row_count = cursor.u32_be()? as usize;
    let input_count = cursor.u32_be()? as usize;
    let alias_count = cursor.u32_be()? as usize;
    let word_alias_count = if version == 2 {
        cursor.u32_be()? as usize
    } else {
        0
    };
    if row_count == 0
        || row_count > 1 << 18
        || input_count > 1 << 20
        || alias_count > 1 << 20
        || word_alias_count > 1 << 20
    {
        return Err("local SHA program geometry".into());
    }
    let mut rows = Vec::with_capacity(row_count);
    let mut next_input = 0usize;
    for row in 0..row_count {
        let operation = match cursor.u8()? {
            tag @ 0..=1 => {
                let input = cursor.u32_be()? as usize;
                if input != next_input || input >= input_count {
                    return Err("local SHA program input order".into());
                }
                next_input += 1;
                if tag == 0 {
                    LocalShaOperation::Input { input }
                } else {
                    LocalShaOperation::Mask { input }
                }
            }
            2 => LocalShaOperation::Constant {
                literal: cursor.u32_be()?,
            },
            3 => {
                let a = cursor.u32_be()? as usize;
                let shift = cursor.u8()? as u32;
                if a >= row || !(1..=31).contains(&shift) {
                    return Err("local SHA program rotation".into());
                }
                LocalShaOperation::RotateRight { a, shift }
            }
            tag @ 4..=6 => {
                let a = cursor.u32_be()? as usize;
                let b = cursor.u32_be()? as usize;
                if a >= row || b >= row {
                    return Err("local SHA program binary wire".into());
                }
                match tag {
                    4 => LocalShaOperation::Xor { a, b },
                    5 => LocalShaOperation::And { a, b },
                    _ => LocalShaOperation::Add { a, b },
                }
            }
            7 => {
                let a = cursor.u32_be()? as usize;
                if a >= row {
                    return Err("local SHA program unary wire".into());
                }
                LocalShaOperation::Nonzero { a }
            }
            _ => return Err("local SHA program operation".into()),
        };
        rows.push(operation);
    }
    if next_input != input_count {
        return Err("local SHA program input count".into());
    }
    let mut copy_aliases = Vec::with_capacity(alias_count);
    for _ in 0..alias_count {
        let left_wire = cursor.u32_be()? as usize;
        let left_limb = cursor.u8()?;
        let right_wire = cursor.u32_be()? as usize;
        let right_limb = cursor.u8()?;
        if left_wire >= row_count || right_wire >= row_count || left_limb >= 8 || right_limb >= 8 {
            return Err("local SHA program alias".into());
        }
        copy_aliases.push((left_wire, left_limb, right_wire, right_limb));
    }
    let mut word_aliases = Vec::with_capacity(word_alias_count);
    for _ in 0..word_alias_count {
        let left = cursor.u32_be()? as usize;
        let right = cursor.u32_be()? as usize;
        if left >= row_count || right >= row_count {
            return Err("local SHA program word alias".into());
        }
        word_aliases.push((left, right));
    }
    if cursor.offset != bytes.len() {
        return Err("trailing local SHA program bytes".into());
    }
    Ok(LocalShaProgram {
        rows,
        input_count,
        copy_aliases,
        word_aliases,
    })
}

pub fn execute_local_sha_program(
    program: &LocalShaProgram,
    inputs: &[u32],
) -> Result<Vec<u32>, String> {
    if inputs.len() != program.input_count {
        return Err("local SHA input count".into());
    }
    let mut wires: Vec<u32> = Vec::with_capacity(program.rows.len());
    for operation in &program.rows {
        let value = match *operation {
            LocalShaOperation::Input { input } | LocalShaOperation::Mask { input } => inputs[input],
            LocalShaOperation::Constant { literal } => literal,
            LocalShaOperation::RotateRight { a, shift } => wires[a].rotate_right(shift),
            LocalShaOperation::Xor { a, b } => wires[a] ^ wires[b],
            LocalShaOperation::And { a, b } => wires[a] & wires[b],
            LocalShaOperation::Add { a, b } => wires[a].wrapping_add(wires[b]),
            LocalShaOperation::Nonzero { a } => wires[a],
        };
        wires.push(value);
    }
    Ok(wires)
}

pub fn local_sha_program_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn local_sha_wire_digest(wires: &[u32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for wire in wires {
        hasher.update(wire.to_le_bytes());
    }
    hasher.finalize().into()
}

const LOCAL_SHA_LIMBS: usize = 8;
const LOCAL_SHA_COPY_SLOTS_PER_ROW: usize = 24;
const LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW: usize = 3;
const LOCAL_SHA_WORD_PREPROCESSED_COLUMNS: usize = 40;
const LOCAL_SHA_WORD_INTERACTION_COLUMNS: usize = 15;
const LOCAL_SHA_LOOKUP_TABLE_ROWS: usize = 1_841;
const LOCAL_SHA_COPY_INACTIVE_ID: u32 = M31 as u32 - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LocalShaLookupEntry {
    tag: u8,
    a: u32,
    b: u32,
    carry_in: u32,
    out: u32,
    carry_out: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaCopyPermutation {
    pub identities: Vec<u32>,
    pub sigmas: Vec<u32>,
    pub active_slots: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaWordCopyPermutation {
    pub identities: Vec<u32>,
    pub sigmas: Vec<u32>,
    pub active_slots: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaRelationFrame {
    pub row: usize,
    pub original: Vec<u32>,
    pub preprocessed: Vec<u32>,
}

fn local_sha_word_limbs(word: u32) -> [u32; LOCAL_SHA_LIMBS] {
    std::array::from_fn(|limb| (word >> (limb * 4)) & 15)
}

fn local_sha_relation_rows(program: &LocalShaProgram) -> usize {
    program
        .rows
        .len()
        .max(LOCAL_SHA_LOOKUP_TABLE_ROWS)
        .next_power_of_two()
}

fn local_sha_operation_a(operation: &LocalShaOperation) -> Option<usize> {
    match operation {
        LocalShaOperation::RotateRight { a, .. } | LocalShaOperation::Nonzero { a } => Some(*a),
        LocalShaOperation::Xor { a, .. }
        | LocalShaOperation::And { a, .. }
        | LocalShaOperation::Add { a, .. } => Some(*a),
        _ => None,
    }
}

fn local_sha_operation_b(operation: &LocalShaOperation) -> Option<usize> {
    match operation {
        LocalShaOperation::Xor { b, .. }
        | LocalShaOperation::And { b, .. }
        | LocalShaOperation::Add { b, .. } => Some(*b),
        _ => None,
    }
}

fn local_sha_lookup_tag(operation: &LocalShaOperation) -> u8 {
    match operation {
        LocalShaOperation::Input { .. } => 0,
        LocalShaOperation::Mask { .. } => 8,
        LocalShaOperation::Constant { .. } => 1,
        LocalShaOperation::Xor { .. } => 2,
        LocalShaOperation::And { .. } => 3,
        LocalShaOperation::Add { .. } => 4,
        LocalShaOperation::Nonzero { .. } => 9,
        LocalShaOperation::RotateRight { shift, .. } if shift % 4 == 0 => 1,
        LocalShaOperation::RotateRight { shift, .. } => 4 + (shift % 4) as u8,
    }
}

fn local_sha_trace_row(
    operation: Option<&LocalShaOperation>,
    row: usize,
    wires: &[u32],
) -> ([u32; 8], [u32; 8], [u32; 8], [u32; 9]) {
    let Some(operation) = operation else {
        return ([0; 8], [0; 8], [0; 8], [0; 9]);
    };
    let a_word = local_sha_operation_a(operation).map_or(0, |wire| wires[wire]);
    let b_word = local_sha_operation_b(operation).map_or(0, |wire| wires[wire]);
    let mut a = local_sha_word_limbs(a_word);
    let mut b = local_sha_word_limbs(b_word);
    let out = local_sha_word_limbs(wires[row]);
    let mut carry = [0u32; 9];
    if matches!(operation, LocalShaOperation::Add { .. }) {
        for limb in 0..LOCAL_SHA_LIMBS {
            let sum = a[limb] + b[limb] + carry[limb];
            carry[limb + 1] = sum / 16;
        }
    }
    if let LocalShaOperation::RotateRight { shift, .. } = operation {
        let source = local_sha_word_limbs(a_word);
        let limb_shift = (*shift as usize) / 4;
        a = std::array::from_fn(|limb| source[(limb + limb_shift) % LOCAL_SHA_LIMBS]);
        b = if shift % 4 == 0 {
            [0; LOCAL_SHA_LIMBS]
        } else {
            std::array::from_fn(|limb| source[(limb + limb_shift + 1) % LOCAL_SHA_LIMBS])
        };
    }
    (a, b, out, carry)
}

fn local_sha_stitch(bits: u32, a: u32, b: u32) -> u32 {
    ((a >> bits) | ((b & ((1 << bits) - 1)) << (4 - bits))) & 15
}

fn local_sha_lookup_table() -> Vec<LocalShaLookupEntry> {
    let mut result = Vec::with_capacity(LOCAL_SHA_LOOKUP_TABLE_ROWS);
    for out in 0..16 {
        result.push(LocalShaLookupEntry {
            tag: 0,
            a: 0,
            b: 0,
            carry_in: 0,
            out,
            carry_out: 0,
        });
        result.push(LocalShaLookupEntry {
            tag: 1,
            a: out,
            b: 0,
            carry_in: 0,
            out,
            carry_out: 0,
        });
    }
    for out in [0, 15] {
        result.push(LocalShaLookupEntry {
            tag: 8,
            a: 0,
            b: 0,
            carry_in: 0,
            out,
            carry_out: 0,
        });
    }
    for value in 1..16 {
        result.push(LocalShaLookupEntry {
            tag: 9,
            a: value,
            b: 0,
            carry_in: 0,
            out: value,
            carry_out: 0,
        });
    }
    for a in 0..16 {
        for b in 0..16 {
            result.push(LocalShaLookupEntry {
                tag: 2,
                a,
                b,
                carry_in: 0,
                out: a ^ b,
                carry_out: 0,
            });
            result.push(LocalShaLookupEntry {
                tag: 3,
                a,
                b,
                carry_in: 0,
                out: a & b,
                carry_out: 0,
            });
            for carry_in in 0..=1 {
                let sum = a + b + carry_in;
                result.push(LocalShaLookupEntry {
                    tag: 4,
                    a,
                    b,
                    carry_in,
                    out: sum % 16,
                    carry_out: sum / 16,
                });
            }
            for bits in 1..=3 {
                result.push(LocalShaLookupEntry {
                    tag: 4 + bits as u8,
                    a,
                    b,
                    carry_in: 0,
                    out: local_sha_stitch(bits, a, b),
                    carry_out: 0,
                });
            }
        }
    }
    assert_eq!(result.len(), LOCAL_SHA_LOOKUP_TABLE_ROWS);
    result
}

fn local_sha_lookup_entries_at_row(
    operation: &LocalShaOperation,
    row: usize,
    wires: &[u32],
) -> [LocalShaLookupEntry; LOCAL_SHA_LIMBS] {
    let (a, b, out, carry) = local_sha_trace_row(Some(operation), row, wires);
    let literal = match operation {
        LocalShaOperation::Constant { literal } => local_sha_word_limbs(*literal),
        _ => [0; LOCAL_SHA_LIMBS],
    };
    let tag = local_sha_lookup_tag(operation);
    std::array::from_fn(|limb| LocalShaLookupEntry {
        tag,
        a: a[limb] + literal[limb],
        b: b[limb],
        carry_in: carry[limb],
        out: out[limb],
        carry_out: carry[limb + 1],
    })
}

pub fn local_sha_table_multiplicities(
    program: &LocalShaProgram,
    wires: &[u32],
) -> Result<Vec<u32>, String> {
    if wires.len() != program.rows.len() {
        return Err("local SHA multiplicity execution".into());
    }
    let table = local_sha_lookup_table();
    let table_index: HashMap<LocalShaLookupEntry, usize> = table
        .iter()
        .copied()
        .enumerate()
        .map(|(index, entry)| (entry, index))
        .collect();
    let mut multiplicities = vec![0u32; table.len()];
    for (row, operation) in program.rows.iter().enumerate() {
        for entry in local_sha_lookup_entries_at_row(operation, row, wires) {
            let index = *table_index
                .get(&entry)
                .ok_or("local SHA invalid lookup row")?;
            multiplicities[index] = multiplicities[index]
                .checked_add(1)
                .ok_or("local SHA multiplicity overflow")?;
        }
    }
    if multiplicities.iter().any(|value| *value as u64 >= M31) {
        return Err("local SHA table multiplicity M31".into());
    }
    Ok(multiplicities)
}

fn local_sha_find(parent: &mut [u32], cell: usize) -> usize {
    let mut root = cell;
    while parent[root] as usize != root {
        root = parent[root] as usize;
    }
    let mut cursor = cell;
    while parent[cursor] as usize != cursor {
        let next = parent[cursor] as usize;
        parent[cursor] = root as u32;
        cursor = next;
    }
    root
}

pub fn compile_local_sha_copy_permutation(
    program: &LocalShaProgram,
) -> Result<LocalShaCopyPermutation, String> {
    let wire_cells = program
        .rows
        .len()
        .checked_mul(LOCAL_SHA_LIMBS)
        .ok_or("local SHA wire cells")?;
    let slot_count = local_sha_relation_rows(program)
        .checked_mul(LOCAL_SHA_COPY_SLOTS_PER_ROW)
        .ok_or("local SHA copy slots")?;
    let mut parent: Vec<u32> = (0..wire_cells)
        .map(|cell| u32::try_from(cell).map_err(|_| "local SHA wire cell M31"))
        .collect::<Result<_, _>>()?;
    for &(left_wire, left_limb, right_wire, right_limb) in &program.copy_aliases {
        let left = left_wire * LOCAL_SHA_LIMBS + left_limb as usize;
        let right = right_wire * LOCAL_SHA_LIMBS + right_limb as usize;
        let left_root = local_sha_find(&mut parent, left);
        let right_root = local_sha_find(&mut parent, right);
        if left_root != right_root {
            parent[right_root] = left_root as u32;
        }
    }
    for &(left_wire, right_wire) in &program.word_aliases {
        if left_wire >= program.rows.len() || right_wire >= program.rows.len() {
            return Err("local SHA word alias".into());
        }
        for limb in 0..LOCAL_SHA_LIMBS {
            let left = left_wire * LOCAL_SHA_LIMBS + limb;
            let right = right_wire * LOCAL_SHA_LIMBS + limb;
            let left_root = local_sha_find(&mut parent, left);
            let right_root = local_sha_find(&mut parent, right);
            if left_root != right_root {
                parent[right_root] = left_root as u32;
            }
        }
    }
    let mut identities = vec![LOCAL_SHA_COPY_INACTIVE_ID; slot_count];
    let mut sigmas = vec![LOCAL_SHA_COPY_INACTIVE_ID; slot_count];
    let mut first_identity = vec![0u32; wire_cells];
    let mut last_slot = vec![-1i32; wire_cells];
    let mut identity = 1u32;
    let mut add = |row: usize,
                   port: usize,
                   limb: usize,
                   wire: usize,
                   wire_limb: usize|
     -> Result<(), String> {
        let slot = row * LOCAL_SHA_COPY_SLOTS_PER_ROW + port * LOCAL_SHA_LIMBS + limb;
        let root = local_sha_find(&mut parent, wire * LOCAL_SHA_LIMBS + wire_limb);
        identities[slot] = identity;
        let previous = last_slot[root];
        if previous < 0 {
            first_identity[root] = identity;
        } else {
            sigmas[previous as usize] = identity;
        }
        last_slot[root] = i32::try_from(slot).map_err(|_| "local SHA copy slot")?;
        identity = identity.checked_add(1).ok_or("local SHA copy identity")?;
        Ok(())
    };
    for (row, operation) in program.rows.iter().enumerate() {
        for limb in 0..LOCAL_SHA_LIMBS {
            add(row, 2, limb, row, limb)?;
            if let Some(a) = local_sha_operation_a(operation) {
                let mapped = match operation {
                    LocalShaOperation::RotateRight { shift, .. } => {
                        (limb + *shift as usize / 4) % LOCAL_SHA_LIMBS
                    }
                    _ => limb,
                };
                add(row, 0, limb, a, mapped)?;
            }
            if let Some(b) = local_sha_operation_b(operation).or_else(|| {
                if let LocalShaOperation::RotateRight { a, shift } = operation {
                    if shift % 4 != 0 {
                        Some(*a)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }) {
                let mapped = match operation {
                    LocalShaOperation::RotateRight { shift, .. } => {
                        (limb + *shift as usize / 4 + 1) % LOCAL_SHA_LIMBS
                    }
                    _ => limb,
                };
                add(row, 1, limb, b, mapped)?;
            }
        }
    }
    drop(add);
    if identity as u64 >= M31 {
        return Err("local SHA copy identities exceed M31".into());
    }
    for root in 0..last_slot.len() {
        let slot = last_slot[root];
        if slot >= 0 {
            sigmas[slot as usize] = first_identity[root];
        }
    }
    Ok(LocalShaCopyPermutation {
        identities,
        sigmas,
        active_slots: identity as usize - 1,
    })
}

pub fn local_sha_relation_frame_at(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaCopyPermutation,
    multiplicities: &[u32],
    row: usize,
) -> Result<LocalShaRelationFrame, String> {
    let relation_rows = local_sha_relation_rows(program);
    if row >= relation_rows
        || wires.len() != program.rows.len()
        || permutation.identities.len() != relation_rows * LOCAL_SHA_COPY_SLOTS_PER_ROW
        || permutation.sigmas.len() != permutation.identities.len()
        || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS
    {
        return Err("local SHA relation frame geometry".into());
    }
    let operation = program.rows.get(row);
    let (a, b, out, carry) = local_sha_trace_row(operation, row, wires);
    let mut original = Vec::with_capacity(34);
    original.extend(a);
    original.extend(b);
    original.extend(out);
    original.extend(carry);
    original.push(multiplicities.get(row).copied().unwrap_or(0));

    let literal = match operation {
        Some(LocalShaOperation::Constant { literal }) => local_sha_word_limbs(*literal),
        _ => [0; LOCAL_SHA_LIMBS],
    };
    let mut preprocessed = Vec::with_capacity(64);
    preprocessed.push(operation.map_or(0, local_sha_lookup_tag) as u32);
    preprocessed.extend(literal);
    let slot_start = row * LOCAL_SHA_COPY_SLOTS_PER_ROW;
    for slot in 0..LOCAL_SHA_COPY_SLOTS_PER_ROW {
        let index = slot_start + slot;
        preprocessed.push(permutation.identities[index]);
        preprocessed.push(permutation.sigmas[index]);
    }
    preprocessed.push(u32::from(operation.is_some()));
    if let Some(table) = local_sha_lookup_table().get(row).copied() {
        preprocessed.extend([
            table.tag as u32,
            table.a,
            table.b,
            table.carry_in,
            table.out,
            table.carry_out,
        ]);
    } else {
        preprocessed.extend([0; 6]);
    }
    if original.len() != 34 || preprocessed.len() != 64 {
        return Err("local SHA relation frame width".into());
    }
    Ok(LocalShaRelationFrame {
        row,
        original,
        preprocessed,
    })
}

fn local_sha_normalized_cell_alias(
    left_wire: usize,
    left_limb: u8,
    right_wire: usize,
    right_limb: u8,
) -> (usize, usize) {
    let left = left_wire * LOCAL_SHA_LIMBS + left_limb as usize;
    let right = right_wire * LOCAL_SHA_LIMBS + right_limb as usize;
    if left < right {
        (left, right)
    } else {
        (right, left)
    }
}

fn assert_local_sha_only_legacy_mask_cell_aliases(program: &LocalShaProgram) -> Result<(), String> {
    let mut expected = std::collections::HashSet::new();
    for (row, operation) in program.rows.iter().enumerate() {
        if !matches!(operation, LocalShaOperation::Mask { .. }) {
            continue;
        }
        for limb in 1..LOCAL_SHA_LIMBS {
            expected.insert(local_sha_normalized_cell_alias(row, 0, row, limb as u8));
        }
    }
    if program.copy_aliases.len() != expected.len() {
        return Err("local SHA word copy unsupported cell alias".into());
    }
    for &(left_wire, left_limb, right_wire, right_limb) in &program.copy_aliases {
        if !expected.remove(&local_sha_normalized_cell_alias(
            left_wire, left_limb, right_wire, right_limb,
        )) {
            return Err("local SHA word copy unsupported cell alias".into());
        }
    }
    if !expected.is_empty() {
        return Err("local SHA word copy missing mask alias".into());
    }
    Ok(())
}

fn local_sha_word_port(operation: &LocalShaOperation, row: usize, port: usize) -> Option<usize> {
    match port {
        0 => local_sha_operation_a(operation),
        1 => match operation {
            LocalShaOperation::RotateRight { a, shift } if shift % 4 != 0 => Some(*a),
            _ => local_sha_operation_b(operation),
        },
        2 => Some(row),
        _ => None,
    }
}

fn local_sha_word_shift(operation: &LocalShaOperation, row: usize, port: usize) -> Option<usize> {
    local_sha_word_port(operation, row, port)?;
    Some(match (operation, port) {
        (LocalShaOperation::RotateRight { shift, .. }, 0) => *shift as usize / 4,
        (LocalShaOperation::RotateRight { shift, .. }, 1) => {
            (*shift as usize / 4 + 1) % LOCAL_SHA_LIMBS
        }
        _ => 0,
    })
}

fn compile_local_sha_word_copy_permutation_with_rows(
    program: &LocalShaProgram,
    relation_rows: usize,
) -> Result<LocalShaWordCopyPermutation, String> {
    assert_local_sha_only_legacy_mask_cell_aliases(program)?;
    if !relation_rows.is_power_of_two() || relation_rows < local_sha_relation_rows(program) {
        return Err("local SHA word copy relation rows".into());
    }
    let slot_count = relation_rows
        .checked_mul(LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW)
        .ok_or("local SHA word copy slots")?;
    let mut parent: Vec<u32> = (0..program.rows.len())
        .map(|wire| u32::try_from(wire).map_err(|_| "local SHA word wire M31"))
        .collect::<Result<_, _>>()?;
    for &(left, right) in &program.word_aliases {
        if left >= program.rows.len() || right >= program.rows.len() {
            return Err("local SHA word alias".into());
        }
        let left_root = local_sha_find(&mut parent, left);
        let right_root = local_sha_find(&mut parent, right);
        if left_root != right_root {
            parent[right_root] = left_root as u32;
        }
    }
    let mut identities = vec![LOCAL_SHA_COPY_INACTIVE_ID; slot_count];
    let mut sigmas = vec![LOCAL_SHA_COPY_INACTIVE_ID; slot_count];
    let mut first_identity = vec![0u32; program.rows.len()];
    let mut last_slot = vec![-1i32; program.rows.len()];
    let mut identity = 1u32;
    for (row, operation) in program.rows.iter().enumerate() {
        for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
            let Some(wire) = local_sha_word_port(operation, row, port) else {
                continue;
            };
            let root = local_sha_find(&mut parent, wire);
            let slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
            identities[slot] = identity;
            let previous = last_slot[root];
            if previous < 0 {
                first_identity[root] = identity;
            } else {
                sigmas[previous as usize] = identity;
            }
            last_slot[root] = i32::try_from(slot).map_err(|_| "local SHA word copy slot")?;
            identity = identity
                .checked_add(1)
                .ok_or("local SHA word copy identity")?;
        }
    }
    if identity as u64 >= M31 {
        return Err("local SHA word copy identities exceed M31".into());
    }
    for root in 0..last_slot.len() {
        let slot = last_slot[root];
        if slot >= 0 {
            sigmas[slot as usize] = first_identity[root];
        }
    }
    Ok(LocalShaWordCopyPermutation {
        identities,
        sigmas,
        active_slots: identity as usize - 1,
    })
}

pub fn compile_local_sha_word_copy_permutation(
    program: &LocalShaProgram,
) -> Result<LocalShaWordCopyPermutation, String> {
    compile_local_sha_word_copy_permutation_with_rows(program, local_sha_relation_rows(program))
}

/** Compile the same word-copy permutation in an explicitly larger fixed domain. */
pub fn compile_local_sha_word_copy_permutation_for_rows(
    program: &LocalShaProgram,
    relation_rows: usize,
) -> Result<LocalShaWordCopyPermutation, String> {
    compile_local_sha_word_copy_permutation_with_rows(program, relation_rows)
}

fn local_sha_word_copy_relation_rows(
    program: &LocalShaProgram,
    permutation: &LocalShaWordCopyPermutation,
) -> Result<usize, String> {
    if permutation.identities.len() % LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW != 0 {
        return Err("local SHA word copy relation geometry".into());
    }
    let relation_rows = permutation.identities.len() / LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
    if !relation_rows.is_power_of_two()
        || relation_rows < local_sha_relation_rows(program)
        || permutation.sigmas.len() != permutation.identities.len()
    {
        return Err("local SHA word copy relation geometry".into());
    }
    Ok(relation_rows)
}

pub fn local_sha_word_relation_frame_at(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
    row: usize,
) -> Result<LocalShaRelationFrame, String> {
    let relation_rows = local_sha_word_copy_relation_rows(program, permutation)
        .map_err(|_| "local SHA word relation frame geometry")?;
    if row >= relation_rows
        || wires.len() != program.rows.len()
        || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS
    {
        return Err("local SHA word relation frame geometry".into());
    }
    let operation = program.rows.get(row);
    let (a, b, out, carry) = local_sha_trace_row(operation, row, wires);
    let mut original = Vec::with_capacity(34);
    original.extend(a);
    original.extend(b);
    original.extend(out);
    original.extend(carry);
    original.push(multiplicities.get(row).copied().unwrap_or(0));

    let literal = match operation {
        Some(LocalShaOperation::Constant { literal }) => local_sha_word_limbs(*literal),
        _ => [0; LOCAL_SHA_LIMBS],
    };
    let mut preprocessed = Vec::with_capacity(LOCAL_SHA_WORD_PREPROCESSED_COLUMNS);
    preprocessed.push(operation.map_or(0, local_sha_lookup_tag) as u32);
    preprocessed.extend(literal);
    for port in 0..2 {
        let shift = operation.and_then(|value| local_sha_word_shift(value, row, port));
        preprocessed
            .extend((0..LOCAL_SHA_LIMBS).map(|candidate| u32::from(shift == Some(candidate))));
    }
    let slot_start = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW;
    for slot in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
        let index = slot_start + slot;
        preprocessed.push(permutation.identities[index]);
        preprocessed.push(permutation.sigmas[index]);
    }
    preprocessed.push(u32::from(operation.is_some()));
    preprocessed.push(u32::from(matches!(
        operation,
        Some(LocalShaOperation::Mask { .. })
    )));
    preprocessed.push(u32::from(row + 1 == relation_rows));
    if let Some(table) = local_sha_lookup_table().get(row).copied() {
        preprocessed.extend([
            table.tag as u32,
            table.a,
            table.b,
            table.carry_in,
            table.out,
            table.carry_out,
        ]);
    } else {
        preprocessed.extend([0; 6]);
    }
    if original.len() != 34 || preprocessed.len() != LOCAL_SHA_WORD_PREPROCESSED_COLUMNS {
        return Err("local SHA word relation frame width".into());
    }
    Ok(LocalShaRelationFrame {
        row,
        original,
        preprocessed,
    })
}

const LOCAL_SHA_INTERACTION_FRACTIONS: usize = 9 + 2 * LOCAL_SHA_COPY_SLOTS_PER_ROW * 2;
const LOCAL_SHA_INTERACTION_COLUMNS: usize = LOCAL_SHA_INTERACTION_FRACTIONS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalShaCopyChallenges {
    pub gamma: Qm31Value,
    pub identity: Qm31Value,
    pub value: Qm31Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalShaInteractionChallenges {
    pub lookup_gamma: Qm31Value,
    pub lookup_tuple: [Qm31Value; 6],
    pub copy: [LocalShaCopyChallenges; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalShaWordCopyChallenges {
    pub gamma: Qm31Value,
    pub identity: Qm31Value,
    pub limbs: [Qm31Value; LOCAL_SHA_LIMBS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalShaV14InteractionChallenges {
    pub lookup_gamma: Qm31Value,
    pub lookup_tuple: [Qm31Value; 6],
    pub word_copy: LocalShaWordCopyChallenges,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaInteractionSample {
    pub row: usize,
    pub columns: Vec<Qm31Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaInteractionSamples {
    pub relation_rows: usize,
    pub claimed_sum: Qm31Value,
    pub samples: Vec<LocalShaInteractionSample>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalShaV14InteractionSamples {
    pub relation_rows: usize,
    pub lookup_claimed_sum: Qm31Value,
    pub final_word_product: Qm31Value,
    pub samples: Vec<LocalShaInteractionSample>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordPublicWord {
    pub id: u16,
    pub row: usize,
    pub expected: u32,
}

#[derive(Clone, Debug)]
pub struct LocalWordProverBundle {
    pub profile: u8,
    pub relation_rows: usize,
    pub transcript_initial: Vec<u8>,
    pub construction_descriptor: Vec<u8>,
    pub program_bytes: Vec<u8>,
    pub program: LocalShaProgram,
    pub inputs: Vec<u32>,
    pub public_words: Vec<LocalWordPublicWord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalWordBoundaryChallenges {
    pub gamma: Qm31Value,
    pub identity: Qm31Value,
    pub limbs: [Qm31Value; LOCAL_SHA_LIMBS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordBoundarySamples {
    pub relation_rows: usize,
    pub claimed_sum: Qm31Value,
    pub public_inverses: Vec<Qm31Value>,
    pub samples: Vec<(usize, [Qm31Value; 2])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordRelationMatrices {
    /** A, B, output, carries, and private table multiplicity. */
    pub original: Vec<Vec<u32>>,
    /** Core microcode/table plus the public-word selector and identity. */
    pub preprocessed: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordInteractionMatrix {
    /** 15 quadratic core QM31 columns plus two public-boundary columns. */
    pub columns: Vec<Vec<u32>>,
    pub boundary_claimed_sum: Qm31Value,
    pub boundary_inverses: Vec<Qm31Value>,
}

pub const LOCAL_WORD_ORIGINAL_COLUMNS: usize = 34;
pub const LOCAL_WORD_PREPROCESSED_COLUMNS: usize = LOCAL_SHA_WORD_PREPROCESSED_COLUMNS + 3;
pub const LOCAL_WORD_INTERACTION_COLUMNS: usize = LOCAL_SHA_WORD_INTERACTION_COLUMNS + 2;
pub const LOCAL_WORD_AIR_CONSTRAINTS: usize = 25;
pub const LOCAL_WORD_AIR_PARTIAL_WIDTHS: [usize; 3] = [9, 8, 8];
/** Three balanced current groups; group 3 alone is also opened at the predecessor. */
pub const LOCAL_WORD_INTERACTION_GROUP_M31_WIDTHS: [usize; 4] = [20, 20, 16, 12];
pub const LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH: usize = 20 + 20 + 16;
pub const LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH: usize = 12;
pub const LOCAL_WORD_GLOBAL_INTERACTION_QM31_COLUMNS: [usize; 3] = [8, 14, 16];
pub const LOCAL_WORD_INTERACTION_CHALLENGE_COUNT: usize = 27;
const LOCAL_WORD_INTERACTION_COMMIT_ORDER: [usize; 17] =
    [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 8, 14, 16];

pub const LOCAL_WORD_EVAL_LOG: u32 = 24;
pub const LOCAL_WORD_RELATION_LOG: u32 = 18;
pub const LOCAL_WORD_PRIVATE_SEAL_BLOWUP: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalWordProofParameters {
    relation_log: u32,
    eval_log: u32,
    quotient_degree_rows: usize,
    fri: SuccessorFriConfig,
}

impl LocalWordProofParameters {
    const PRODUCTION: Self = Self {
        relation_log: LOCAL_WORD_RELATION_LOG,
        eval_log: LOCAL_WORD_EVAL_LOG,
        quotient_degree_rows: 1 << 20,
        fri: LOCAL_WORD_FRI_CONFIG,
    };

    fn validate(self) -> Result<(), String> {
        let seal_blowup = self
            .eval_log
            .checked_sub(self.relation_log + 1)
            .ok_or("local-word proof domain")?;
        let final_log = self
            .fri
            .final_log_degree
            .checked_add(self.fri.log_blowup)
            .ok_or("local-word FRI domain")?;
        if self.relation_log < 1
            || self.eval_log > 30
            || seal_blowup > 16
            || final_log >= self.eval_log
            || self.quotient_degree_rows < 2
            || !self.quotient_degree_rows.is_power_of_two()
            || self.quotient_degree_rows > 1usize << self.eval_log
            || self.quotient_degree_rows > 1usize << (self.eval_log - self.fri.log_blowup)
            || self.fri.queries == 0
            || self.fri.queries > (1usize << self.eval_log) / 2
            || self.fri.fold_log != 2
            || self.fri.query_orbit_log
                != self.eval_log - self.fri.log_blowup - self.fri.final_log_degree
            || self.eval_log % 2 != 0
        {
            return Err("local-word proof parameters".into());
        }
        Ok(())
    }

    fn private_seal_blowup(self) -> Result<u32, String> {
        self.validate()?;
        Ok(self.eval_log - self.relation_log - 1)
    }

    fn row_count(self) -> usize {
        1usize << self.eval_log
    }

    fn fri_layers(self) -> usize {
        self.fri_fold_counts().len()
    }

    fn fri_fold_counts(self) -> Vec<u32> {
        fri_fold_counts(
            self.eval_log,
            self.fri.log_blowup + self.fri.final_log_degree,
            self.fri.fold_log,
        )
        .expect("validated local-word FRI folds")
    }

    fn fri_layer_logs(self) -> Vec<u32> {
        let mut log = self.eval_log;
        self.fri_fold_counts()
            .into_iter()
            .map(|folds| {
                let layer_log = log;
                log -= folds;
                layer_log
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordCommittedRelation {
    pub preprocessed: DiskMatrixCommitment,
    pub original: DiskMatrixCommitment,
    /** Groups 0, 1, and 2 share one current-row commitment. */
    pub interaction: DiskMatrixCommitment,
    /** Group 3 alone requires current and cyclic-predecessor rows. */
    pub interaction_global: DiskMatrixCommitment,
    pub interaction_challenges: LocalShaV14InteractionChallenges,
    pub boundary_challenges: LocalWordBoundaryChallenges,
    pub boundary_claimed_sum: Qm31Value,
    pub boundary_inverses: Vec<Qm31Value>,
    pub interaction_transcript_digest: [u8; 32],
    pub constraint_alpha: Qm31Value,
    pub composition_transcript_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalWordCompositionEvaluation {
    pub composition: Qm31Value,
    pub quotient: Qm31Value,
    pub zerofier: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordSealedQuotient {
    /** Quotient derived only from already-sealed relation oracles. */
    pub quotient: DiskMatrixCommitment,
    /** Fresh, independent polynomial used only to isolate the FRI transcript. */
    pub fri_mask: DiskMatrixCommitment,
    /** One transcript commitment to sealed quotient followed by the FRI mask. */
    pub quotient_and_fri_mask: DiskMatrixCommitment,
}

pub const LOCAL_WORD_PROOF_VERSION: u8 = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordTranscriptManifest {
    pub interaction_challenges: Vec<Qm31Value>,
    pub interaction_digest: [u8; 32],
    pub constraint_alpha: Qm31Value,
    pub composition_digest: [u8; 32],
    pub batch_beta: Qm31Value,
    pub batch_digest: [u8; 32],
    pub fri_alphas: Vec<Qm31Value>,
    pub fri_mid_digest: [u8; 32],
    pub fri_roots_digest: [u8; 32],
    pub query_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordSealedProof {
    pub version: u8,
    pub profile: u8,
    pub construction_digest: [u8; 32],
    pub public_boundary_inverses: Vec<Qm31Value>,
    pub public_boundary_claimed_sum: Qm31Value,
    pub preprocessed: SuccessorMatrixOpening,
    pub original: SuccessorMatrixOpening,
    /** Groups 0, 1, and 2 in their canonical column order. */
    pub interaction: SuccessorMatrixOpening,
    /** Group 3 at current and cyclic-predecessor rows. */
    pub interaction_global: SuccessorMatrixOpening,
    /** Sealed quotient followed by the independent FRI isolator. */
    pub quotient_and_fri_mask: SuccessorMatrixOpening,
    pub fri: SuccessorFriProof,
    pub transcript_manifest: LocalWordTranscriptManifest,
    /** Transcript-derived and serialized once as a VM-checked manifest. */
    pub queries: Vec<usize>,
    /** Three checked contiguous AIR Horner segments for each transcript query. */
    pub composition_partials: Vec<[Qm31Value; 3]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordProveResult {
    pub proof: LocalWordSealedProof,
    pub quotient_degree_bound: usize,
    pub workspace: std::path::PathBuf,
}

pub fn local_word_interaction_transcript(
    initial: &[u8],
    descriptor_digest: [u8; 32],
    preprocessed_root: [u8; 32],
    original_root: [u8; 32],
) -> (
    SuccessorTranscript,
    LocalShaInteractionChallenges,
    LocalWordBoundaryChallenges,
) {
    let mut transcript = SuccessorTranscript::new(initial);
    transcript.absorb("local-word-descriptor", &descriptor_digest);
    transcript.absorb("local-word-preprocessed-root", &preprocessed_root);
    transcript.absorb("local-word-original-root", &original_root);
    let lookup_gamma = transcript.challenge_qm31("local-word-lookup-gamma");
    let lookup_tuple = std::array::from_fn(|index| {
        transcript.challenge_qm31(&format!("local-word-lookup-tuple-{index}"))
    });
    let copy = std::array::from_fn(|lane| LocalShaCopyChallenges {
        gamma: transcript.challenge_qm31(&format!("local-word-copy-{lane}-gamma")),
        identity: transcript.challenge_qm31(&format!("local-word-copy-{lane}-identity")),
        value: transcript.challenge_qm31(&format!("local-word-copy-{lane}-value")),
    });
    let boundary = LocalWordBoundaryChallenges {
        gamma: transcript.challenge_qm31("local-word-boundary-gamma"),
        identity: transcript.challenge_qm31("local-word-boundary-identity"),
        limbs: std::array::from_fn(|limb| {
            transcript.challenge_qm31(&format!("local-word-boundary-limb-{limb}"))
        }),
    };
    (
        transcript,
        LocalShaInteractionChallenges {
            lookup_gamma,
            lookup_tuple,
            copy,
        },
        boundary,
    )
}

pub fn local_word_v15_interaction_transcript(
    initial: &[u8],
    descriptor_digest: [u8; 32],
    preprocessed_root: [u8; 32],
    original_root: [u8; 32],
) -> (
    SuccessorTranscript,
    LocalShaV14InteractionChallenges,
    LocalWordBoundaryChallenges,
) {
    let mut transcript = SuccessorTranscript::new(initial);
    transcript.absorb("local-word-v15-descriptor", &descriptor_digest);
    transcript.absorb("local-word-v15-preprocessed-root", &preprocessed_root);
    transcript.absorb("local-word-v15-original-root", &original_root);
    let lookup_gamma = transcript.challenge_qm31("local-word-v15-lookup-gamma");
    let lookup_tuple = std::array::from_fn(|index| {
        transcript.challenge_qm31(&format!("local-word-v15-lookup-tuple-{index}"))
    });
    let word_copy = LocalShaWordCopyChallenges {
        gamma: transcript.challenge_qm31("local-word-v15-copy-gamma"),
        identity: transcript.challenge_qm31("local-word-v15-copy-identity"),
        limbs: std::array::from_fn(|limb| {
            transcript.challenge_qm31(&format!("local-word-v15-copy-limb-{limb}"))
        }),
    };
    let boundary = LocalWordBoundaryChallenges {
        gamma: transcript.challenge_qm31("local-word-v15-boundary-gamma"),
        identity: transcript.challenge_qm31("local-word-v15-boundary-identity"),
        limbs: std::array::from_fn(|limb| {
            transcript.challenge_qm31(&format!("local-word-v15-boundary-limb-{limb}"))
        }),
    };
    (
        transcript,
        LocalShaV14InteractionChallenges {
            lookup_gamma,
            lookup_tuple,
            word_copy,
        },
        boundary,
    )
}

pub fn local_word_v15_interaction_challenge_values(
    interaction: &LocalShaV14InteractionChallenges,
    boundary: &LocalWordBoundaryChallenges,
) -> Vec<Qm31Value> {
    let mut values = Vec::with_capacity(27);
    values.push(interaction.lookup_gamma);
    values.extend(interaction.lookup_tuple);
    values.extend([interaction.word_copy.gamma, interaction.word_copy.identity]);
    values.extend(interaction.word_copy.limbs);
    values.extend([boundary.gamma, boundary.identity]);
    values.extend(boundary.limbs);
    assert_eq!(values.len(), 27);
    values
}

pub fn local_word_v15_composition_transcript(
    transcript: &mut SuccessorTranscript,
    interaction_root: [u8; 32],
    interaction_global_root: [u8; 32],
) -> (Qm31Value, [u8; 32]) {
    transcript.absorb("local-word-v15-interaction-root", &interaction_root);
    transcript.absorb(
        "local-word-v15-interaction-global-root",
        &interaction_global_root,
    );
    let constraint_alpha = transcript.challenge_qm31("local-word-v15-constraint-alpha");
    (constraint_alpha, transcript.digest())
}

pub fn local_word_v15_public_boundary_transcript(
    transcript: &mut SuccessorTranscript,
    public_inverses: &[Qm31Value],
) -> Result<[u8; 32], String> {
    if public_inverses.is_empty()
        || public_inverses.len() > 1024
        || public_inverses
            .iter()
            .flatten()
            .any(|value| *value as u64 >= M31)
    {
        return Err("local-word v15 public boundary transcript".into());
    }
    transcript.absorb(
        "local-word-v15-public-boundary",
        &encode_qm31_values(public_inverses),
    );
    Ok(transcript.digest())
}

pub fn local_word_interaction_challenge_values(
    interaction: &LocalShaInteractionChallenges,
    boundary: &LocalWordBoundaryChallenges,
) -> Vec<Qm31Value> {
    let mut values = Vec::with_capacity(23);
    values.push(interaction.lookup_gamma);
    values.extend(interaction.lookup_tuple);
    for copy in interaction.copy {
        values.extend([copy.gamma, copy.identity, copy.value]);
    }
    values.extend([boundary.gamma, boundary.identity]);
    values.extend(boundary.limbs);
    assert_eq!(values.len(), 23);
    values
}

pub fn local_word_composition_transcript(
    transcript: &mut SuccessorTranscript,
    interaction_root: [u8; 32],
    interaction_global_root: [u8; 32],
) -> (Qm31Value, [u8; 32]) {
    transcript.absorb("local-word-interaction-root", &interaction_root);
    transcript.absorb(
        "local-word-interaction-global-root",
        &interaction_global_root,
    );
    let constraint_alpha = transcript.challenge_qm31("local-word-constraint-alpha");
    (constraint_alpha, transcript.digest())
}

pub fn local_word_public_boundary_transcript(
    transcript: &mut SuccessorTranscript,
    public_inverses: &[Qm31Value],
) -> Result<[u8; 32], String> {
    if public_inverses.is_empty()
        || public_inverses.len() > 1024
        || public_inverses
            .iter()
            .flatten()
            .any(|value| *value as u64 >= M31)
    {
        return Err("local-word public boundary transcript".into());
    }
    transcript.absorb(
        "local-word-public-boundary",
        &encode_qm31_values(public_inverses),
    );
    Ok(transcript.digest())
}

fn local_sha_qm_linear(gamma: Qm31Value, challenges: &[Qm31Value], values: &[u32]) -> SecureField {
    assert_eq!(challenges.len(), values.len());
    challenges
        .iter()
        .zip(values)
        .fold(qm31_to_secure(gamma), |sum, (challenge, value)| {
            sum + qm31_to_secure(*challenge) * BaseField::from_u32_unchecked(*value)
        })
}

fn local_sha_lookup_denominator(
    entry: LocalShaLookupEntry,
    challenges: &LocalShaInteractionChallenges,
) -> SecureField {
    local_sha_qm_linear(
        challenges.lookup_gamma,
        &challenges.lookup_tuple,
        &[
            entry.tag as u32,
            entry.a,
            entry.b,
            entry.carry_in,
            entry.out,
            entry.carry_out,
        ],
    )
}

fn local_sha_copy_denominator(
    identity: u32,
    value: u32,
    challenges: &LocalShaCopyChallenges,
) -> SecureField {
    local_sha_qm_linear(
        challenges.gamma,
        &[challenges.identity, challenges.value],
        &[identity, value],
    )
}

fn local_sha_v14_lookup_denominator(
    entry: LocalShaLookupEntry,
    challenges: &LocalShaV14InteractionChallenges,
) -> SecureField {
    local_sha_qm_linear(
        challenges.lookup_gamma,
        &challenges.lookup_tuple,
        &[
            entry.tag as u32,
            entry.a,
            entry.b,
            entry.carry_in,
            entry.out,
            entry.carry_out,
        ],
    )
}

fn local_sha_word_compressed_value(
    operation: Option<&LocalShaOperation>,
    row: usize,
    wires: &[u32],
    port: usize,
    challenges: &LocalShaWordCopyChallenges,
) -> SecureField {
    let Some(operation) = operation else {
        return qm31_to_secure([0; 4]);
    };
    let Some(shift) = local_sha_word_shift(operation, row, port) else {
        return qm31_to_secure([0; 4]);
    };
    let (a, b, out, _) = local_sha_trace_row(Some(operation), row, wires);
    let values = match port {
        0 => a,
        1 => b,
        2 => out,
        _ => return qm31_to_secure([0; 4]),
    };
    values
        .iter()
        .enumerate()
        .fold(qm31_to_secure([0; 4]), |sum, (limb, value)| {
            sum + qm31_to_secure(challenges.limbs[(limb + shift) % LOCAL_SHA_LIMBS])
                * BaseField::from_u32_unchecked(*value)
        })
}

fn local_sha_word_product_term(
    identity: u32,
    compressed: SecureField,
    challenges: &LocalShaWordCopyChallenges,
) -> SecureField {
    qm31_to_secure(challenges.gamma)
        + qm31_to_secure(challenges.identity) * BaseField::from_u32_unchecked(identity)
        + compressed
}

fn walk_local_sha_v14_interaction<F>(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
    challenges: &LocalShaV14InteractionChallenges,
    mut observe: F,
) -> Result<(Qm31Value, Qm31Value), String>
where
    F: FnMut(usize, &[SecureField; LOCAL_SHA_WORD_INTERACTION_COLUMNS]),
{
    let relation_rows = local_sha_word_copy_relation_rows(program, permutation)
        .map_err(|_| "local SHA v14 interaction geometry")?;
    if wires.len() != program.rows.len() || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS {
        return Err("local SHA v14 interaction geometry".into());
    }
    let table = local_sha_lookup_table();
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let mut lookup_claimed_sum = zero;
    let mut word_product = one;
    const CHUNK_ROWS: usize = 4_096;
    for chunk_start in (0..relation_rows).step_by(CHUNK_ROWS) {
        let chunk_end = (chunk_start + CHUNK_ROWS).min(relation_rows);
        let mut denominators = Vec::with_capacity((chunk_end - chunk_start) * 12);
        for row in chunk_start..chunk_end {
            let operation = program.rows.get(row);
            if let Some(operation) = operation {
                for entry in local_sha_lookup_entries_at_row(operation, row, wires) {
                    denominators.push(local_sha_v14_lookup_denominator(entry, challenges));
                }
            } else {
                denominators.extend([one; LOCAL_SHA_LIMBS]);
            }
            denominators.push(table.get(row).copied().map_or(one, |entry| {
                local_sha_v14_lookup_denominator(entry, challenges)
            }));
            for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
                let slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
                let compressed = local_sha_word_compressed_value(
                    operation,
                    row,
                    wires,
                    port,
                    &challenges.word_copy,
                );
                denominators.push(local_sha_word_product_term(
                    permutation.sigmas[slot],
                    compressed,
                    &challenges.word_copy,
                ));
            }
        }
        let inverses = local_sha_batch_inverse(&denominators)?;
        for row in chunk_start..chunk_end {
            let operation = program.rows.get(row);
            let base = (row - chunk_start) * 12;
            let mut columns = [zero; LOCAL_SHA_WORD_INTERACTION_COLUMNS];
            let mut row_cumulative = zero;
            for limb in 0..LOCAL_SHA_LIMBS {
                if operation.is_some() {
                    row_cumulative += inverses[base + limb];
                }
                columns[limb] = row_cumulative;
            }
            if table.get(row).is_some() {
                row_cumulative -=
                    inverses[base + 8] * BaseField::from_u32_unchecked(multiplicities[row]);
            }
            lookup_claimed_sum += row_cumulative;
            columns[8] = lookup_claimed_sum;
            for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
                let slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
                let compressed = local_sha_word_compressed_value(
                    operation,
                    row,
                    wires,
                    port,
                    &challenges.word_copy,
                );
                columns[9 + port] = compressed;
                word_product *= local_sha_word_product_term(
                    permutation.identities[slot],
                    compressed,
                    &challenges.word_copy,
                ) * inverses[base + 9 + port];
                columns[12 + port] = word_product;
            }
            observe(row, &columns);
        }
    }
    let lookup_claimed_sum = secure_to_qm31(lookup_claimed_sum);
    let word_product = secure_to_qm31(word_product);
    if lookup_claimed_sum != [0; 4] {
        return Err(format!(
            "local SHA v14 lookup claimed sum {lookup_claimed_sum:?}"
        ));
    }
    if word_product != [1, 0, 0, 0] {
        return Err(format!("local SHA v14 word product {word_product:?}"));
    }
    Ok((lookup_claimed_sum, word_product))
}

/**
 * Cheap production-path preflight: execute the exact batched interaction walk
 * without allocating or committing any trace matrices.
 */
pub fn check_local_sha_v14_interaction(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
    challenges: &LocalShaV14InteractionChallenges,
) -> Result<(), String> {
    walk_local_sha_v14_interaction(
        program,
        wires,
        permutation,
        multiplicities,
        challenges,
        |_, _| {},
    )?;
    Ok(())
}

pub fn local_sha_v14_interaction_samples(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
    challenges: &LocalShaV14InteractionChallenges,
    sample_rows: &[usize],
) -> Result<LocalShaV14InteractionSamples, String> {
    let relation_rows = local_sha_word_copy_relation_rows(program, permutation)
        .map_err(|_| "local SHA v14 interaction geometry")?;
    if wires.len() != program.rows.len()
        || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS
        || sample_rows.iter().any(|row| *row >= relation_rows)
    {
        return Err("local SHA v14 interaction geometry".into());
    }
    let positions: HashMap<usize, usize> = sample_rows
        .iter()
        .copied()
        .enumerate()
        .map(|(position, row)| (row, position))
        .collect();
    if positions.len() != sample_rows.len() {
        return Err("duplicate local SHA v14 interaction sample".into());
    }
    let table = local_sha_lookup_table();
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let mut lookup_claimed_sum = zero;
    let mut word_product = one;
    let mut sampled = vec![None; sample_rows.len()];
    for row in 0..relation_rows {
        let operation = program.rows.get(row);
        let mut columns = [zero; LOCAL_SHA_WORD_INTERACTION_COLUMNS];
        let mut row_cumulative = zero;
        if let Some(operation) = operation {
            let entries = local_sha_lookup_entries_at_row(operation, row, wires);
            for limb in 0..LOCAL_SHA_LIMBS {
                let denominator = local_sha_v14_lookup_denominator(entries[limb], challenges);
                if denominator == zero {
                    return Err("local SHA v14 zero lookup denominator".into());
                }
                row_cumulative += denominator.inverse();
                columns[limb] = row_cumulative;
            }
        }
        if let Some(entry) = table.get(row).copied() {
            let denominator = local_sha_v14_lookup_denominator(entry, challenges);
            if denominator == zero {
                return Err("local SHA v14 zero table denominator".into());
            }
            row_cumulative -=
                denominator.inverse() * BaseField::from_u32_unchecked(multiplicities[row]);
        }
        lookup_claimed_sum += row_cumulative;
        columns[8] = lookup_claimed_sum;

        for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
            let slot = row * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW + port;
            let compressed =
                local_sha_word_compressed_value(operation, row, wires, port, &challenges.word_copy);
            columns[9 + port] = compressed;
            let numerator = local_sha_word_product_term(
                permutation.identities[slot],
                compressed,
                &challenges.word_copy,
            );
            let denominator = local_sha_word_product_term(
                permutation.sigmas[slot],
                compressed,
                &challenges.word_copy,
            );
            if denominator == zero {
                return Err("local SHA v14 zero word denominator".into());
            }
            word_product *= numerator * denominator.inverse();
            columns[12 + port] = word_product;
        }
        if let Some(position) = positions.get(&row) {
            sampled[*position] = Some(columns.map(secure_to_qm31).to_vec());
        }
    }
    if lookup_claimed_sum != zero {
        return Err(format!(
            "local SHA v14 lookup claimed sum {:?}",
            secure_to_qm31(lookup_claimed_sum)
        ));
    }
    if word_product != one {
        return Err(format!(
            "local SHA v14 word product {:?}",
            secure_to_qm31(word_product)
        ));
    }
    let samples = sample_rows
        .iter()
        .copied()
        .enumerate()
        .map(|(position, row)| {
            Ok(LocalShaInteractionSample {
                row,
                columns: sampled[position]
                    .take()
                    .ok_or("missing local SHA v14 interaction sample")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(LocalShaV14InteractionSamples {
        relation_rows,
        lookup_claimed_sum: secure_to_qm31(lookup_claimed_sum),
        final_word_product: secure_to_qm31(word_product),
        samples,
    })
}

fn local_sha_batch_inverse(values: &[SecureField]) -> Result<Vec<SecureField>, String> {
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = one;
    for value in values {
        if *value == zero {
            return Err("local SHA zero interaction denominator".into());
        }
        prefixes.push(product);
        product *= *value;
    }
    let mut inverse = product.inverse();
    let mut result = vec![zero; values.len()];
    for index in (0..values.len()).rev() {
        result[index] = inverse * prefixes[index];
        inverse *= values[index];
    }
    Ok(result)
}

fn local_sha_interaction_fractions_at_row(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaCopyPermutation,
    multiplicities: &[u32],
    table: &[LocalShaLookupEntry],
    challenges: &LocalShaInteractionChallenges,
    row: usize,
    numerators: &mut Vec<SecureField>,
    denominators: &mut Vec<SecureField>,
) {
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let operation = program.rows.get(row);
    let (a, b, out, _) = local_sha_trace_row(operation, row, wires);
    let accesses = match operation {
        Some(operation) => local_sha_lookup_entries_at_row(operation, row, wires),
        None => {
            [LocalShaLookupEntry {
                tag: 0,
                a: 0,
                b: 0,
                carry_in: 0,
                out: 0,
                carry_out: 0,
            }; 8]
        }
    };
    for entry in accesses {
        numerators.push(if operation.is_some() { one } else { zero });
        denominators.push(local_sha_lookup_denominator(entry, challenges));
    }
    match table.get(row).copied() {
        Some(entry) => {
            numerators.push(-qm31_to_secure([multiplicities[row], 0, 0, 0]));
            denominators.push(local_sha_lookup_denominator(entry, challenges));
        }
        None => {
            numerators.push(zero);
            denominators.push(one);
        }
    }
    let values = [a, b, out].concat();
    let slot_start = row * LOCAL_SHA_COPY_SLOTS_PER_ROW;
    for lane in &challenges.copy {
        for slot in 0..LOCAL_SHA_COPY_SLOTS_PER_ROW {
            let index = slot_start + slot;
            let identity = permutation.identities[index];
            let sigma = permutation.sigmas[index];
            let value = values[slot];
            numerators.extend([one, -one]);
            denominators.push(local_sha_copy_denominator(identity, value, lane));
            denominators.push(local_sha_copy_denominator(sigma, value, lane));
        }
    }
    debug_assert_eq!(numerators.len() % LOCAL_SHA_INTERACTION_FRACTIONS, 0);
    debug_assert_eq!(numerators.len(), denominators.len());
}

fn walk_local_sha_interaction<F>(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaCopyPermutation,
    multiplicities: &[u32],
    challenges: &LocalShaInteractionChallenges,
    mut observe: F,
) -> Result<Qm31Value, String>
where
    F: FnMut(usize, &[SecureField; LOCAL_SHA_INTERACTION_COLUMNS]),
{
    let relation_rows = local_sha_relation_rows(program);
    if wires.len() != program.rows.len()
        || permutation.identities.len() != relation_rows * LOCAL_SHA_COPY_SLOTS_PER_ROW
        || permutation.sigmas.len() != permutation.identities.len()
        || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS
    {
        return Err("local SHA interaction geometry".into());
    }
    let table = local_sha_lookup_table();
    let zero = qm31_to_secure([0; 4]);
    let mut claimed_sum = zero;
    const CHUNK_ROWS: usize = 4_096;
    for chunk_start in (0..relation_rows).step_by(CHUNK_ROWS) {
        let chunk_end = (chunk_start + CHUNK_ROWS).min(relation_rows);
        let fraction_count = (chunk_end - chunk_start) * LOCAL_SHA_INTERACTION_FRACTIONS;
        let mut numerators = Vec::with_capacity(fraction_count);
        let mut denominators = Vec::with_capacity(fraction_count);
        for row in chunk_start..chunk_end {
            local_sha_interaction_fractions_at_row(
                program,
                wires,
                permutation,
                multiplicities,
                &table,
                challenges,
                row,
                &mut numerators,
                &mut denominators,
            );
        }
        let inverses = local_sha_batch_inverse(&denominators)?;
        for row in chunk_start..chunk_end {
            let base = (row - chunk_start) * LOCAL_SHA_INTERACTION_FRACTIONS;
            let mut row_cumulative = zero;
            let mut columns = [zero; LOCAL_SHA_INTERACTION_COLUMNS];
            let mut fraction = 0usize;
            for column in 0..LOCAL_SHA_INTERACTION_COLUMNS {
                row_cumulative += numerators[base + fraction] * inverses[base + fraction];
                fraction += 1;
                if column + 1 == LOCAL_SHA_INTERACTION_COLUMNS {
                    claimed_sum += row_cumulative;
                    columns[column] = claimed_sum;
                } else {
                    columns[column] = row_cumulative;
                }
            }
            debug_assert_eq!(fraction, LOCAL_SHA_INTERACTION_FRACTIONS);
            observe(row, &columns);
        }
    }
    let claimed_sum = secure_to_qm31(claimed_sum);
    if claimed_sum != [0; 4] {
        return Err(format!("local SHA interaction claimed sum {claimed_sum:?}"));
    }
    Ok(claimed_sum)
}

/**
 * Stream the exact 105-column relation-domain interaction trace and retain only
 * requested rows. Denominators are batch-inverted in bounded chunks, so the
 * worst 2^18-row graph does not require a second object-rich matrix.
 */
pub fn local_sha_interaction_samples(
    program: &LocalShaProgram,
    wires: &[u32],
    permutation: &LocalShaCopyPermutation,
    multiplicities: &[u32],
    challenges: &LocalShaInteractionChallenges,
    sample_rows: &[usize],
) -> Result<LocalShaInteractionSamples, String> {
    let relation_rows = local_sha_relation_rows(program);
    if sample_rows.iter().any(|row| *row >= relation_rows) {
        return Err("local SHA interaction sample row".into());
    }
    let mut positions = HashMap::new();
    for (position, row) in sample_rows.iter().copied().enumerate() {
        if positions.insert(row, position).is_some() {
            return Err("duplicate local SHA interaction sample".into());
        }
    }
    let mut sampled: Vec<Option<Vec<Qm31Value>>> = vec![None; sample_rows.len()];
    let claimed_sum = walk_local_sha_interaction(
        program,
        wires,
        permutation,
        multiplicities,
        challenges,
        |row, columns| {
            if let Some(position) = positions.get(&row) {
                sampled[*position] = Some(columns.iter().copied().map(secure_to_qm31).collect());
            }
        },
    )?;
    let samples = sample_rows
        .iter()
        .copied()
        .enumerate()
        .map(|(position, row)| {
            Ok(LocalShaInteractionSample {
                row,
                columns: sampled[position]
                    .take()
                    .ok_or("missing local SHA interaction sample")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(LocalShaInteractionSamples {
        relation_rows,
        claimed_sum,
        samples,
    })
}

fn local_word_boundary_factor(
    id: u16,
    value: u32,
    challenges: &LocalWordBoundaryChallenges,
) -> SecureField {
    let limbs = local_sha_word_limbs(value);
    let mut result = qm31_to_secure(challenges.gamma)
        + qm31_to_secure(challenges.identity) * BaseField::from_u32_unchecked(id as u32);
    for (challenge, limb) in challenges.limbs.iter().zip(limbs) {
        result += qm31_to_secure(*challenge) * BaseField::from_u32_unchecked(limb);
    }
    result
}

fn local_word_public_boundary_claim_for_words(
    public_words: &[LocalWordPublicWord],
    challenges: &LocalWordBoundaryChallenges,
) -> Result<(Qm31Value, Vec<Qm31Value>), String> {
    if public_words
        .iter()
        .enumerate()
        .any(|(index, word)| word.id as usize != index + 1)
    {
        return Err("local-word public boundary ids".into());
    }
    let inverses = public_words
        .iter()
        .map(|word| {
            secure_to_qm31(local_word_boundary_factor(word.id, word.expected, challenges).inverse())
        })
        .collect::<Vec<_>>();
    let sum = inverses
        .iter()
        .fold(qm31_to_secure([0; 4]), |sum, inverse| {
            sum + qm31_to_secure(*inverse)
        });
    Ok((secure_to_qm31(sum), inverses))
}

fn local_word_public_boundary_claim(
    bundle: &LocalWordProverBundle,
    challenges: &LocalWordBoundaryChallenges,
) -> Result<(Qm31Value, Vec<Qm31Value>), String> {
    local_word_public_boundary_claim_for_words(&bundle.public_words, challenges)
}

fn walk_local_word_boundary<F>(
    bundle: &LocalWordProverBundle,
    wires: &[u32],
    challenges: &LocalWordBoundaryChallenges,
    mut observe: F,
) -> Result<(Qm31Value, Vec<Qm31Value>), String>
where
    F: FnMut(usize, [SecureField; 2]),
{
    if wires.len() != bundle.program.rows.len() {
        return Err("local-word boundary geometry".into());
    }
    let by_row: HashMap<usize, &LocalWordPublicWord> = bundle
        .public_words
        .iter()
        .map(|word| (word.row, word))
        .collect();
    if by_row.len() != bundle.public_words.len() {
        return Err("local-word boundary public rows".into());
    }
    let zero = qm31_to_secure([0; 4]);
    let (claimed_sum, public_inverses) = local_word_public_boundary_claim(bundle, challenges)?;
    let claimed_sum_secure = qm31_to_secure(claimed_sum);
    let mut global = zero;
    for row in 0..bundle.relation_rows {
        let access = match by_row.get(&row) {
            Some(word) => local_word_boundary_factor(word.id, wires[row], challenges).inverse(),
            None => zero,
        };
        global += access;
        if row == 0 {
            global -= claimed_sum_secure;
        }
        observe(row, [access, global]);
    }
    if secure_to_qm31(global) != [0; 4] {
        return Err(format!(
            "local-word boundary global {:?}",
            secure_to_qm31(global)
        ));
    }
    Ok((claimed_sum, public_inverses))
}

/** Exact complete-pool public-word product column on the relation domain. */
pub fn local_word_boundary_samples(
    bundle: &LocalWordProverBundle,
    wires: &[u32],
    challenges: &LocalWordBoundaryChallenges,
    sample_rows: &[usize],
) -> Result<LocalWordBoundarySamples, String> {
    if sample_rows.iter().any(|row| *row >= bundle.relation_rows) {
        return Err("local-word boundary sample row".into());
    }
    let positions: HashMap<usize, usize> = sample_rows
        .iter()
        .copied()
        .enumerate()
        .map(|(position, row)| (row, position))
        .collect();
    if positions.len() != sample_rows.len() {
        return Err("duplicate local-word boundary sample".into());
    }
    let mut sampled = vec![None; sample_rows.len()];
    let (claimed_sum, public_inverses) =
        walk_local_word_boundary(bundle, wires, challenges, |row, values| {
            if let Some(position) = positions.get(&row) {
                sampled[*position] = Some(values.map(secure_to_qm31));
            }
        })?;
    let samples = sample_rows
        .iter()
        .copied()
        .enumerate()
        .map(|(position, row)| {
            Ok((
                row,
                sampled[position].ok_or("missing local-word boundary sample")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(LocalWordBoundarySamples {
        relation_rows: bundle.relation_rows,
        claimed_sum,
        public_inverses,
        samples,
    })
}

fn local_word_air_fraction_residual(
    current: SecureField,
    previous: SecureField,
    denominator: SecureField,
    numerator: SecureField,
) -> SecureField {
    (current - previous) * denominator - numerator
}

/** Complete quadratic local-word AIR at one point and its cyclic predecessor. */
pub fn local_word_air_residuals(
    original: &[u32],
    preprocessed: &[u32],
    interaction: &[Qm31Value],
    interaction_previous: &[Qm31Value],
    interaction_challenges: &LocalShaInteractionChallenges,
    boundary_challenges: &LocalWordBoundaryChallenges,
    boundary_claimed_sum: Qm31Value,
) -> Result<Vec<Qm31Value>, String> {
    if original.len() != LOCAL_WORD_ORIGINAL_COLUMNS
        || preprocessed.len() != LOCAL_WORD_PREPROCESSED_COLUMNS
        || interaction.len() != LOCAL_WORD_INTERACTION_COLUMNS
        || interaction_previous.len() != LOCAL_WORD_INTERACTION_COLUMNS
        || original
            .iter()
            .chain(preprocessed)
            .any(|value| *value as u64 >= M31)
        || interaction
            .iter()
            .chain(interaction_previous)
            .flatten()
            .any(|value| *value as u64 >= M31)
    {
        return Err("local-word AIR frame geometry".into());
    }
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let current = interaction
        .iter()
        .copied()
        .map(qm31_to_secure)
        .collect::<Vec<_>>();
    let previous_row = interaction_previous
        .iter()
        .copied()
        .map(qm31_to_secure)
        .collect::<Vec<_>>();
    let mut residuals = Vec::with_capacity(LOCAL_WORD_AIR_CONSTRAINTS);

    let active = qm31_to_secure([preprocessed[57], 0, 0, 0]);
    let mut lookup_denominators = Vec::with_capacity(9);
    for limb in 0..LOCAL_SHA_LIMBS {
        lookup_denominators.push(local_sha_qm_linear(
            interaction_challenges.lookup_gamma,
            &interaction_challenges.lookup_tuple,
            &[
                preprocessed[0],
                add_m31_fast(original[limb], preprocessed[1 + limb]),
                original[8 + limb],
                original[24 + limb],
                original[16 + limb],
                original[25 + limb],
            ],
        ));
    }
    lookup_denominators.push(local_sha_qm_linear(
        interaction_challenges.lookup_gamma,
        &interaction_challenges.lookup_tuple,
        &preprocessed[58..64],
    ));
    let mut column = 0usize;
    for limb in 0..LOCAL_SHA_LIMBS {
        let prior = if column == 0 {
            zero
        } else {
            current[column - 1]
        };
        residuals.push(local_word_air_fraction_residual(
            current[column],
            prior,
            lookup_denominators[limb],
            active,
        ));
        column += 1;
    }
    residuals.push(local_word_air_fraction_residual(
        current[column],
        current[column - 1],
        lookup_denominators[8],
        -qm31_to_secure([original[33], 0, 0, 0]),
    ));
    column += 1;

    for lane in &interaction_challenges.copy {
        for slot in 0..LOCAL_SHA_COPY_SLOTS_PER_ROW {
            let value = original[slot];
            let identity = local_sha_copy_denominator(preprocessed[9 + 2 * slot], value, lane);
            let sigma = local_sha_copy_denominator(preprocessed[10 + 2 * slot], value, lane);
            residuals.push(local_word_air_fraction_residual(
                current[column],
                current[column - 1],
                identity,
                one,
            ));
            column += 1;
            let prior = if column == LOCAL_SHA_INTERACTION_COLUMNS - 1 {
                previous_row[column] + current[column - 1]
            } else {
                current[column - 1]
            };
            residuals.push(local_word_air_fraction_residual(
                current[column],
                prior,
                sigma,
                -one,
            ));
            column += 1;
        }
    }
    if column != LOCAL_SHA_INTERACTION_COLUMNS {
        return Err("local-word AIR copy geometry".into());
    }

    let mut witness_values = Vec::with_capacity(9);
    witness_values.push(preprocessed[65]);
    witness_values.extend_from_slice(&original[16..24]);
    let mut boundary_linear_challenges = Vec::with_capacity(9);
    boundary_linear_challenges.push(boundary_challenges.identity);
    boundary_linear_challenges.extend_from_slice(&boundary_challenges.limbs);
    let witness_factor = local_sha_qm_linear(
        boundary_challenges.gamma,
        &boundary_linear_challenges,
        &witness_values,
    );
    let selector = qm31_to_secure([preprocessed[64], 0, 0, 0]);
    residuals.push(local_word_air_fraction_residual(
        current[105],
        zero,
        witness_factor,
        selector,
    ));

    residuals.push(
        current[106] - previous_row[106] - current[105]
            + qm31_to_secure(boundary_claimed_sum)
                * BaseField::from_u32_unchecked(preprocessed[66]),
    );
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS {
        return Err("local-word AIR constraint count".into());
    }
    Ok(residuals.into_iter().map(secure_to_qm31).collect())
}

pub fn mix_local_word_air_residuals(
    residuals: &[Qm31Value],
    alpha: Qm31Value,
) -> Result<Qm31Value, String> {
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS {
        return Err("local-word AIR mix count".into());
    }
    let alpha = qm31_to_secure(alpha);
    let mixed = residuals
        .iter()
        .rev()
        .fold(qm31_to_secure([0; 4]), |sum, residual| {
            qm31_to_secure(*residual) + alpha * sum
        });
    Ok(secure_to_qm31(mixed))
}

pub fn local_word_air_composition_partials(
    residuals: &[Qm31Value],
    alpha: Qm31Value,
) -> Result<[Qm31Value; 3], String> {
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS
        || LOCAL_WORD_AIR_PARTIAL_WIDTHS.iter().sum::<usize>() != residuals.len()
    {
        return Err("local-word AIR partial geometry".into());
    }
    let alpha = qm31_to_secure(alpha);
    let mut start = 0usize;
    Ok(LOCAL_WORD_AIR_PARTIAL_WIDTHS.map(|width| {
        let partial = residuals[start..start + width]
            .iter()
            .rev()
            .fold(qm31_to_secure([0; 4]), |sum, residual| {
                qm31_to_secure(*residual) + alpha * sum
            });
        start += width;
        secure_to_qm31(partial)
    }))
}

pub fn combine_local_word_air_composition_partials(
    partials: [Qm31Value; 3],
    alpha: Qm31Value,
) -> Qm31Value {
    let alpha = qm31_to_secure(alpha);
    let power = |exponent: usize| {
        (0..exponent).fold(SecureField::from_u32_unchecked(1, 0, 0, 0), |power, _| {
            power * alpha
        })
    };
    secure_to_qm31(
        qm31_to_secure(partials[0])
            + power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0]) * qm31_to_secure(partials[1])
            + power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0] + LOCAL_WORD_AIR_PARTIAL_WIDTHS[1])
                * qm31_to_secure(partials[2]),
    )
}

fn local_word_v14_compressed_air(
    original: &[u32],
    preprocessed: &[u32],
    port: usize,
    challenges: &LocalShaWordCopyChallenges,
) -> SecureField {
    let original_start = match port {
        0 => 0,
        1 => 8,
        2 => 16,
        _ => return qm31_to_secure([0; 4]),
    };
    if port == 2 {
        return (0..LOCAL_SHA_LIMBS).fold(qm31_to_secure([0; 4]), |sum, limb| {
            sum + qm31_to_secure(challenges.limbs[limb])
                * BaseField::from_u32_unchecked(mul_m31_fast(
                    preprocessed[31],
                    original[original_start + limb],
                ))
        });
    }
    let selector_start = if port == 0 { 9 } else { 17 };
    let mut result = qm31_to_secure([0; 4]);
    for shift in 0..LOCAL_SHA_LIMBS {
        for limb in 0..LOCAL_SHA_LIMBS {
            result += qm31_to_secure(challenges.limbs[(limb + shift) % LOCAL_SHA_LIMBS])
                * BaseField::from_u32_unchecked(mul_m31_fast(
                    preprocessed[selector_start + shift],
                    original[original_start + limb],
                ));
        }
    }
    result
}

pub fn local_word_v14_air_residuals(
    original: &[u32],
    preprocessed: &[u32],
    interaction: &[Qm31Value],
    interaction_previous: &[Qm31Value],
    interaction_challenges: &LocalShaV14InteractionChallenges,
    boundary_challenges: &LocalWordBoundaryChallenges,
    boundary_claimed_sum: Qm31Value,
) -> Result<Vec<Qm31Value>, String> {
    if original.len() != LOCAL_WORD_ORIGINAL_COLUMNS
        || preprocessed.len() != LOCAL_WORD_PREPROCESSED_COLUMNS
        || interaction.len() != LOCAL_WORD_INTERACTION_COLUMNS
        || interaction_previous.len() != LOCAL_WORD_INTERACTION_COLUMNS
        || original
            .iter()
            .chain(preprocessed)
            .any(|value| *value as u64 >= M31)
        || interaction
            .iter()
            .chain(interaction_previous)
            .flatten()
            .any(|value| *value as u64 >= M31)
    {
        return Err("local-word v14 AIR frame geometry".into());
    }
    let zero = qm31_to_secure([0; 4]);
    let one = qm31_to_secure([1, 0, 0, 0]);
    let current = interaction
        .iter()
        .copied()
        .map(qm31_to_secure)
        .collect::<Vec<_>>();
    let previous_row = interaction_previous
        .iter()
        .copied()
        .map(qm31_to_secure)
        .collect::<Vec<_>>();
    let mut residuals = Vec::with_capacity(LOCAL_WORD_AIR_CONSTRAINTS);

    let active = qm31_to_secure([preprocessed[31], 0, 0, 0]);
    let mut lookup_denominators = Vec::with_capacity(9);
    for limb in 0..LOCAL_SHA_LIMBS {
        lookup_denominators.push(local_sha_qm_linear(
            interaction_challenges.lookup_gamma,
            &interaction_challenges.lookup_tuple,
            &[
                preprocessed[0],
                add_m31_fast(original[limb], preprocessed[1 + limb]),
                original[8 + limb],
                original[24 + limb],
                original[16 + limb],
                original[25 + limb],
            ],
        ));
    }
    lookup_denominators.push(local_sha_qm_linear(
        interaction_challenges.lookup_gamma,
        &interaction_challenges.lookup_tuple,
        &preprocessed[34..40],
    ));
    for limb in 0..LOCAL_SHA_LIMBS {
        residuals.push(local_word_air_fraction_residual(
            current[limb],
            if limb == 0 { zero } else { current[limb - 1] },
            lookup_denominators[limb],
            active,
        ));
    }
    residuals.push(local_word_air_fraction_residual(
        current[8],
        previous_row[8] + current[7],
        lookup_denominators[8],
        -qm31_to_secure([original[33], 0, 0, 0]),
    ));

    for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
        residuals.push(
            current[9 + port]
                - local_word_v14_compressed_air(
                    original,
                    preprocessed,
                    port,
                    &interaction_challenges.word_copy,
                ),
        );
    }
    for port in 0..LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW {
        let compressed = current[9 + port];
        let identity = local_sha_word_product_term(
            preprocessed[25 + 2 * port],
            compressed,
            &interaction_challenges.word_copy,
        );
        let sigma = local_sha_word_product_term(
            preprocessed[26 + 2 * port],
            compressed,
            &interaction_challenges.word_copy,
        );
        let prior = if port == 0 {
            previous_row[14]
        } else {
            current[11 + port]
        };
        residuals.push(current[12 + port] * sigma - prior * identity);
    }
    residuals.push(qm31_to_secure([preprocessed[33], 0, 0, 0]) * (current[14] - one));

    for limb in 1..LOCAL_SHA_LIMBS {
        residuals.push(qm31_to_secure([
            mul_m31_fast(
                preprocessed[32],
                sub_m31_fast(original[16 + limb], original[16]),
            ),
            0,
            0,
            0,
        ]));
    }

    let mut witness_values = Vec::with_capacity(9);
    witness_values.push(preprocessed[41]);
    witness_values.extend_from_slice(&original[16..24]);
    let mut boundary_linear_challenges = Vec::with_capacity(9);
    boundary_linear_challenges.push(boundary_challenges.identity);
    boundary_linear_challenges.extend_from_slice(&boundary_challenges.limbs);
    let witness_factor = local_sha_qm_linear(
        boundary_challenges.gamma,
        &boundary_linear_challenges,
        &witness_values,
    );
    residuals.push(local_word_air_fraction_residual(
        current[15],
        zero,
        witness_factor,
        qm31_to_secure([preprocessed[40], 0, 0, 0]),
    ));
    residuals.push(
        current[16] - previous_row[16] - current[15]
            + qm31_to_secure(boundary_claimed_sum)
                * BaseField::from_u32_unchecked(preprocessed[42]),
    );
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS {
        return Err("local-word v14 AIR constraint count".into());
    }
    Ok(residuals.into_iter().map(secure_to_qm31).collect())
}

pub fn mix_local_word_v14_air_residuals(
    residuals: &[Qm31Value],
    alpha: Qm31Value,
) -> Result<Qm31Value, String> {
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS {
        return Err("local-word v14 AIR mix count".into());
    }
    let alpha = qm31_to_secure(alpha);
    Ok(secure_to_qm31(
        residuals
            .iter()
            .rev()
            .fold(qm31_to_secure([0; 4]), |sum, residual| {
                qm31_to_secure(*residual) + alpha * sum
            }),
    ))
}

pub fn local_word_v14_air_composition_partials(
    residuals: &[Qm31Value],
    alpha: Qm31Value,
) -> Result<[Qm31Value; 3], String> {
    if residuals.len() != LOCAL_WORD_AIR_CONSTRAINTS
        || LOCAL_WORD_AIR_PARTIAL_WIDTHS.iter().sum::<usize>() != residuals.len()
    {
        return Err("local-word v14 AIR partial geometry".into());
    }
    let alpha = qm31_to_secure(alpha);
    let mut start = 0usize;
    Ok(LOCAL_WORD_AIR_PARTIAL_WIDTHS.map(|width| {
        let partial = residuals[start..start + width]
            .iter()
            .rev()
            .fold(qm31_to_secure([0; 4]), |sum, residual| {
                qm31_to_secure(*residual) + alpha * sum
            });
        start += width;
        secure_to_qm31(partial)
    }))
}

pub fn combine_local_word_v14_air_composition_partials(
    partials: [Qm31Value; 3],
    alpha: Qm31Value,
) -> Qm31Value {
    let alpha = qm31_to_secure(alpha);
    let power = |exponent: usize| {
        (0..exponent).fold(SecureField::from_u32_unchecked(1, 0, 0, 0), |power, _| {
            power * alpha
        })
    };
    secure_to_qm31(
        qm31_to_secure(partials[0])
            + power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0]) * qm31_to_secure(partials[1])
            + power(LOCAL_WORD_AIR_PARTIAL_WIDTHS[0] + LOCAL_WORD_AIR_PARTIAL_WIDTHS[1])
                * qm31_to_secure(partials[2]),
    )
}

/** Materialize the complete 55-QM31 relation interaction for sealing. */
pub fn build_local_word_interaction_matrix(
    bundle: &LocalWordProverBundle,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
    interaction_challenges: &LocalShaV14InteractionChallenges,
    boundary_challenges: &LocalWordBoundaryChallenges,
) -> Result<LocalWordInteractionMatrix, String> {
    let rows = bundle.relation_rows;
    let mut columns = vec![vec![0u32; rows]; (LOCAL_SHA_WORD_INTERACTION_COLUMNS + 2) * 4];
    walk_local_sha_v14_interaction(
        &bundle.program,
        wires,
        permutation,
        multiplicities,
        interaction_challenges,
        |row, values| {
            for (column, value) in values.iter().copied().enumerate() {
                for (coordinate, coordinate_value) in secure_to_qm31(value).into_iter().enumerate()
                {
                    columns[column * 4 + coordinate][row] = coordinate_value;
                }
            }
        },
    )?;
    let (boundary_claimed_sum, boundary_inverses) =
        walk_local_word_boundary(bundle, wires, boundary_challenges, |row, values| {
            for (boundary_column, value) in values.into_iter().enumerate() {
                let coordinates = secure_to_qm31(value);
                for coordinate in 0..4 {
                    columns
                        [(LOCAL_SHA_WORD_INTERACTION_COLUMNS + boundary_column) * 4 + coordinate]
                        [row] = coordinates[coordinate];
                }
            }
        })?;
    Ok(LocalWordInteractionMatrix {
        columns,
        boundary_claimed_sum,
        boundary_inverses,
    })
}

fn local_word_interaction_commit_order(
    mut columns: Vec<Vec<u32>>,
) -> Result<Vec<Vec<u32>>, String> {
    if columns.len() != LOCAL_WORD_INTERACTION_COLUMNS * 4 {
        return Err("local-word interaction commit width".into());
    }
    let qm31_order = LOCAL_WORD_INTERACTION_COMMIT_ORDER;
    if qm31_order.len() != LOCAL_WORD_INTERACTION_COLUMNS {
        return Err("local-word interaction commit order".into());
    }
    let mut ordered = Vec::with_capacity(columns.len());
    for qm31_column in qm31_order {
        for coordinate in 0..4 {
            ordered.push(std::mem::take(&mut columns[qm31_column * 4 + coordinate]));
        }
    }
    Ok(ordered)
}

/** Reference column-major 34/67 relation matrices reconstructed from SKLB. */
pub fn build_local_word_relation_matrices(
    bundle: &LocalWordProverBundle,
    wires: &[u32],
    permutation: &LocalShaWordCopyPermutation,
    multiplicities: &[u32],
) -> Result<LocalWordRelationMatrices, String> {
    if wires.len() != bundle.program.rows.len()
        || permutation.identities.len() != bundle.relation_rows * LOCAL_SHA_WORD_COPY_SLOTS_PER_ROW
        || permutation.sigmas.len() != permutation.identities.len()
        || multiplicities.len() != LOCAL_SHA_LOOKUP_TABLE_ROWS
    {
        return Err("local-word relation matrix geometry".into());
    }
    let rows = bundle.relation_rows;
    let mut original = vec![vec![0u32; rows]; 34];
    let mut preprocessed = vec![vec![0u32; rows]; LOCAL_WORD_PREPROCESSED_COLUMNS];
    let public_by_row: HashMap<usize, u16> = bundle
        .public_words
        .iter()
        .map(|word| (word.row, word.id))
        .collect();
    for row in 0..rows {
        let frame = local_sha_word_relation_frame_at(
            &bundle.program,
            wires,
            permutation,
            multiplicities,
            row,
        )?;
        for (column, value) in frame.original.into_iter().enumerate() {
            original[column][row] = value;
        }
        for (column, value) in frame.preprocessed.into_iter().enumerate() {
            preprocessed[column][row] = value;
        }
        if let Some(id) = public_by_row.get(&row) {
            preprocessed[40][row] = 1;
            preprocessed[41][row] = *id as u32;
        }
        preprocessed[42][row] = u32::from(row == 0);
    }
    Ok(LocalWordRelationMatrices {
        original,
        preprocessed,
    })
}

/**
 * Commit the complete 34/67/428-M31 relation as four canonical log-24 disk
 * oracles. Private original and interaction columns cross `w + Z_H r`; fixed
 * preprocessed columns do not. The caller owns the new workspace directory.
 */
fn commit_local_word_relation_with_parameters(
    bundle: &LocalWordProverBundle,
    workspace: &std::path::Path,
    parameters: LocalWordProofParameters,
) -> Result<LocalWordCommittedRelation, String> {
    parameters.validate()?;
    if bundle.relation_rows != 1usize << parameters.relation_log {
        return Err("local-word commitment relation rows".into());
    }
    if workspace.exists() {
        return Err("local-word commitment workspace exists".into());
    }
    std::fs::create_dir(workspace)
        .map_err(|error| format!("create local-word commitment workspace: {error}"))?;
    let wires = execute_local_sha_program(&bundle.program, &bundle.inputs)?;
    let permutation = compile_local_sha_word_copy_permutation_for_rows(
        &bundle.program,
        bundle.relation_rows,
    )?;
    let multiplicities = local_sha_table_multiplicities(&bundle.program, &wires)?;
    let relation =
        build_local_word_relation_matrices(bundle, &wires, &permutation, &multiplicities)?;
    let preprocessed = build_disk_matrix_commitment(
        "local-word:preprocessed",
        &relation.preprocessed,
        DiskColumnExtension::PublicRelation {
            eval_log: parameters.eval_log,
        },
        &workspace.join("preprocessed"),
    )?;
    let original = build_disk_matrix_commitment(
        "local-word:original",
        &relation.original,
        DiskColumnExtension::SealedRelation {
            log_blowup: parameters.private_seal_blowup()?,
        },
        &workspace.join("original"),
    )?;
    drop(relation);

    let descriptor_digest: [u8; 32] = Sha256::digest(&bundle.construction_descriptor).into();
    let (mut transcript, interaction_challenges, boundary_challenges) =
        local_word_v15_interaction_transcript(
            &bundle.transcript_initial,
            descriptor_digest,
            preprocessed.root,
            original.root,
        );
    let (boundary_claimed_sum, boundary_inverses) =
        local_word_public_boundary_claim(bundle, &boundary_challenges)?;
    local_word_v15_public_boundary_transcript(&mut transcript, &boundary_inverses)?;
    let interaction_matrix = build_local_word_interaction_matrix(
        bundle,
        &wires,
        &permutation,
        &multiplicities,
        &interaction_challenges,
        &boundary_challenges,
    )?;
    if interaction_matrix.boundary_claimed_sum != boundary_claimed_sum
        || interaction_matrix.boundary_inverses != boundary_inverses
    {
        return Err("local-word public boundary construction".into());
    }
    let interaction_columns = local_word_interaction_commit_order(interaction_matrix.columns)?;
    let interaction = build_disk_matrix_commitment(
        "local-word:interaction",
        &interaction_columns[..LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH],
        DiskColumnExtension::SealedRelation {
            log_blowup: parameters.private_seal_blowup()?,
        },
        &workspace.join("interaction"),
    )?;
    let interaction_global = build_disk_matrix_commitment(
        "local-word:interaction-global",
        &interaction_columns[LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH..],
        DiskColumnExtension::SealedRelation {
            log_blowup: parameters.private_seal_blowup()?,
        },
        &workspace.join("interaction-global"),
    )?;
    let interaction_transcript_digest = transcript.digest();
    let (constraint_alpha, composition_transcript_digest) = local_word_v15_composition_transcript(
        &mut transcript,
        interaction.root,
        interaction_global.root,
    );
    Ok(LocalWordCommittedRelation {
        preprocessed,
        original,
        interaction,
        interaction_global,
        interaction_challenges,
        boundary_challenges,
        boundary_claimed_sum,
        boundary_inverses,
        interaction_transcript_digest,
        constraint_alpha,
        composition_transcript_digest,
    })
}

pub fn commit_local_word_relation(
    bundle: &LocalWordProverBundle,
    workspace: &std::path::Path,
) -> Result<LocalWordCommittedRelation, String> {
    commit_local_word_relation_with_parameters(
        bundle,
        workspace,
        LocalWordProofParameters::PRODUCTION,
    )
}

fn local_word_interaction_from_committed_rows(rows: [&[u32]; 4]) -> Result<Vec<Qm31Value>, String> {
    if rows
        .iter()
        .zip(LOCAL_WORD_INTERACTION_GROUP_M31_WIDTHS)
        .any(|(row, width)| row.len() != width)
    {
        return Err("local-word committed interaction width".into());
    }
    let mut interaction = vec![[0u32; 4]; LOCAL_WORD_INTERACTION_COLUMNS];
    let mut position = 0usize;
    for row in rows {
        for chunk in row.chunks_exact(4) {
            interaction[LOCAL_WORD_INTERACTION_COMMIT_ORDER[position]].copy_from_slice(chunk);
            position += 1;
        }
    }
    if position != LOCAL_WORD_INTERACTION_COLUMNS {
        return Err("local-word committed interaction order".into());
    }
    Ok(interaction)
}

fn local_word_interaction_from_packed_rows(
    current: &[u32],
    global: &[u32],
) -> Result<Vec<Qm31Value>, String> {
    if current.len() != LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH
        || global.len() != LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH
    {
        return Err("local-word packed interaction width".into());
    }
    local_word_interaction_from_committed_rows([
        &current[..20],
        &current[20..40],
        &current[40..56],
        global,
    ])
}

fn local_word_air_residuals_at_committed_row_with_trace_log(
    relation: &LocalWordCommittedRelation,
    index: usize,
    relation_trace_log: u32,
) -> Result<Vec<Qm31Value>, String> {
    let row_count = relation.preprocessed.row_count;
    let eval_log = row_count.ilog2();
    if row_count < 2
        || !row_count.is_power_of_two()
        || relation_trace_log >= eval_log
        || index >= row_count
        || relation.preprocessed.column_count != LOCAL_WORD_PREPROCESSED_COLUMNS
        || relation.original.column_count != LOCAL_WORD_ORIGINAL_COLUMNS
        || relation.original.row_count != row_count
        || relation.interaction.row_count != row_count
        || relation.interaction.column_count != LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH
        || relation.interaction_global.row_count != row_count
        || relation.interaction_global.column_count != LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH
    {
        return Err("local-word committed composition geometry".into());
    }
    let original = relation.original.row_values(index)?;
    let preprocessed = relation.preprocessed.row_values(index)?;
    let interaction_current = relation.interaction.row_values(index)?;
    let interaction_global = relation.interaction_global.row_values(index)?;
    let interaction =
        local_word_interaction_from_packed_rows(&interaction_current, &interaction_global)?;
    let previous_index = stwo::core::utils::offset_bit_reversed_circle_domain_index(
        index,
        relation_trace_log,
        eval_log,
        -1,
    );
    let previous_global = relation.interaction_global.row_values(previous_index)?;
    let mut interaction_previous = vec![[0u32; 4]; LOCAL_WORD_INTERACTION_COLUMNS];
    for (position, column) in LOCAL_WORD_GLOBAL_INTERACTION_QM31_COLUMNS
        .into_iter()
        .enumerate()
    {
        interaction_previous[column]
            .copy_from_slice(&previous_global[position * 4..position * 4 + 4]);
    }
    local_word_v14_air_residuals(
        &original,
        &preprocessed,
        &interaction,
        &interaction_previous,
        &relation.interaction_challenges,
        &relation.boundary_challenges,
        relation.boundary_claimed_sum,
    )
}

fn local_word_composition_at_committed_row_with_trace_log(
    relation: &LocalWordCommittedRelation,
    index: usize,
    relation_trace_log: u32,
) -> Result<LocalWordCompositionEvaluation, String> {
    let row_count = relation.preprocessed.row_count;
    let eval_log = row_count.ilog2();
    let residuals = local_word_air_residuals_at_committed_row_with_trace_log(
        relation,
        index,
        relation_trace_log,
    )?;
    let composition = mix_local_word_v14_air_residuals(&residuals, relation.constraint_alpha)?;
    let zerofier = trace_zerofier_at_bit_reversed(index, eval_log, relation_trace_log).0;
    if zerofier == 0 {
        return Err("local-word committed composition zerofier".into());
    }
    let inverse = inv_m(zerofier as u64) as u32;
    let quotient = composition.map(|coordinate| mul_m31_fast(coordinate, inverse));
    Ok(LocalWordCompositionEvaluation {
        composition,
        quotient,
        zerofier,
    })
}

/** Re-evaluate the production AIR and raw quotient directly from committed disk rows. */
pub fn local_word_composition_at_committed_row(
    relation: &LocalWordCommittedRelation,
    index: usize,
) -> Result<LocalWordCompositionEvaluation, String> {
    if relation.preprocessed.row_count != 1 << LOCAL_WORD_EVAL_LOG {
        return Err("local-word production composition rows".into());
    }
    local_word_composition_at_committed_row_with_trace_log(relation, index, LOCAL_WORD_RELATION_LOG)
}

fn local_word_interaction_from_committed_column_chunks(
    current: &[Vec<u32>],
    global: &[Vec<u32>],
    row: usize,
) -> Result<Vec<Qm31Value>, String> {
    if current.len() != LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH
        || global.len() != LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH
    {
        return Err("local-word packed interaction chunk width".into());
    }
    let mut interaction = vec![[0u32; 4]; LOCAL_WORD_INTERACTION_COLUMNS];
    for (position, qm31_column) in LOCAL_WORD_INTERACTION_COMMIT_ORDER.into_iter().enumerate() {
        let source = if position < 14 { current } else { global };
        let offset = if position < 14 {
            position * 4
        } else {
            (position - 14) * 4
        };
        interaction[qm31_column] =
            std::array::from_fn(|coordinate| source[offset + coordinate][row]);
    }
    Ok(interaction)
}

fn build_local_word_raw_quotient_with_trace_log(
    relation: &LocalWordCommittedRelation,
    directory: &std::path::Path,
    relation_trace_log: u32,
) -> Result<DiskQm31Evaluation, String> {
    let row_count = relation.preprocessed.row_count;
    let eval_log = row_count.ilog2();
    if row_count < 2
        || !row_count.is_power_of_two()
        || relation_trace_log >= eval_log
        || relation.preprocessed.column_count != LOCAL_WORD_PREPROCESSED_COLUMNS
        || relation.original.column_count != LOCAL_WORD_ORIGINAL_COLUMNS
        || relation.original.row_count != row_count
        || relation.interaction.row_count != row_count
        || relation.interaction.column_count != LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH
        || relation.interaction_global.row_count != row_count
        || relation.interaction_global.column_count != LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH
    {
        return Err("local-word raw quotient geometry".into());
    }
    let mut preprocessed_reader = relation.preprocessed.column_reader()?;
    let mut original_reader = relation.original.column_reader()?;
    let mut interaction_reader = relation.interaction.column_reader()?;
    let mut interaction_global_reader = relation.interaction_global.column_reader()?;
    let global_columns = (0..LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH)
        .map(|column| relation.interaction_global.column_values(column))
        .collect::<Result<Vec<_>, _>>()?;

    let mut zerofier = trace_zerofier_values(eval_log, relation_trace_log);
    stwo::core::utils::bit_reverse(&mut zerofier);
    if zerofier.iter().any(|value| *value == 0) {
        return Err("local-word raw quotient zerofier".into());
    }
    let mut inverse_by_value = HashMap::<u32, u32>::new();
    for value in &zerofier {
        inverse_by_value
            .entry(*value)
            .or_insert_with(|| inv_m(*value as u64) as u32);
    }
    let inverse_zerofier = zerofier
        .iter()
        .map(|value| inverse_by_value[value])
        .collect::<Vec<_>>();
    let mut writer = DiskQm31Writer::create(directory, row_count)?;
    const ROW_CHUNK: usize = 1 << 10;
    for start in (0..row_count).step_by(ROW_CHUNK) {
        let count = (row_count - start).min(ROW_CHUNK);
        let preprocessed = preprocessed_reader.read_next(count)?;
        let original = original_reader.read_next(count)?;
        let interaction_chunk = interaction_reader.read_next(count)?;
        let interaction_global_chunk = interaction_global_reader.read_next(count)?;
        let quotient = (0..count)
            .into_par_iter()
            .map(|row| -> Result<Qm31Value, String> {
                let absolute_row = start + row;
                let original_row = original
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>();
                let preprocessed_row = preprocessed
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>();
                let interaction = local_word_interaction_from_committed_column_chunks(
                    &interaction_chunk,
                    &interaction_global_chunk,
                    row,
                )?;
                let previous_index = stwo::core::utils::offset_bit_reversed_circle_domain_index(
                    absolute_row,
                    relation_trace_log,
                    eval_log,
                    -1,
                );
                let mut interaction_previous = vec![[0u32; 4]; LOCAL_WORD_INTERACTION_COLUMNS];
                for (position, column) in LOCAL_WORD_GLOBAL_INTERACTION_QM31_COLUMNS
                    .into_iter()
                    .enumerate()
                {
                    interaction_previous[column] = std::array::from_fn(|coordinate| {
                        global_columns[position * 4 + coordinate][previous_index]
                    });
                }
                let residuals = local_word_v14_air_residuals(
                    &original_row,
                    &preprocessed_row,
                    &interaction,
                    &interaction_previous,
                    &relation.interaction_challenges,
                    &relation.boundary_challenges,
                    relation.boundary_claimed_sum,
                )?;
                let composition =
                    mix_local_word_v14_air_residuals(&residuals, relation.constraint_alpha)?;
                Ok(composition
                    .map(|coordinate| mul_m31_fast(coordinate, inverse_zerofier[absolute_row])))
            })
            .collect::<Result<Vec<_>, _>>()?;
        writer.write_chunk(&quotient)?;
    }
    if preprocessed_reader.remaining() != 0
        || original_reader.remaining() != 0
        || interaction_reader.remaining() != 0
        || interaction_global_reader.remaining() != 0
    {
        return Err("local-word raw quotient reader completion".into());
    }
    writer.finish()
}

/**
 * Build the private raw quotient in bounded memory. This is an internal prover
 * artifact, not a commitment: it must cross the quotient/FRI mask before proof encoding.
 */
pub fn build_local_word_raw_quotient(
    relation: &LocalWordCommittedRelation,
    directory: &std::path::Path,
) -> Result<DiskQm31Evaluation, String> {
    if relation.preprocessed.row_count != 1 << LOCAL_WORD_EVAL_LOG {
        return Err("local-word production quotient rows".into());
    }
    build_local_word_raw_quotient_with_trace_log(relation, directory, LOCAL_WORD_RELATION_LOG)
}

fn build_local_word_quotient_seal_with_degree(
    raw: &DiskQm31Evaluation,
    workspace: &std::path::Path,
    mask_degree_rows: usize,
) -> Result<LocalWordSealedQuotient, String> {
    if workspace.exists()
        || raw.row_count < 2
        || !raw.row_count.is_power_of_two()
        || mask_degree_rows < 2
        || !mask_degree_rows.is_power_of_two()
        || mask_degree_rows > raw.row_count
    {
        return Err("local-word quotient seal geometry".into());
    }
    std::fs::create_dir(workspace)
        .map_err(|error| format!("create local-word quotient seal: {error}"))?;
    let fresh_qm31_polynomial = || {
        (0..4)
            .map(|_| {
                (0..mask_degree_rows)
                    .map(|_| fresh_m31().0)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let quotient = commit_disk_qm31_evaluation(
        "local-word:quotient",
        raw,
        &workspace.join("quotient"),
    )?;
    let fri_mask = build_disk_matrix_commitment(
        "local-word:fri-mask",
        &fresh_qm31_polynomial(),
        DiskColumnExtension::RandomPolynomial {
            eval_log: raw.row_count.ilog2(),
        },
        &workspace.join("fri-mask"),
    )?;
    let quotient_and_fri_mask = combine_disk_matrix_commitments(
        "local-word:quotient-and-fri-mask",
        &[&quotient, &fri_mask],
        &workspace.join("quotient-and-fri-mask"),
    )?;
    Ok(LocalWordSealedQuotient {
        quotient,
        fri_mask,
        quotient_and_fri_mask,
    })
}

/** Commit the sealed-trace quotient and add one independent degree-2^20 FRI isolator. */
pub fn build_local_word_quotient_seal(
    raw: &DiskQm31Evaluation,
    workspace: &std::path::Path,
) -> Result<LocalWordSealedQuotient, String> {
    if raw.row_count != 1 << LOCAL_WORD_EVAL_LOG {
        return Err("local-word production quotient seal rows".into());
    }
    build_local_word_quotient_seal_with_degree(raw, workspace, 1 << 20)
}

pub fn local_word_quotient_identity(
    composition: Qm31Value,
    zerofier: u32,
    quotient: Qm31Value,
) -> bool {
    let z = BaseField::from_u32_unchecked(zerofier);
    qm31_to_secure(composition) == qm31_to_secure(quotient) * z
}

pub fn local_word_fri_batch_value(
    original: &[u32],
    interaction_groups: [&[u32]; 4],
    quotient: Qm31Value,
    fri_mask: Qm31Value,
    beta: Qm31Value,
) -> Result<Qm31Value, String> {
    if original.len() != LOCAL_WORD_ORIGINAL_COLUMNS
        || interaction_groups
            .iter()
            .zip(LOCAL_WORD_INTERACTION_GROUP_M31_WIDTHS)
            .any(|(group, width)| group.len() != width)
        || original
            .iter()
            .chain(interaction_groups.into_iter().flatten())
            .any(|value| *value as u64 >= M31)
    {
        return Err("local-word FRI batch value geometry".into());
    }
    let mut packed = Vec::with_capacity(
        2 + original.len().div_ceil(4)
            + interaction_groups
                .iter()
                .map(|group| group.len() / 4)
                .sum::<usize>(),
    );
    for chunk in original.chunks(4) {
        packed.push(qm31_to_secure(std::array::from_fn(|coordinate| {
            chunk.get(coordinate).copied().unwrap_or(0)
        })));
    }
    for group in interaction_groups {
        for chunk in group.chunks_exact(4) {
            packed.push(qm31_to_secure(std::array::from_fn(|coordinate| {
                chunk[coordinate]
            })));
        }
    }
    packed.push(qm31_to_secure(quotient));
    let beta = qm31_to_secure(beta);
    let mut values = packed.into_iter();
    let mut accumulator = values.next().ok_or("local-word FRI batch values")?;
    for value in values {
        accumulator = accumulator * beta + value;
    }
    // The independent FRI mask has coefficient exactly one. It can neither be
    // cancelled by beta nor correlated with the quotient pad.
    Ok(secure_to_qm31(accumulator + qm31_to_secure(fri_mask)))
}

fn build_local_word_fri_batch_at_rows(
    relation: &LocalWordCommittedRelation,
    quotient: &LocalWordSealedQuotient,
    beta: Qm31Value,
    directory: &std::path::Path,
) -> Result<DiskQm31Evaluation, String> {
    let row_count = relation.original.row_count;
    if quotient.quotient.row_count != row_count
        || quotient.fri_mask.row_count != row_count
        || quotient.quotient.column_count != 4
        || quotient.fri_mask.column_count != 4
        || relation.original.column_count != LOCAL_WORD_ORIGINAL_COLUMNS
        || relation.interaction.row_count != row_count
        || relation.interaction.column_count != LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH
        || relation.interaction_global.row_count != row_count
        || relation.interaction_global.column_count != LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH
    {
        return Err("local-word FRI batch geometry".into());
    }
    let mut original_reader = relation.original.column_reader()?;
    let mut interaction_reader = relation.interaction.column_reader()?;
    let mut interaction_global_reader = relation.interaction_global.column_reader()?;
    let mut quotient_reader = quotient.quotient.column_reader()?;
    let mut fri_mask_reader = quotient.fri_mask.column_reader()?;
    let beta = qm31_to_secure(beta);
    let mut writer = DiskQm31Writer::create(directory, row_count)?;
    const ROW_CHUNK: usize = 1 << 12;
    for _start in (0..row_count).step_by(ROW_CHUNK) {
        let count = original_reader.remaining().min(ROW_CHUNK);
        let original = original_reader.read_next(count)?;
        let interaction = interaction_reader.read_next(count)?;
        let interaction_global = interaction_global_reader.read_next(count)?;
        let quotient_columns = quotient_reader.read_next(count)?;
        let fri_mask_columns = fri_mask_reader.read_next(count)?;
        let batch = (0..count)
            .into_par_iter()
            .map(|row| {
                let mut values = Vec::with_capacity(27);
                for chunk in original.chunks(4) {
                    values.push(qm31_to_secure(std::array::from_fn(|coordinate| {
                        chunk.get(coordinate).map(|column| column[row]).unwrap_or(0)
                    })));
                }
                for columns in [&interaction, &interaction_global] {
                    for chunk in columns.chunks_exact(4) {
                        values.push(qm31_to_secure(std::array::from_fn(|coordinate| {
                            chunk[coordinate][row]
                        })));
                    }
                }
                values.push(qm31_to_secure(std::array::from_fn(|coordinate| {
                    quotient_columns[coordinate][row]
                })));
                let mut values = values.into_iter();
                let mut accumulator = values.next().expect("local-word FRI batch values");
                for value in values {
                    accumulator = accumulator * beta + value;
                }
                secure_to_qm31(
                    accumulator
                        + qm31_to_secure(std::array::from_fn(|coordinate| {
                            fri_mask_columns[coordinate][row]
                        })),
                )
            })
            .collect::<Vec<_>>();
        writer.write_chunk(&batch)?;
    }
    if original_reader.remaining() != 0
        || quotient_reader.remaining() != 0
        || fri_mask_reader.remaining() != 0
        || interaction_reader.remaining() != 0
        || interaction_global_reader.remaining() != 0
    {
        return Err("local-word FRI batch reader completion".into());
    }
    writer.finish()
}

pub fn build_local_word_fri_batch(
    relation: &LocalWordCommittedRelation,
    quotient: &LocalWordSealedQuotient,
    beta: Qm31Value,
    directory: &std::path::Path,
) -> Result<DiskQm31Evaluation, String> {
    if relation.original.row_count != 1 << LOCAL_WORD_EVAL_LOG {
        return Err("local-word production FRI batch rows".into());
    }
    build_local_word_fri_batch_at_rows(relation, quotient, beta, directory)
}

pub fn local_word_batch_transcript(
    bundle: &LocalWordProverBundle,
    relation: &LocalWordCommittedRelation,
    quotient: &LocalWordSealedQuotient,
) -> Result<(SuccessorTranscript, Qm31Value, [u8; 32]), String> {
    let descriptor_digest: [u8; 32] = Sha256::digest(&bundle.construction_descriptor).into();
    let (mut transcript, interaction, boundary) = local_word_v15_interaction_transcript(
        &bundle.transcript_initial,
        descriptor_digest,
        relation.preprocessed.root,
        relation.original.root,
    );
    if interaction != relation.interaction_challenges || boundary != relation.boundary_challenges {
        return Err("local-word interaction transcript replay".into());
    }
    let (claimed_sum, inverses) = local_word_public_boundary_claim(bundle, &boundary)?;
    if claimed_sum != relation.boundary_claimed_sum || inverses != relation.boundary_inverses {
        return Err("local-word public boundary replay".into());
    }
    local_word_v15_public_boundary_transcript(&mut transcript, &inverses)?;
    if transcript.digest() != relation.interaction_transcript_digest {
        return Err("local-word interaction transcript replay".into());
    }
    let (constraint_alpha, digest) = local_word_v15_composition_transcript(
        &mut transcript,
        relation.interaction.root,
        relation.interaction_global.root,
    );
    if constraint_alpha != relation.constraint_alpha
        || digest != relation.composition_transcript_digest
    {
        return Err("local-word composition transcript replay".into());
    }
    transcript.absorb(
        "local-word-quotient-and-fri-mask-root",
        &quotient.quotient_and_fri_mask.root,
    );
    let beta = transcript.challenge_qm31("local-word-batch-beta");
    let digest = transcript.digest();
    Ok((transcript, beta, digest))
}

fn local_word_query_schedule_is_full(
    queries: &[usize],
    parameters: LocalWordProofParameters,
) -> bool {
    let global = sorted_unique(
        queries
            .iter()
            .copied()
            .chain(queries.iter().map(|index| {
                stwo::core::utils::offset_bit_reversed_circle_domain_index(
                    *index,
                    parameters.relation_log,
                    parameters.eval_log,
                    -1,
                )
            }))
            .collect(),
    );
    global.len() == 2 * queries.len()
}

fn local_word_query_indices(
    transcript: &SuccessorTranscript,
    parameters: LocalWordProofParameters,
) -> Result<Vec<usize>, String> {
    let queries = transcript.query_indices_with_orbit_log(
        parameters.row_count(),
        parameters.fri.queries,
        parameters.fri.query_orbit_log,
    );
    if !local_word_query_schedule_is_full(&queries, parameters) {
        return Err("local-word global query collision".into());
    }
    Ok(queries)
}

struct LocalWordFriTranscript<'a> {
    inner: &'a mut SuccessorTranscript,
    parameters: LocalWordProofParameters,
}

impl FriProverTranscript for LocalWordFriTranscript<'_> {
    fn fri_absorb(&mut self, label: &str, data: &[u8]) {
        self.inner.absorb(label, data);
    }

    fn fri_challenge_qm31(&mut self, label: &str) -> Qm31Value {
        self.inner.challenge_qm31(label)
    }

    fn fri_grind(
        &mut self,
        bits: u8,
        row_count: usize,
        query_count: usize,
        query_orbit_log: u32,
    ) -> u32 {
        assert_eq!(row_count, self.parameters.row_count());
        assert_eq!(query_count, self.parameters.fri.queries);
        assert_eq!(query_orbit_log, self.parameters.fri.query_orbit_log);
        self.inner.grind_for_queries_matching(
            bits,
            row_count,
            query_count,
            query_orbit_log,
            |queries| local_word_query_schedule_is_full(queries, self.parameters),
        )
    }

    fn fri_query_indices(
        &self,
        row_count: usize,
        count: usize,
        query_orbit_log: u32,
    ) -> Vec<usize> {
        assert_eq!(row_count, self.parameters.row_count());
        assert_eq!(count, self.parameters.fri.queries);
        assert_eq!(query_orbit_log, self.parameters.fri.query_orbit_log);
        local_word_query_indices(self.inner, self.parameters).expect("local-word query schedule")
    }
}

fn prove_local_word_bundle_with_parameters(
    bundle: LocalWordProverBundle,
    workspace: &std::path::Path,
    parameters: LocalWordProofParameters,
) -> Result<LocalWordProveResult, String> {
    parameters.validate()?;
    if bundle.relation_rows != 1usize << parameters.relation_log {
        return Err("local-word prover relation rows".into());
    }
    if workspace.exists() {
        return Err("local-word prover workspace exists".into());
    }
    std::fs::create_dir(workspace)
        .map_err(|error| format!("create local-word prover workspace: {error}"))?;
    let relation = commit_local_word_relation_with_parameters(
        &bundle,
        &workspace.join("relation"),
        parameters,
    )?;
    let raw_quotient = build_local_word_raw_quotient_with_trace_log(
        &relation,
        &workspace.join("raw-quotient"),
        parameters.relation_log,
    )?;
    let raw_values = raw_quotient.values()?;
    let quotient_degree_bound = qm31_circle_degree_bound_bit_reversed(&raw_values);
    drop(raw_values);
    if quotient_degree_bound > parameters.quotient_degree_rows {
        return Err(format!(
            "local-word quotient degree {quotient_degree_bound}"
        ));
    }
    let quotient = build_local_word_quotient_seal_with_degree(
        &raw_quotient,
        &workspace.join("quotient-seal"),
        parameters.quotient_degree_rows,
    )?;
    let (mut transcript, beta, batch_digest) =
        local_word_batch_transcript(&bundle, &relation, &quotient)?;
    let fri_transcript_start = transcript.clone();
    let batch = build_local_word_fri_batch_at_rows(
        &relation,
        &quotient,
        beta,
        &workspace.join("fri-batch"),
    )?;
    let mut natural_batch = batch.values()?;
    stwo::core::utils::bit_reverse(&mut natural_batch);
    let fri = {
        let mut local_transcript = LocalWordFriTranscript {
            inner: &mut transcript,
            parameters,
        };
        prove_successor_fri(&natural_batch, &mut local_transcript, parameters.fri)
            .map_err(str::to_owned)?
    };
    drop(natural_batch);
    let query_digest = transcript.digest();
    let mut manifest_transcript = fri_transcript_start;
    let mut fri_alphas = Vec::with_capacity(fri.layers.len());
    let fri_split = fri.layers.len().div_ceil(2);
    let mut fri_mid_digest = [0u8; 32];
    for (round, layer) in fri.layers.iter().enumerate() {
        manifest_transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        fri_alphas.push(manifest_transcript.challenge_qm31(&format!("fri-alpha:{round}")));
        if round + 1 == fri_split {
            fri_mid_digest = manifest_transcript.digest();
        }
    }
    let fri_roots_digest = manifest_transcript.digest();
    manifest_transcript.absorb("fri-final", &encode_qm31_values(&fri.final_coefficients));
    if !manifest_transcript.accept_grind(parameters.fri.grind_bits, fri.grind_nonce)
        || manifest_transcript.digest() != query_digest
    {
        return Err("local-word prover transcript manifest".into());
    }
    let transcript_manifest = LocalWordTranscriptManifest {
        interaction_challenges: local_word_v15_interaction_challenge_values(
            &relation.interaction_challenges,
            &relation.boundary_challenges,
        ),
        interaction_digest: relation.interaction_transcript_digest,
        constraint_alpha: relation.constraint_alpha,
        composition_digest: relation.composition_transcript_digest,
        batch_beta: beta,
        batch_digest,
        fri_alphas,
        fri_mid_digest,
        fri_roots_digest,
        query_digest,
    };
    let queries = local_word_query_indices(&transcript, parameters)?;
    let composition_partials = queries
        .iter()
        .map(|query| {
            let residuals = local_word_air_residuals_at_committed_row_with_trace_log(
                &relation,
                *query,
                parameters.relation_log,
            )?;
            local_word_v14_air_composition_partials(&residuals, relation.constraint_alpha)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let current = sorted_unique(queries.clone());
    let global = sorted_unique(
        current
            .iter()
            .copied()
            .chain(current.iter().map(|index| {
                stwo::core::utils::offset_bit_reversed_circle_domain_index(
                    *index,
                    parameters.relation_log,
                    parameters.eval_log,
                    -1,
                )
            }))
            .collect(),
    );
    let construction_digest: [u8; 32] = Sha256::digest(&bundle.construction_descriptor).into();
    let proof = LocalWordSealedProof {
        version: LOCAL_WORD_PROOF_VERSION,
        profile: bundle.profile,
        construction_digest,
        public_boundary_inverses: relation.boundary_inverses.clone(),
        public_boundary_claimed_sum: relation.boundary_claimed_sum,
        preprocessed: relation.preprocessed.opening(&current)?,
        original: relation.original.opening(&current)?,
        interaction: relation.interaction.opening(&current)?,
        interaction_global: relation.interaction_global.opening(&global)?,
        quotient_and_fri_mask: quotient.quotient_and_fri_mask.opening(&current)?,
        fri,
        transcript_manifest,
        queries,
        composition_partials,
    };
    Ok(LocalWordProveResult {
        proof,
        quotient_degree_bound,
        workspace: workspace.to_path_buf(),
    })
}

pub fn prove_local_word_bundle(
    bundle: LocalWordProverBundle,
    workspace: &std::path::Path,
) -> Result<LocalWordProveResult, String> {
    prove_local_word_bundle_with_parameters(bundle, workspace, LocalWordProofParameters::PRODUCTION)
}

fn verify_local_word_sealed_proof_with_parameters(
    proof: &LocalWordSealedProof,
    profile: u8,
    transcript_initial: &[u8],
    construction_descriptor: &[u8],
    public_words: &[LocalWordPublicWord],
    expected_preprocessed_root: [u8; 32],
    parameters: LocalWordProofParameters,
) -> Result<(), String> {
    parameters.validate()?;
    let row_count = parameters.row_count();
    if proof.version != LOCAL_WORD_PROOF_VERSION
        || proof.profile != profile
        || profile > 2
        || transcript_initial.is_empty()
        || proof.construction_digest != <[u8; 32]>::from(Sha256::digest(construction_descriptor))
        || proof.preprocessed.root != expected_preprocessed_root
        || public_words.is_empty()
        || proof.transcript_manifest.interaction_challenges.len()
            != LOCAL_WORD_INTERACTION_CHALLENGE_COUNT
        || proof.transcript_manifest.fri_alphas.len() != parameters.fri_layers()
        || proof.queries.len() != parameters.fri.queries
        || proof
            .queries
            .iter()
            .any(|query| *query >= parameters.row_count())
        || proof.queries.len() != parameters.fri.queries
        || proof.composition_partials.len() != parameters.fri.queries
        || proof
            .composition_partials
            .iter()
            .flatten()
            .flatten()
            .any(|coordinate| *coordinate as u64 >= M31)
        || public_words
            .iter()
            .any(|word| word.row >= 1 << parameters.relation_log)
    {
        return Err("local-word verifier key".into());
    }
    let (mut transcript, interaction_challenges, boundary_challenges) =
        local_word_v15_interaction_transcript(
            transcript_initial,
            proof.construction_digest,
            proof.preprocessed.root,
            proof.original.root,
        );
    if proof.transcript_manifest.interaction_challenges
        != local_word_v15_interaction_challenge_values(
            &interaction_challenges,
            &boundary_challenges,
        )
    {
        return Err("local-word interaction challenge manifest".into());
    }
    let (boundary_claimed_sum, expected_inverses) =
        local_word_public_boundary_claim_for_words(public_words, &boundary_challenges)?;
    if proof.public_boundary_inverses != expected_inverses {
        return Err("local-word public boundary inverses".into());
    }
    if proof.public_boundary_claimed_sum != boundary_claimed_sum {
        return Err("local-word public boundary claimed sum".into());
    }
    local_word_v15_public_boundary_transcript(&mut transcript, &proof.public_boundary_inverses)?;
    if proof.transcript_manifest.interaction_digest != transcript.digest() {
        return Err("local-word interaction digest manifest".into());
    }
    let (constraint_alpha, composition_digest) = local_word_v15_composition_transcript(
        &mut transcript,
        proof.interaction.root,
        proof.interaction_global.root,
    );
    if proof.transcript_manifest.constraint_alpha != constraint_alpha
        || proof.transcript_manifest.composition_digest != composition_digest
    {
        return Err("local-word composition manifest".into());
    }
    transcript.absorb(
        "local-word-quotient-and-fri-mask-root",
        &proof.quotient_and_fri_mask.root,
    );
    let beta = transcript.challenge_qm31("local-word-batch-beta");
    if proof.transcript_manifest.batch_beta != beta
        || proof.transcript_manifest.batch_digest != transcript.digest()
    {
        return Err("local-word batch manifest".into());
    }
    let mut manifest_transcript = transcript.clone();
    let fri_split = proof.fri.layers.len().div_ceil(2);
    let mut fri_alphas = Vec::with_capacity(proof.fri.layers.len());
    let mut fri_mid_digest = [0u8; 32];
    for (round, layer) in proof.fri.layers.iter().enumerate() {
        manifest_transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        fri_alphas.push(manifest_transcript.challenge_qm31(&format!("fri-alpha:{round}")));
        if round + 1 == fri_split {
            fri_mid_digest = manifest_transcript.digest();
        }
    }
    if proof.transcript_manifest.fri_alphas != fri_alphas
        || proof.transcript_manifest.fri_mid_digest != fri_mid_digest
        || proof.transcript_manifest.fri_roots_digest != manifest_transcript.digest()
    {
        return Err("local-word FRI root manifest".into());
    }
    manifest_transcript.absorb(
        "fri-final",
        &encode_qm31_values(&proof.fri.final_coefficients),
    );
    if !manifest_transcript.accept_grind(parameters.fri.grind_bits, proof.fri.grind_nonce)
        || proof.transcript_manifest.query_digest != manifest_transcript.digest()
    {
        return Err("local-word query digest manifest".into());
    }
    verify_successor_fri(
        &proof.fri,
        parameters.eval_log,
        &mut transcript,
        parameters.fri,
    )
    .map_err(str::to_owned)?;
    let queries = local_word_query_indices(&transcript, parameters)?;
    if proof.queries != queries {
        return Err("local-word query manifest".into());
    }
    let current = sorted_unique(queries.clone());
    let global = sorted_unique(
        current
            .iter()
            .copied()
            .chain(current.iter().map(|index| {
                stwo::core::utils::offset_bit_reversed_circle_domain_index(
                    *index,
                    parameters.relation_log,
                    parameters.eval_log,
                    -1,
                )
            }))
            .collect(),
    );
    let preprocessed = verify_and_decode_matrix_opening(
        &proof.preprocessed,
        "local-word:preprocessed",
        LOCAL_WORD_PREPROCESSED_COLUMNS,
        &current,
        row_count,
        true,
    )?;
    let original = verify_and_decode_matrix_opening(
        &proof.original,
        "local-word:original",
        LOCAL_WORD_ORIGINAL_COLUMNS,
        &current,
        row_count,
        true,
    )?;
    let interaction = verify_and_decode_matrix_opening(
        &proof.interaction,
        "local-word:interaction",
        LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH,
        &current,
        row_count,
        true,
    )?;
    let interaction_global = verify_and_decode_matrix_opening(
        &proof.interaction_global,
        "local-word:interaction-global",
        LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH,
        &global,
        row_count,
        true,
    )?;
    let quotient_and_fri_mask = verify_and_decode_matrix_opening(
        &proof.quotient_and_fri_mask,
        "local-word:quotient-and-fri-mask",
        8,
        &current,
        row_count,
        true,
    )?;
    let layer_zero = proof
        .fri
        .layers
        .first()
        .ok_or("local-word FRI layer zero")?;
    let layer_zero_values = layer_zero
        .merkle
        .indices
        .iter()
        .copied()
        .zip(layer_zero.values.iter().copied())
        .collect::<std::collections::BTreeMap<_, _>>();

    for (query_number, query) in queries.into_iter().enumerate() {
        let previous = stwo::core::utils::offset_bit_reversed_circle_domain_index(
            query,
            parameters.relation_log,
            parameters.eval_log,
            -1,
        );
        let interaction_current = interaction
            .get(&query)
            .ok_or("local-word interaction opening")?;
        let interaction_global_row = interaction_global
            .get(&query)
            .ok_or("local-word interaction global opening")?;
        let group_rows = [
            &interaction_current[..20],
            &interaction_current[20..40],
            &interaction_current[40..56],
            interaction_global_row.as_slice(),
        ];
        let interaction_row =
            local_word_interaction_from_packed_rows(interaction_current, interaction_global_row)?;
        let previous_global = interaction_global
            .get(&previous)
            .ok_or("local-word global predecessor")?;
        let mut interaction_previous = vec![[0u32; 4]; LOCAL_WORD_INTERACTION_COLUMNS];
        for (position, column) in LOCAL_WORD_GLOBAL_INTERACTION_QM31_COLUMNS
            .into_iter()
            .enumerate()
        {
            interaction_previous[column]
                .copy_from_slice(&previous_global[position * 4..position * 4 + 4]);
        }
        let original_row = original.get(&query).ok_or("local-word original opening")?;
        let preprocessed_row = preprocessed
            .get(&query)
            .ok_or("local-word preprocessed opening")?;
        let residuals = local_word_v14_air_residuals(
            original_row,
            preprocessed_row,
            &interaction_row,
            &interaction_previous,
            &interaction_challenges,
            &boundary_challenges,
            boundary_claimed_sum,
        )?;
        let expected_partials =
            local_word_v14_air_composition_partials(&residuals, constraint_alpha)?;
        if proof.composition_partials[query_number] != expected_partials {
            return Err("local-word composition partial".into());
        }
        let composition = combine_local_word_v14_air_composition_partials(
            proof.composition_partials[query_number],
            constraint_alpha,
        );
        let quotient_and_mask_row = quotient_and_fri_mask
            .get(&query)
            .ok_or("local-word quotient and FRI mask opening")?;
        let quotient = qm31_from_opened_row(&quotient_and_mask_row[..4])?;
        let fri_mask = qm31_from_opened_row(&quotient_and_mask_row[4..])?;
        let zerofier =
            trace_zerofier_at_bit_reversed(query, parameters.eval_log, parameters.relation_log).0;
        if !local_word_quotient_identity(composition, zerofier, quotient) {
            return Err("local-word quotient identity".into());
        }
        let batch = local_word_fri_batch_value(
            original_row,
            [group_rows[0], group_rows[1], group_rows[2], group_rows[3]],
            quotient,
            fri_mask,
            beta,
        )?;
        if layer_zero_values.get(&query) != Some(&batch) {
            return Err("local-word FRI batch link".into());
        }
    }
    Ok(())
}

pub fn verify_local_word_sealed_proof(
    proof: &LocalWordSealedProof,
    profile: u8,
    transcript_initial: &[u8],
    construction_descriptor: &[u8],
    public_words: &[LocalWordPublicWord],
    expected_preprocessed_root: [u8; 32],
) -> Result<(), String> {
    verify_local_word_sealed_proof_with_parameters(
        proof,
        profile,
        transcript_initial,
        construction_descriptor,
        public_words,
        expected_preprocessed_root,
        LocalWordProofParameters::PRODUCTION,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolAirNode {
    Constant(u32),
    Public(u16),
    Input {
        oracle: u8,
        column: u16,
        offset: i32,
    },
    Add {
        left: u32,
        right: u32,
    },
    Sub {
        left: u32,
        right: u32,
    },
    Mul {
        left: u32,
        right: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolAirProgram {
    pub profile: u8,
    pub public_input_count: usize,
    pub nodes: Vec<PoolAirNode>,
    pub outputs: Vec<(u32, String)>,
}

struct AirCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> AirCursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("AIR program offset")?;
        if end > self.bytes.len() {
            return Err("truncated AIR program".into());
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16_be(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32_be(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i32_be(&mut self) -> Result<i32, String> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
}

/** Decode the matrix-free SKLB v1 local-word prover handoff. */
pub fn decode_local_word_prover_bundle(bytes: &[u8]) -> Result<LocalWordProverBundle, String> {
    let mut cursor = AirCursor { bytes, offset: 0 };
    if cursor.take(4)? != b"SKLB" || cursor.u8()? != 1 {
        return Err("local-word prover bundle codec".into());
    }
    let profile = cursor.u8()?;
    if profile > 2 {
        return Err("local-word prover profile".into());
    }
    let relation_rows = cursor.u32_be()? as usize;
    let initial_len = cursor.u32_be()? as usize;
    if initial_len == 0 || initial_len > 1 << 20 {
        return Err("local-word prover transcript initial".into());
    }
    let transcript_initial = cursor.take(initial_len)?.to_vec();
    let descriptor_len = cursor.u32_be()? as usize;
    if descriptor_len == 0 || descriptor_len > 1 << 20 {
        return Err("local-word construction descriptor".into());
    }
    let construction_descriptor = cursor.take(descriptor_len)?.to_vec();
    let program_len = cursor.u32_be()? as usize;
    if program_len == 0 || program_len > 1 << 22 {
        return Err("local-word program bytes".into());
    }
    let program_bytes = cursor.take(program_len)?.to_vec();
    let program = decode_local_sha_program(&program_bytes)?;
    if relation_rows < local_sha_relation_rows(&program) || relation_rows != 1 << 18 {
        return Err("local-word relation rows".into());
    }
    let input_count = cursor.u32_be()? as usize;
    if input_count != program.input_count {
        return Err("local-word prover input count".into());
    }
    let inputs = cursor
        .take(input_count.checked_mul(4).ok_or("local-word input bytes")?)?
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    let public_count = cursor.u16_be()? as usize;
    if public_count == 0 || public_count > 1_024 {
        return Err("local-word public word count".into());
    }
    let mut public_words = Vec::with_capacity(public_count);
    let mut rows = std::collections::HashSet::with_capacity(public_count);
    for position in 0..public_count {
        let id = cursor.u16_be()?;
        let row = cursor.u32_be()? as usize;
        let expected = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap());
        if id as usize != position + 1 || !rows.insert(row) {
            return Err("local-word public word order".into());
        }
        let input = match program.rows.get(row) {
            Some(LocalShaOperation::Input { input }) => *input,
            _ => return Err("local-word public input row".into()),
        };
        if inputs[input] != expected {
            return Err("local-word public input value".into());
        }
        public_words.push(LocalWordPublicWord { id, row, expected });
    }
    if cursor.offset != bytes.len() {
        return Err("trailing local-word prover bundle bytes".into());
    }
    Ok(LocalWordProverBundle {
        profile,
        relation_rows,
        transcript_initial,
        construction_descriptor,
        program_bytes,
        program,
        inputs,
        public_words,
    })
}

pub fn decode_pool_air_program(bytes: &[u8]) -> Result<PoolAirProgram, String> {
    let mut cursor = AirCursor { bytes, offset: 0 };
    if cursor.take(4)? != b"SKAI" {
        return Err("AIR program codec".into());
    }
    let version = cursor.u8()?;
    if version != 2 && version != 3 {
        return Err("AIR program version".into());
    }
    let profile = cursor.u8()?;
    if profile > 2 {
        return Err("AIR profile".into());
    }
    let node_count = cursor.u32_be()? as usize;
    let output_count = cursor.u32_be()? as usize;
    let public_input_count = cursor.u16_be()? as usize;
    if node_count == 0 || node_count > 1_000_000 || output_count == 0 || output_count > 100_000 {
        return Err("AIR program shape".into());
    }
    let mut nodes = Vec::with_capacity(node_count);
    for id in 0..node_count {
        let node = match cursor.u8()? {
            0 => {
                let value = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap());
                if value as u64 >= M31 {
                    return Err("AIR constant".into());
                }
                PoolAirNode::Constant(value)
            }
            5 => {
                let index = cursor.u16_be()?;
                if index as usize >= public_input_count {
                    return Err("AIR public input".into());
                }
                PoolAirNode::Public(index)
            }
            1 => {
                let oracle = cursor.u8()?;
                if oracle > 3 {
                    return Err("AIR oracle".into());
                }
                let column = cursor.u16_be()?;
                let offset = if version == 2 {
                    cursor.u8()? as i8 as i32
                } else {
                    cursor.i32_be()?
                };
                PoolAirNode::Input {
                    oracle,
                    column,
                    offset,
                }
            }
            tag @ 2..=4 => {
                let left = cursor.u32_be()?;
                let right = cursor.u32_be()?;
                if left as usize >= id || right as usize >= id {
                    return Err("AIR node order".into());
                }
                match tag {
                    2 => PoolAirNode::Add { left, right },
                    3 => PoolAirNode::Sub { left, right },
                    _ => PoolAirNode::Mul { left, right },
                }
            }
            _ => return Err("AIR node tag".into()),
        };
        nodes.push(node);
    }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let node = cursor.u32_be()?;
        if node as usize >= nodes.len() {
            return Err("AIR output node".into());
        }
        let label_len = cursor.u16_be()? as usize;
        if label_len == 0 {
            return Err("AIR output label".into());
        }
        let label = std::str::from_utf8(cursor.take(label_len)?)
            .map_err(|_| "AIR output utf8")?
            .to_owned();
        outputs.push((node, label));
    }
    if cursor.offset != bytes.len() {
        return Err("trailing AIR program bytes".into());
    }
    Ok(PoolAirProgram {
        profile,
        public_input_count,
        nodes,
        outputs,
    })
}

pub fn evaluate_pool_air_program(
    program: &PoolAirProgram,
    public_inputs: &[u32],
    mut read: impl FnMut(u8, u16, i32) -> u32,
) -> Vec<u32> {
    assert_eq!(public_inputs.len(), program.public_input_count);
    assert!(public_inputs.iter().all(|value| (*value as u64) < M31));
    let mut values = Vec::with_capacity(program.nodes.len());
    for node in &program.nodes {
        let value = match *node {
            PoolAirNode::Constant(value) => value,
            PoolAirNode::Public(index) => public_inputs[index as usize],
            PoolAirNode::Input {
                oracle,
                column,
                offset,
            } => read(oracle, column, offset),
            PoolAirNode::Add { left, right } => {
                add_m(values[left as usize] as u64, values[right as usize] as u64) as u32
            }
            PoolAirNode::Sub { left, right } => {
                sub_m(values[left as usize] as u64, values[right as usize] as u64) as u32
            }
            PoolAirNode::Mul { left, right } => {
                mul_m(values[left as usize] as u64, values[right as usize] as u64) as u32
            }
        };
        values.push(value);
    }
    program
        .outputs
        .iter()
        .map(|(node, _)| values[*node as usize])
        .collect()
}

pub fn pool_air_residual_digest(values: &[u32]) -> [u8; 32] {
    let encoded: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    sha256(&[&encoded])
}

const POOL_AIR_PARTIAL_START_LABELS: [&str; 7] = [
    "sha-bit:256",
    "primary-constant:0",
    "sha-t1-low",
    "sha-digest-carry-low-zero:0",
    "bus-message-constant:0",
    "walk-direction-bit",
    "sha-aux-big-e:0",
];
const POOL_AIR_COEFFICIENT_SEED_DOMAIN: &[u8] = b"ShieldKit/AIRCoefficientSeed/v1";
const POOL_AIR_HORNER_LANES: usize = 4;

fn pool_air_partial_ranges(program: &PoolAirProgram) -> Result<[(usize, usize); 8], String> {
    let mut starts = [0usize; 8];
    for (partial, label) in POOL_AIR_PARTIAL_START_LABELS.iter().enumerate() {
        let matches: Vec<usize> = program
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(index, (_, constraint))| (constraint == label).then_some(index))
            .collect();
        if matches.len() != 1 {
            return Err(format!("AIR composition boundary {label}"));
        }
        starts[partial + 1] = matches[0];
    }
    if starts.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("AIR composition partial order".into());
    }
    Ok(std::array::from_fn(|partial| {
        (
            starts[partial],
            starts
                .get(partial + 1)
                .copied()
                .unwrap_or(program.outputs.len()),
        )
    }))
}

fn pool_air_coefficient_seed(alpha: Qm31Value) -> [u8; 32] {
    let encoded: Vec<u8> = alpha
        .iter()
        .flat_map(|coordinate| coordinate.to_le_bytes())
        .collect();
    sha256(&[POOL_AIR_COEFFICIENT_SEED_DOMAIN, &encoded])
}

fn pool_air_challenge_digest(coefficient_seed: [u8; 32], family: u8, index: usize) -> [u8; 32] {
    sha256(&[&coefficient_seed, &[family], &(index as u32).to_be_bytes()])
}

fn pool_air_challenge_coordinate(digest: &[u8; 32], coordinate: usize) -> u32 {
    let mut bytes: [u8; 4] = digest[coordinate * 4..coordinate * 4 + 4]
        .try_into()
        .unwrap();
    bytes[3] &= 0x7f;
    (u32::from_le_bytes(bytes) as u64 % M31) as u32
}

fn pool_air_partial_challenges(coefficient_seed: [u8; 32]) -> [[u32; POOL_AIR_HORNER_LANES]; 8] {
    std::array::from_fn(|partial| {
        let digests = [
            pool_air_challenge_digest(coefficient_seed, 0, partial * 2),
            pool_air_challenge_digest(coefficient_seed, 0, partial * 2 + 1),
        ];
        std::array::from_fn(|lane| pool_air_challenge_coordinate(&digests[lane / 4], lane % 4))
    })
}

fn pool_air_compression_challenges(
    coefficient_seed: [u8; 32],
) -> [Qm31Value; POOL_AIR_HORNER_LANES] {
    std::array::from_fn(|lane| {
        let digest = pool_air_challenge_digest(coefficient_seed, 1, lane);
        std::array::from_fn(|coordinate| pool_air_challenge_coordinate(&digest, coordinate))
    })
}

fn pool_air_horner_partials(
    residuals: &[u32],
    partial_challenges: &[[u32; POOL_AIR_HORNER_LANES]; 8],
    ranges: &[(usize, usize); 8],
) -> [[u32; POOL_AIR_HORNER_LANES]; 8] {
    std::array::from_fn(|partial| {
        let (start, end) = ranges[partial];
        let mut accumulators = [0u32; POOL_AIR_HORNER_LANES];
        for output in start..end {
            for lane in 0..POOL_AIR_HORNER_LANES {
                accumulators[lane] = add_m31_fast(
                    mul_m31_fast(accumulators[lane], partial_challenges[partial][lane]),
                    residuals[output],
                );
            }
        }
        accumulators
    })
}

fn pool_air_compress_partials(
    partials: &[[u32; POOL_AIR_HORNER_LANES]; 8],
    compression_challenges: &[Qm31Value; POOL_AIR_HORNER_LANES],
) -> Qm31Value {
    let mut composition = SecureField::from_u32_unchecked(0, 0, 0, 0);
    for lane in 0..POOL_AIR_HORNER_LANES {
        let lane_sum = partials
            .iter()
            .fold(0u32, |sum, partial| add_m31_fast(sum, partial[lane]));
        composition +=
            qm31_to_secure(compression_challenges[lane]) * BaseField::from_u32_unchecked(lane_sum);
    }
    secure_to_qm31(composition)
}

#[derive(Clone, Debug)]
pub struct SuccessorProverBundle {
    pub trace_rows: usize,
    pub transcript_initial: Vec<u8>,
    pub program_bytes: Vec<u8>,
    pub program: PoolAirProgram,
    pub public_inputs: Vec<u32>,
    pub sha: Vec<Vec<u32>>,
    pub sha_aux: Vec<Vec<u32>>,
    pub bus: Vec<Vec<u32>>,
    pub preprocessed: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalPublicCell {
    pub row: usize,
    pub column: usize,
    pub value: u32,
}

#[derive(Clone, Debug)]
pub struct VerticalSuccessorProverBundle {
    pub trace_rows: usize,
    pub transcript_initial: Vec<u8>,
    pub program_bytes: Vec<u8>,
    pub program: PoolAirProgram,
    pub base_public_inputs: Vec<u32>,
    pub public_cells: Vec<VerticalPublicCell>,
    pub sha: Vec<Vec<u32>>,
    pub boundary: Vec<Vec<u32>>,
    pub preprocessed: Vec<Vec<u32>>,
}

struct BundleCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BundleCursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("bundle offset")?;
        if end > self.bytes.len() {
            return Err("truncated successor prover bundle".into());
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16_be(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32_be(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
}

pub fn pool_air_program_widths(program: &PoolAirProgram) -> [usize; 4] {
    let mut widths = [0usize; 4];
    for node in &program.nodes {
        if let PoolAirNode::Input { oracle, column, .. } = *node {
            widths[oracle as usize] = widths[oracle as usize].max(column as usize + 1);
        }
    }
    widths
}

pub fn decode_successor_prover_bundle(bytes: &[u8]) -> Result<SuccessorProverBundle, String> {
    let mut cursor = BundleCursor { bytes, offset: 0 };
    if cursor.take(4)? != b"SKPB" || cursor.u8()? != 2 {
        return Err("successor prover bundle codec".into());
    }
    let trace_rows = cursor.u32_be()? as usize;
    if trace_rows < 2 || !trace_rows.is_power_of_two() || trace_rows > 1 << 20 {
        return Err("successor bundle trace rows".into());
    }
    let initial_len = cursor.u32_be()? as usize;
    let transcript_initial = cursor.take(initial_len)?.to_vec();
    if transcript_initial.is_empty() || transcript_initial.len() > 1 << 20 {
        return Err("successor transcript initial".into());
    }
    let program_len = cursor.u32_be()? as usize;
    let program_bytes = cursor.take(program_len)?.to_vec();
    let program = decode_pool_air_program(&program_bytes)?;
    let public_input_count = cursor.u16_be()? as usize;
    if public_input_count != program.public_input_count {
        return Err("successor bundle public input count".into());
    }
    let mut public_inputs = Vec::with_capacity(public_input_count);
    for chunk in cursor.take(public_input_count * 4)?.chunks_exact(4) {
        let value = u32::from_le_bytes(chunk.try_into().unwrap());
        if value as u64 >= M31 {
            return Err("successor bundle public input".into());
        }
        public_inputs.push(value);
    }
    let widths = pool_air_program_widths(&program);
    let mut matrices = Vec::with_capacity(4);
    for expected_columns in widths {
        let column_count = cursor.u16_be()? as usize;
        if column_count != expected_columns {
            return Err("successor bundle column count".into());
        }
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let mut column = Vec::with_capacity(trace_rows);
            for chunk in cursor.take(trace_rows * 4)?.chunks_exact(4) {
                let value = u32::from_le_bytes(chunk.try_into().unwrap());
                if value as u64 >= M31 {
                    return Err("successor bundle field element".into());
                }
                column.push(value);
            }
            columns.push(column);
        }
        matrices.push(columns);
    }
    if cursor.offset != bytes.len() {
        return Err("trailing successor prover bundle bytes".into());
    }
    let [sha, sha_aux, bus, preprocessed]: [Vec<Vec<u32>>; 4] = matrices.try_into().unwrap();
    Ok(SuccessorProverBundle {
        trace_rows,
        transcript_initial,
        program_bytes,
        program,
        public_inputs,
        sha,
        sha_aux,
        bus,
        preprocessed,
    })
}

pub fn decode_vertical_successor_prover_bundle(
    bytes: &[u8],
) -> Result<VerticalSuccessorProverBundle, String> {
    let mut cursor = BundleCursor { bytes, offset: 0 };
    if cursor.take(4)? != b"SKPB" || cursor.u8()? != 3 {
        return Err("vertical successor prover bundle codec".into());
    }
    let trace_rows = cursor.u32_be()? as usize;
    if trace_rows != 1 << 18 {
        return Err("vertical successor trace rows".into());
    }
    let initial_len = cursor.u32_be()? as usize;
    let transcript_initial = cursor.take(initial_len)?.to_vec();
    if transcript_initial.is_empty() || transcript_initial.len() > 1 << 20 {
        return Err("vertical successor transcript initial".into());
    }
    let program_len = cursor.u32_be()? as usize;
    let program_bytes = cursor.take(program_len)?.to_vec();
    let program = decode_pool_air_program(&program_bytes)?;
    let base_public_count = cursor.u16_be()? as usize;
    if base_public_count + 15 != program.public_input_count {
        return Err("vertical successor public input count".into());
    }
    let mut base_public_inputs = Vec::with_capacity(base_public_count);
    for chunk in cursor.take(base_public_count * 4)?.chunks_exact(4) {
        let value = u32::from_le_bytes(chunk.try_into().unwrap());
        if value as u64 >= M31 {
            return Err("vertical successor public input".into());
        }
        base_public_inputs.push(value);
    }
    let public_cell_count = cursor.u16_be()? as usize;
    if public_cell_count == 0 || public_cell_count > 1024 {
        return Err("vertical successor public cells".into());
    }
    let mut public_cells = Vec::with_capacity(public_cell_count);
    for _ in 0..public_cell_count {
        let row = cursor.u32_be()? as usize;
        let column = cursor.u8()? as usize;
        let value = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap());
        if row >= trace_rows || column >= 3 || value as u64 >= M31 {
            return Err("vertical successor public cell".into());
        }
        public_cells.push(VerticalPublicCell { row, column, value });
    }
    let unique_rows: std::collections::HashSet<usize> =
        public_cells.iter().map(|cell| cell.row).collect();
    if unique_rows.len() != public_cells.len()
        || public_cells.iter().any(|cell| cell.row == trace_rows - 1)
    {
        return Err("vertical successor public cell order".into());
    }
    let widths = pool_air_program_widths(&program);
    if widths[2] != 5 {
        return Err("vertical successor interaction width".into());
    }
    let expected_widths = [widths[0], widths[1], widths[3]];
    let mut matrices = Vec::with_capacity(3);
    for expected_columns in expected_widths {
        let column_count = cursor.u16_be()? as usize;
        if column_count != expected_columns || column_count == 0 {
            return Err("vertical successor column count".into());
        }
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let mut column = Vec::with_capacity(trace_rows);
            for chunk in cursor.take(trace_rows * 4)?.chunks_exact(4) {
                let value = u32::from_le_bytes(chunk.try_into().unwrap());
                if value as u64 >= M31 {
                    return Err("vertical successor field element".into());
                }
                column.push(value);
            }
            columns.push(column);
        }
        matrices.push(columns);
    }
    if cursor.offset != bytes.len() {
        return Err("trailing vertical successor bundle bytes".into());
    }
    let [sha, boundary, preprocessed]: [Vec<Vec<u32>>; 3] = matrices.try_into().unwrap();
    Ok(VerticalSuccessorProverBundle {
        trace_rows,
        transcript_initial,
        program_bytes,
        program,
        base_public_inputs,
        public_cells,
        sha,
        boundary,
        preprocessed,
    })
}

pub struct PoolAirOracleLdes<'a> {
    pub sha: &'a [Vec<u32>],
    pub sha_aux: &'a [Vec<u32>],
    pub bus: &'a [Vec<u32>],
    pub preprocessed: &'a [Vec<u32>],
}

impl PoolAirOracleLdes<'_> {
    fn columns(&self, oracle: u8) -> &[Vec<u32>] {
        match oracle {
            0 => self.sha,
            1 => self.sha_aux,
            2 => self.bus,
            3 => self.preprocessed,
            _ => unreachable!(),
        }
    }

    fn rows(&self) -> usize {
        self.sha[0].len()
    }

    fn validate(&self, program: &PoolAirProgram) {
        let rows = self.rows();
        assert!(rows.is_power_of_two());
        for columns in [self.sha, self.sha_aux, self.bus, self.preprocessed] {
            assert!(!columns.is_empty());
            assert!(columns.iter().all(|column| column.len() == rows));
            assert!(columns.iter().flatten().all(|value| (*value as u64) < M31));
        }
        for node in &program.nodes {
            if let PoolAirNode::Input { oracle, column, .. } = *node {
                assert!((column as usize) < self.columns(oracle).len());
            }
        }
    }
}

#[inline]
fn add_m31_fast(a: u32, b: u32) -> u32 {
    let sum = a as u64 + b as u64;
    if sum >= M31 {
        (sum - M31) as u32
    } else {
        sum as u32
    }
}

#[inline]
fn sub_m31_fast(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        (a as u64 + M31 - b as u64) as u32
    }
}

#[inline]
fn mul_m31_fast(a: u32, b: u32) -> u32 {
    let product = a as u64 * b as u64;
    let first = (product & M31) + (product >> 31);
    let second = (first & M31) + (first >> 31);
    if second >= M31 {
        (second - M31) as u32
    } else {
        second as u32
    }
}

/// Evaluate the shared AIR IR over complete bit-reversed successor LDEs and
/// fingerprint each semantic partial in six M31 Horner lanes, then compress
/// the lane sums once into QM31.
pub fn pool_composition_lde_bit_reversed(
    program: &PoolAirProgram,
    public_inputs: &[u32],
    oracles: PoolAirOracleLdes<'_>,
    relation_trace_log: u32,
    coefficient_seed: [u8; 32],
) -> Vec<Qm31Value> {
    oracles.validate(program);
    assert_eq!(public_inputs.len(), program.public_input_count);
    let rows = oracles.rows();
    let eval_log = rows.ilog2();
    assert!(relation_trace_log < eval_log);
    let ranges = pool_air_partial_ranges(program).expect("AIR composition ranges");
    let partial_challenges = pool_air_partial_challenges(coefficient_seed);
    let compression_challenges = pool_air_compression_challenges(coefficient_seed);

    (0..rows)
        .into_par_iter()
        .map_init(
            || Vec::<u32>::with_capacity(program.nodes.len()),
            |values, row| {
                values.clear();
                for node in &program.nodes {
                    let value = match *node {
                        PoolAirNode::Constant(value) => value,
                        PoolAirNode::Public(index) => public_inputs[index as usize],
                        PoolAirNode::Input {
                            oracle,
                            column,
                            offset,
                        } => {
                            let location = if offset == 0 {
                                row
                            } else {
                                stwo::core::utils::offset_bit_reversed_circle_domain_index(
                                    row,
                                    relation_trace_log,
                                    eval_log,
                                    offset as isize,
                                )
                            };
                            oracles.columns(oracle)[column as usize][location]
                        }
                        PoolAirNode::Add { left, right } => {
                            add_m31_fast(values[left as usize], values[right as usize])
                        }
                        PoolAirNode::Sub { left, right } => {
                            sub_m31_fast(values[left as usize], values[right as usize])
                        }
                        PoolAirNode::Mul { left, right } => {
                            mul_m31_fast(values[left as usize], values[right as usize])
                        }
                    };
                    values.push(value);
                }
                let residuals: Vec<u32> = program
                    .outputs
                    .iter()
                    .map(|(node, _)| values[*node as usize])
                    .collect();
                let partials = pool_air_horner_partials(&residuals, &partial_challenges, &ranges);
                pool_air_compress_partials(&partials, &compression_challenges)
            },
        )
        .collect()
}

const VERTICAL_AIR_HORNER_LANES: usize = 5;

fn vertical_air_challenge(
    coefficient_seed: [u8; 32],
    family: u8,
    lane: usize,
    coordinate: u8,
) -> u32 {
    vertical_digest_to_m31(&sha256(&[
        &coefficient_seed,
        &[family],
        &(lane as u32).to_le_bytes(),
        &[coordinate],
    ]))
}

fn vertical_air_horner_challenges(coefficient_seed: [u8; 32]) -> [u32; VERTICAL_AIR_HORNER_LANES] {
    std::array::from_fn(|lane| vertical_air_challenge(coefficient_seed, 4, lane, 0))
}

fn vertical_air_compression_challenges(
    coefficient_seed: [u8; 32],
) -> [Qm31Value; VERTICAL_AIR_HORNER_LANES] {
    std::array::from_fn(|lane| {
        std::array::from_fn(|coordinate| {
            vertical_air_challenge(coefficient_seed, 5, lane, coordinate as u8)
        })
    })
}

fn vertical_air_horner(
    residuals: &[u32],
    challenges: &[u32; VERTICAL_AIR_HORNER_LANES],
) -> [u32; VERTICAL_AIR_HORNER_LANES] {
    let mut accumulators = [0u32; VERTICAL_AIR_HORNER_LANES];
    for residual in residuals {
        for lane in 0..VERTICAL_AIR_HORNER_LANES {
            accumulators[lane] = add_m31_fast(
                mul_m31_fast(accumulators[lane], challenges[lane]),
                *residual,
            );
        }
    }
    accumulators
}

fn vertical_air_compress(
    values: &[u32; VERTICAL_AIR_HORNER_LANES],
    challenges: &[Qm31Value; VERTICAL_AIR_HORNER_LANES],
) -> Qm31Value {
    let mut composition = SecureField::from_u32_unchecked(0, 0, 0, 0);
    for lane in 0..VERTICAL_AIR_HORNER_LANES {
        composition +=
            qm31_to_secure(challenges[lane]) * BaseField::from_u32_unchecked(values[lane]);
    }
    secure_to_qm31(composition)
}

fn evaluate_air_residuals_at_lde_row(
    program: &PoolAirProgram,
    public_inputs: &[u32],
    oracles: &PoolAirOracleLdes<'_>,
    relation_trace_log: u32,
    eval_log: u32,
    row: usize,
    values: &mut Vec<u32>,
) -> Vec<u32> {
    values.clear();
    for node in &program.nodes {
        let value = match *node {
            PoolAirNode::Constant(value) => value,
            PoolAirNode::Public(index) => public_inputs[index as usize],
            PoolAirNode::Input {
                oracle,
                column,
                offset,
            } => {
                let location = if offset == 0 {
                    row
                } else {
                    stwo::core::utils::offset_bit_reversed_circle_domain_index(
                        row,
                        relation_trace_log,
                        eval_log,
                        offset as isize,
                    )
                };
                oracles.columns(oracle)[column as usize][location]
            }
            PoolAirNode::Add { left, right } => {
                add_m31_fast(values[left as usize], values[right as usize])
            }
            PoolAirNode::Sub { left, right } => {
                sub_m31_fast(values[left as usize], values[right as usize])
            }
            PoolAirNode::Mul { left, right } => {
                mul_m31_fast(values[left as usize], values[right as usize])
            }
        };
        values.push(value);
    }
    program
        .outputs
        .iter()
        .map(|(node, _)| values[*node as usize])
        .collect()
}

fn vertical_composition_lde_bit_reversed(
    program: &PoolAirProgram,
    public_inputs: &[u32],
    oracles: PoolAirOracleLdes<'_>,
    relation_trace_log: u32,
    coefficient_seed: [u8; 32],
) -> Vec<Qm31Value> {
    oracles.validate(program);
    assert_eq!(public_inputs.len(), program.public_input_count);
    let rows = oracles.rows();
    let eval_log = rows.ilog2();
    let horner_challenges = vertical_air_horner_challenges(coefficient_seed);
    let compression_challenges = vertical_air_compression_challenges(coefficient_seed);
    (0..rows)
        .into_par_iter()
        .map_init(
            || Vec::<u32>::with_capacity(program.nodes.len()),
            |values, row| {
                let residuals = evaluate_air_residuals_at_lde_row(
                    program,
                    public_inputs,
                    &oracles,
                    relation_trace_log,
                    eval_log,
                    row,
                    values,
                );
                vertical_air_compress(
                    &vertical_air_horner(&residuals, &horner_challenges),
                    &compression_challenges,
                )
            },
        )
        .collect()
}

const SUCCESSOR_TRANSCRIPT_DOMAIN: &[u8] = b"ShieldKit/SuccessorTranscript/v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorTranscript {
    digest: [u8; 32],
}

impl SuccessorTranscript {
    pub fn new(initial: &[u8]) -> Self {
        assert!(!initial.is_empty() && initial.len() <= u16::MAX as usize);
        let initial_len = (initial.len() as u32).to_le_bytes();
        Self {
            digest: sha256(&[SUCCESSOR_TRANSCRIPT_DOMAIN, &initial_len, initial]),
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        assert!(!label.is_empty() && label.len() <= 96 && data.len() <= u32::MAX as usize);
        let label_len = [label.len() as u8];
        let data_len = (data.len() as u32).to_le_bytes();
        self.digest = sha256(&[
            &[0],
            &self.digest,
            &label_len,
            label.as_bytes(),
            &data_len,
            data,
        ]);
    }

    pub fn challenge_qm31(&mut self, label: &str) -> Qm31Value {
        assert!(!label.is_empty() && label.len() <= 96);
        let label_len = [label.len() as u8];
        let challenge = std::array::from_fn(|coordinate| {
            vertical_digest_to_m31(&sha256(&[
                &[1],
                &self.digest,
                &label_len,
                label.as_bytes(),
                &[coordinate as u8],
            ]))
        });
        let encoded: Vec<u8> = challenge
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        self.digest = sha256(&[&[2], &self.digest, &label_len, label.as_bytes(), &encoded]);
        challenge
    }

    fn grind_accepts(&self, bits: u8, nonce: u32) -> bool {
        if bits > 32 {
            return false;
        }
        let candidate = sha256(&[&[3], &self.digest, &[bits], &nonce.to_le_bytes()]);
        let mut zeros = 0u32;
        for byte in candidate {
            if byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros >= bits as u32
    }

    pub fn grind(&mut self, bits: u8) -> u32 {
        assert!(bits <= 32);
        for nonce in 0u32..=u32::MAX {
            if self.grind_accepts(bits, nonce) {
                let mut data = Vec::with_capacity(5);
                data.push(bits);
                data.extend_from_slice(&nonce.to_le_bytes());
                self.absorb("pow", &data);
                return nonce;
            }
        }
        panic!("grind exhausted")
    }

    pub fn grind_for_queries(&mut self, bits: u8, row_count: usize, count: usize) -> u32 {
        self.grind_for_queries_matching(bits, row_count, count, 1, |_| true)
    }

    pub fn grind_for_queries_with_orbit_log(
        &mut self,
        bits: u8,
        row_count: usize,
        count: usize,
        orbit_log: u32,
    ) -> u32 {
        self.grind_for_queries_matching(bits, row_count, count, orbit_log, |_| true)
    }

    fn grind_for_queries_matching<F>(
        &mut self,
        bits: u8,
        row_count: usize,
        count: usize,
        orbit_log: u32,
        accept_schedule: F,
    ) -> u32
    where
        F: Fn(&[usize]) -> bool,
    {
        for nonce in 0u32..=u32::MAX {
            if !self.grind_accepts(bits, nonce) {
                continue;
            }
            let mut candidate = self.clone();
            let mut data = Vec::with_capacity(5);
            data.push(bits);
            data.extend_from_slice(&nonce.to_le_bytes());
            candidate.absorb("pow", &data);
            if let Some(indices) =
                candidate.try_query_indices_with_orbit_log(row_count, count, orbit_log)
            {
                if accept_schedule(&indices) {
                    *self = candidate;
                    return nonce;
                }
            }
        }
        panic!("successor conditioned grind exhausted")
    }

    pub fn accept_grind(&mut self, bits: u8, nonce: u32) -> bool {
        if !self.grind_accepts(bits, nonce) {
            return false;
        }
        let mut data = Vec::with_capacity(5);
        data.push(bits);
        data.extend_from_slice(&nonce.to_le_bytes());
        self.absorb("pow", &data);
        true
    }

    fn try_query_indices(&self, row_count: usize, count: usize) -> Option<Vec<usize>> {
        self.try_query_indices_with_orbit_log(row_count, count, 1)
    }

    fn try_query_indices_with_orbit_log(
        &self,
        row_count: usize,
        count: usize,
        orbit_log: u32,
    ) -> Option<Vec<usize>> {
        use std::collections::HashSet;

        assert!(row_count >= 2 && row_count.is_power_of_two() && row_count <= u32::MAX as usize);
        assert!(orbit_log >= 1 && orbit_log < row_count.ilog2());
        assert!(count >= 1 && count <= row_count / (1usize << orbit_log));
        let mut indices = Vec::with_capacity(count);
        let mut orbits = HashSet::with_capacity(count);
        for counter in 0u32..=u32::MAX {
            let block = sha256(&[&[4], &self.digest, &counter.to_le_bytes()]);
            let index =
                (u32::from_le_bytes(block[..4].try_into().unwrap()) as usize) & (row_count - 1);
            if !orbits.insert(index >> orbit_log) {
                if orbit_log == 1 {
                    return None;
                }
                continue;
            }
            indices.push(index);
            if indices.len() == count {
                return Some(indices);
            }
        }
        None
    }

    pub fn query_indices(&self, row_count: usize, count: usize) -> Vec<usize> {
        self.try_query_indices(row_count, count)
            .expect("successor query orbit collision")
    }

    pub fn query_indices_with_orbit_log(
        &self,
        row_count: usize,
        count: usize,
        orbit_log: u32,
    ) -> Vec<usize> {
        self.try_query_indices_with_orbit_log(row_count, count, orbit_log)
            .expect("successor query orbit collision")
    }
}

const VERTICAL_TRANSCRIPT_DOMAIN: &[u8] = b"ShieldKit/VerticalTranscript/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalTranscript {
    digest: [u8; 32],
}

fn vertical_digest_to_m31(digest: &[u8; 32]) -> u32 {
    digest
        .iter()
        .rev()
        .fold(0u64, |value, byte| (value * 256 + *byte as u64) % M31) as u32
}

impl VerticalTranscript {
    pub fn new(initial: &[u8]) -> Self {
        assert!(!initial.is_empty() && initial.len() <= u16::MAX as usize);
        Self {
            digest: sha256(&[
                VERTICAL_TRANSCRIPT_DOMAIN,
                &(initial.len() as u32).to_le_bytes(),
                initial,
            ]),
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        assert!(!label.is_empty() && label.len() <= 96 && data.len() <= u32::MAX as usize);
        self.digest = sha256(&[
            &[0],
            &self.digest,
            &[label.len() as u8],
            label.as_bytes(),
            &(data.len() as u32).to_le_bytes(),
            data,
        ]);
    }

    pub fn challenge_qm31(&mut self, label: &str) -> Qm31Value {
        assert!(!label.is_empty() && label.len() <= 96);
        let challenge = std::array::from_fn(|coordinate| {
            vertical_digest_to_m31(&sha256(&[
                &[1],
                &self.digest,
                &[label.len() as u8],
                label.as_bytes(),
                &[coordinate as u8],
            ]))
        });
        self.digest = sha256(&[
            &[2],
            &self.digest,
            &[label.len() as u8],
            label.as_bytes(),
            &encode_qm31_values(&[challenge]),
        ]);
        challenge
    }

    fn grind_accepts(&self, bits: u8, nonce: u32) -> bool {
        if bits > 32 {
            return false;
        }
        let candidate = sha256(&[&[3], &self.digest, &[bits], &nonce.to_le_bytes()]);
        let mut zeros = 0u32;
        for byte in candidate {
            if byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros >= bits as u32
    }

    pub fn grind(&mut self, bits: u8) -> u32 {
        for nonce in 0u32..=u32::MAX {
            if self.grind_accepts(bits, nonce) {
                let mut data = Vec::with_capacity(5);
                data.push(bits);
                data.extend_from_slice(&nonce.to_le_bytes());
                self.absorb("pow", &data);
                return nonce;
            }
        }
        panic!("vertical grind exhausted")
    }

    pub fn grind_for_queries(&mut self, bits: u8, row_count: usize, count: usize) -> u32 {
        for nonce in 0u32..=u32::MAX {
            if !self.grind_accepts(bits, nonce) {
                continue;
            }
            let mut candidate = self.clone();
            let mut data = Vec::with_capacity(5);
            data.push(bits);
            data.extend_from_slice(&nonce.to_le_bytes());
            candidate.absorb("pow", &data);
            if candidate.try_query_indices(row_count, count).is_some() {
                *self = candidate;
                return nonce;
            }
        }
        panic!("vertical conditioned grind exhausted")
    }

    pub fn accept_grind(&mut self, bits: u8, nonce: u32) -> bool {
        if !self.grind_accepts(bits, nonce) {
            return false;
        }
        let mut data = Vec::with_capacity(5);
        data.push(bits);
        data.extend_from_slice(&nonce.to_le_bytes());
        self.absorb("pow", &data);
        true
    }

    fn try_query_indices(&self, row_count: usize, count: usize) -> Option<Vec<usize>> {
        use std::collections::HashSet;
        assert!(row_count >= 2 && row_count.is_power_of_two() && row_count <= u32::MAX as usize);
        assert!(count >= 1 && count <= row_count / 2);
        let mut indices = Vec::with_capacity(count);
        let mut orbits = HashSet::with_capacity(count);
        for counter in 0u32..count as u32 {
            let block = sha256(&[&[4], &self.digest, &counter.to_le_bytes()]);
            let index =
                (u32::from_le_bytes(block[..4].try_into().unwrap()) as usize) & (row_count - 1);
            if !orbits.insert(index >> 1) {
                return None;
            }
            indices.push(index);
        }
        Some(indices)
    }

    pub fn query_indices(&self, row_count: usize, count: usize) -> Vec<usize> {
        self.try_query_indices(row_count, count)
            .expect("vertical query orbit collision")
    }
}

pub trait FriProverTranscript {
    fn fri_absorb(&mut self, label: &str, data: &[u8]);
    fn fri_challenge_qm31(&mut self, label: &str) -> Qm31Value;
    fn fri_grind(
        &mut self,
        bits: u8,
        row_count: usize,
        query_count: usize,
        query_orbit_log: u32,
    ) -> u32;
    fn fri_query_indices(&self, row_count: usize, count: usize, query_orbit_log: u32)
        -> Vec<usize>;
}

impl FriProverTranscript for SuccessorTranscript {
    fn fri_absorb(&mut self, label: &str, data: &[u8]) {
        self.absorb(label, data);
    }
    fn fri_challenge_qm31(&mut self, label: &str) -> Qm31Value {
        self.challenge_qm31(label)
    }
    fn fri_grind(
        &mut self,
        bits: u8,
        row_count: usize,
        query_count: usize,
        query_orbit_log: u32,
    ) -> u32 {
        self.grind_for_queries_with_orbit_log(bits, row_count, query_count, query_orbit_log)
    }
    fn fri_query_indices(
        &self,
        row_count: usize,
        count: usize,
        query_orbit_log: u32,
    ) -> Vec<usize> {
        self.query_indices_with_orbit_log(row_count, count, query_orbit_log)
    }
}

impl FriProverTranscript for VerticalTranscript {
    fn fri_absorb(&mut self, label: &str, data: &[u8]) {
        self.absorb(label, data);
    }
    fn fri_challenge_qm31(&mut self, label: &str) -> Qm31Value {
        self.challenge_qm31(label)
    }
    fn fri_grind(
        &mut self,
        bits: u8,
        row_count: usize,
        query_count: usize,
        query_orbit_log: u32,
    ) -> u32 {
        assert_eq!(query_orbit_log, 1);
        self.grind_for_queries(bits, row_count, query_count)
    }
    fn fri_query_indices(
        &self,
        row_count: usize,
        count: usize,
        query_orbit_log: u32,
    ) -> Vec<usize> {
        assert_eq!(query_orbit_log, 1);
        self.query_indices(row_count, count)
    }
}

fn qm31_to_secure(value: Qm31Value) -> SecureField {
    SecureField::from_m31_array(value.map(BaseField::from_u32_unchecked))
}

fn secure_to_qm31(value: SecureField) -> Qm31Value {
    value.to_m31_array().map(|coordinate| coordinate.0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorFriLayers {
    /// Each committed layer in Stwo's canonical bit-reversed order.
    pub layers: Vec<Vec<Qm31Value>>,
    /// Ordered coefficients of the final line polynomial, with the known-zero
    /// high-degree tail removed.
    pub final_coefficients: Vec<Qm31Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorFriConfig {
    pub log_blowup: u32,
    pub final_log_degree: u32,
    /** Number of binary folds represented by each committed layer (1 or 2). */
    pub fold_log: u32,
    /** Reject schedules that collide after this many binary folds. */
    pub query_orbit_log: u32,
    pub queries: usize,
    pub grind_bits: u8,
}

impl SuccessorFriConfig {
    pub const PRODUCTION: Self = Self {
        log_blowup: 5,
        final_log_degree: 3,
        fold_log: 1,
        query_orbit_log: 1,
        queries: 21,
        grind_bits: 20,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorFriLayerProof {
    pub root: [u8; 32],
    pub values: Vec<Qm31Value>,
    pub merkle: CanonicalMerkleMultiProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorFriProof {
    pub layers: Vec<SuccessorFriLayerProof>,
    pub final_coefficients: Vec<Qm31Value>,
    pub grind_nonce: u32,
}

fn encode_qm31_values(values: &[Qm31Value]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.iter().flat_map(|coordinate| coordinate.to_le_bytes()))
        .collect()
}

fn fri_fold_counts(
    input_log: u32,
    final_log_domain: u32,
    fold_log: u32,
) -> Result<Vec<u32>, &'static str> {
    if final_log_domain >= input_log || !(1..=2).contains(&fold_log) {
        return Err("FRI config");
    }
    let mut remaining = input_log - final_log_domain;
    let mut counts = Vec::new();
    while remaining > 0 {
        let count = remaining.min(fold_log);
        counts.push(count);
        remaining -= count;
    }
    Ok(counts)
}

fn fri_opening_indices(mut queries: Vec<usize>, fold_counts: &[u32]) -> Vec<Vec<usize>> {
    let mut openings = Vec::with_capacity(fold_counts.len());
    for folds in fold_counts {
        let arity = 1usize << *folds;
        let mut indices: Vec<usize> = queries
            .iter()
            .flat_map(|index| {
                let base = index & !(arity - 1);
                base..base + arity
            })
            .collect();
        indices.sort_unstable();
        indices.dedup();
        openings.push(indices);
        queries = queries.into_iter().map(|index| index >> *folds).collect();
        queries.sort_unstable();
        queries.dedup();
    }
    openings
}

#[derive(Clone, Debug)]
enum SuccessorFriMerkleTree {
    Binary(CanonicalMerkleTree),
    Quaternary(CanonicalMerkleTree4),
}

impl SuccessorFriMerkleTree {
    fn root(&self) -> [u8; 32] {
        match self {
            Self::Binary(tree) => tree.root(),
            Self::Quaternary(tree) => tree.root(),
        }
    }

    fn multiproof(&self, indices: &[usize]) -> CanonicalMerkleMultiProof {
        match self {
            Self::Binary(tree) => tree.multiproof(indices),
            Self::Quaternary(tree) => tree.multiproof(indices),
        }
    }
}

fn commit_fri_layer<T: FriProverTranscript>(
    round: usize,
    values: Vec<Qm31Value>,
    transcript: &mut T,
    fold_log: u32,
) -> (Vec<Qm31Value>, SuccessorFriMerkleTree, Qm31Value) {
    let tree_label = format!("fri:layer:{round}");
    let tree = if fold_log == 2 {
        SuccessorFriMerkleTree::Quaternary(CanonicalMerkleTree4::from_qm31(&tree_label, &values))
    } else {
        SuccessorFriMerkleTree::Binary(CanonicalMerkleTree::from_qm31(&tree_label, &values))
    };
    let root = tree.root();
    transcript.fri_absorb(&format!("fri-root:{round}"), &root);
    let alpha = transcript.fri_challenge_qm31(&format!("fri-alpha:{round}"));
    (values, tree, alpha)
}

/// Commit, fold, grind, and multiproof one independently masked QM31 batch.
pub fn prove_successor_fri<T: FriProverTranscript>(
    natural_values: &[Qm31Value],
    transcript: &mut T,
    config: SuccessorFriConfig,
) -> Result<SuccessorFriProof, &'static str> {
    if !natural_values.len().is_power_of_two() || natural_values.len() < 4 {
        return Err("FRI input size");
    }
    let input_log = natural_values.len().ilog2();
    let final_log_domain = config
        .final_log_degree
        .checked_add(config.log_blowup)
        .ok_or("FRI final domain")?;
    if final_log_domain >= input_log
        || !(1..=2).contains(&config.fold_log)
        || config.query_orbit_log == 0
        || config.query_orbit_log >= input_log
        || (config.fold_log == 2 && input_log % 2 != 0)
        || config.queries == 0
        || config.queries > natural_values.len() / 2
    {
        return Err("FRI config");
    }

    let domain = CanonicCoset::new(input_log).circle_domain();
    let natural: CpuCircleEvaluation<SecureField, NaturalOrder> = CpuCircleEvaluation::new(
        domain,
        natural_values.iter().copied().map(qm31_to_secure).collect(),
    );
    let generic_circle = natural.bit_reverse();
    let circle: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::new(domain, generic_circle.values.into_iter().collect());

    let mut committed_values = Vec::new();
    let mut trees = Vec::new();
    let circle_values: Vec<Qm31Value> = circle
        .values
        .to_vec()
        .into_iter()
        .map(secure_to_qm31)
        .collect();
    let fold_counts = fri_fold_counts(input_log, final_log_domain, config.fold_log)?;
    let (values, tree, alpha) = commit_fri_layer(0, circle_values, transcript, config.fold_log);
    committed_values.push(values);
    trees.push(tree);
    let alpha_secure = qm31_to_secure(alpha);
    let mut line = fold_circle_into_line_cpu(&circle, alpha_secure);
    if fold_counts[0] == 2 {
        line = fold_line_cpu(&line, alpha_secure * alpha_secure);
    }
    for round in 1..fold_counts.len() {
        let line_values: Vec<Qm31Value> = line
            .values
            .to_vec()
            .into_iter()
            .map(secure_to_qm31)
            .collect();
        let (values, tree, alpha) =
            commit_fri_layer(round, line_values, transcript, config.fold_log);
        committed_values.push(values);
        trees.push(tree);
        let alpha_secure = qm31_to_secure(alpha);
        line = fold_line_cpu(&line, alpha_secure);
        if fold_counts[round] == 2 {
            line = fold_line_cpu(&line, alpha_secure * alpha_secure);
        }
    }
    if line.len().ilog2() != final_log_domain {
        return Err("FRI final domain");
    }
    let coefficients = line.interpolate().into_ordered_coefficients();
    let degree_bound = 1usize << config.final_log_degree;
    if coefficients[degree_bound..]
        .iter()
        .any(|value| secure_to_qm31(*value) != [0; 4])
    {
        return Err("FRI final degree");
    }
    let final_coefficients: Vec<Qm31Value> = coefficients[..degree_bound]
        .iter()
        .copied()
        .map(secure_to_qm31)
        .collect();
    transcript.fri_absorb("fri-final", &encode_qm31_values(&final_coefficients));
    let grind_nonce = transcript.fri_grind(
        config.grind_bits,
        natural_values.len(),
        config.queries,
        config.query_orbit_log,
    );
    let queries =
        transcript.fri_query_indices(natural_values.len(), config.queries, config.query_orbit_log);
    let opening_indices = fri_opening_indices(queries, &fold_counts);
    let layers = trees
        .into_iter()
        .zip(committed_values)
        .zip(opening_indices)
        .map(|((tree, values), indices)| {
            let merkle = tree.multiproof(&indices);
            let opened_values = indices.iter().map(|index| values[*index]).collect();
            SuccessorFriLayerProof {
                root: tree.root(),
                values: opened_values,
                merkle,
            }
        })
        .collect();
    Ok(SuccessorFriProof {
        layers,
        final_coefficients,
        grind_nonce,
    })
}

fn fold_opened_pair(
    left: Qm31Value,
    right: Qm31Value,
    inverse_twiddle: BaseField,
    alpha: Qm31Value,
) -> Qm31Value {
    let (mut f0, mut f1) = (qm31_to_secure(left), qm31_to_secure(right));
    ibutterfly(&mut f0, &mut f1, inverse_twiddle);
    secure_to_qm31(f0 + qm31_to_secure(alpha) * f1)
}

fn fri_inverse_twiddle(input_log: u32, completed_folds: u32, base: usize) -> BaseField {
    if completed_folds == 0 {
        CanonicCoset::new(input_log)
            .circle_domain()
            .at(bit_reverse_index(base, input_log))
            .y
            .inverse()
    } else {
        let line_log = input_log - completed_folds;
        LineDomain::new(Coset::half_odds(line_log))
            .at(bit_reverse_index(base, line_log))
            .inverse()
    }
}

pub fn verify_successor_fri(
    proof: &SuccessorFriProof,
    input_log: u32,
    transcript: &mut SuccessorTranscript,
    config: SuccessorFriConfig,
) -> Result<(), &'static str> {
    if proof
        .layers
        .iter()
        .flat_map(|layer| layer.values.iter())
        .chain(proof.final_coefficients.iter())
        .flatten()
        .any(|value| *value as u64 >= M31)
    {
        return Err("FRI field");
    }
    let final_log_domain = config
        .final_log_degree
        .checked_add(config.log_blowup)
        .ok_or("FRI final domain")?;
    if final_log_domain >= input_log
        || !(1..=2).contains(&config.fold_log)
        || config.query_orbit_log == 0
        || config.query_orbit_log >= input_log
        || (config.fold_log == 2 && input_log % 2 != 0)
    {
        return Err("FRI config");
    }
    let fold_counts = fri_fold_counts(input_log, final_log_domain, config.fold_log)?;
    if proof.layers.len() != fold_counts.len()
        || proof.final_coefficients.len() != 1usize << config.final_log_degree
    {
        return Err("FRI shape");
    }
    let mut alphas = Vec::with_capacity(fold_counts.len());
    for (round, layer) in proof.layers.iter().enumerate() {
        transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        alphas.push(transcript.challenge_qm31(&format!("fri-alpha:{round}")));
    }
    transcript.absorb("fri-final", &encode_qm31_values(&proof.final_coefficients));
    if !transcript.accept_grind(config.grind_bits, proof.grind_nonce) {
        return Err("FRI grind");
    }
    let row_count = 1usize << input_log;
    let original_queries =
        transcript.query_indices_with_orbit_log(row_count, config.queries, config.query_orbit_log);
    let expected_openings = fri_opening_indices(original_queries.clone(), &fold_counts);

    let mut query_positions = original_queries;
    let mut folded_values: Option<Vec<Qm31Value>> = None;
    let mut completed_folds = 0u32;
    for (round, layer) in proof.layers.iter().enumerate() {
        let folds = fold_counts[round];
        let arity = 1usize << folds;
        let layer_rows = row_count >> completed_folds;
        if layer.merkle.indices != expected_openings[round]
            || layer.values.len() != layer.merkle.indices.len()
        {
            return Err("FRI opening shape");
        }
        let rows: Vec<(usize, Qm31Value)> = layer
            .merkle
            .indices
            .iter()
            .copied()
            .zip(layer.values.iter().copied())
            .collect();
        let merkle_ok = if config.fold_log == 2 {
            verify_qm31_multiproof4(
                &format!("fri:layer:{round}"),
                &rows,
                &layer.merkle,
                layer_rows,
                layer.root,
            )
        } else {
            verify_qm31_multiproof(
                &format!("fri:layer:{round}"),
                &rows,
                &layer.merkle,
                layer_rows,
                layer.root,
            )
        };
        if !merkle_ok {
            return Err("FRI Merkle");
        }
        let opened: std::collections::BTreeMap<usize, Qm31Value> = rows.into_iter().collect();
        if let Some(expected) = &folded_values {
            for (position, value) in query_positions.iter().zip(expected) {
                if opened.get(position) != Some(value) {
                    return Err("FRI fold link");
                }
            }
        }
        let mut next_values = Vec::with_capacity(query_positions.len());
        for position in &query_positions {
            let base = position & !(arity - 1);
            let mut values = (base..base + arity)
                .map(|index| opened.get(&index).copied().ok_or("FRI opening"))
                .collect::<Result<Vec<_>, _>>()?;
            let alpha = qm31_to_secure(alphas[round]);
            for subfold in 0..folds {
                let challenge = if subfold == 0 {
                    alphas[round]
                } else {
                    secure_to_qm31(alpha * alpha)
                };
                values = values
                    .chunks_exact(2)
                    .enumerate()
                    .map(|(pair, values)| {
                        let pair_base = (base >> subfold) + pair * 2;
                        fold_opened_pair(
                            values[0],
                            values[1],
                            fri_inverse_twiddle(input_log, completed_folds + subfold, pair_base),
                            challenge,
                        )
                    })
                    .collect();
            }
            next_values.push(values[0]);
        }
        folded_values = Some(next_values);
        query_positions = query_positions
            .into_iter()
            .map(|position| position >> folds)
            .collect();
        completed_folds += folds;
    }

    let final_poly = LinePoly::from_ordered_coefficients(
        proof
            .final_coefficients
            .iter()
            .copied()
            .map(qm31_to_secure)
            .collect(),
    );
    let final_domain = LineDomain::new(Coset::half_odds(final_log_domain));
    for (position, value) in query_positions.iter().zip(folded_values.unwrap()) {
        let x = final_domain.at(bit_reverse_index(*position, final_log_domain));
        if final_poly.eval_at_point(x.into()) != qm31_to_secure(value) {
            return Err("FRI final evaluation");
        }
    }
    Ok(())
}

const SUCCESSOR_FRI_CODEC_MAGIC: &[u8; 4] = b"SKFR";
const SUCCESSOR_FRI_CODEC_VERSION: u8 = 1;

pub fn encode_successor_fri_proof(proof: &SuccessorFriProof) -> Vec<u8> {
    assert!(proof.layers.len() <= u8::MAX as usize);
    assert!(proof.final_coefficients.len() <= u16::MAX as usize);
    let mut out = Vec::new();
    out.extend_from_slice(SUCCESSOR_FRI_CODEC_MAGIC);
    out.push(SUCCESSOR_FRI_CODEC_VERSION);
    out.push(proof.layers.len() as u8);
    out.extend_from_slice(&proof.grind_nonce.to_be_bytes());
    out.extend_from_slice(&(proof.final_coefficients.len() as u16).to_be_bytes());
    out.extend_from_slice(&encode_qm31_values(&proof.final_coefficients));
    for layer in &proof.layers {
        assert_eq!(layer.values.len(), layer.merkle.indices.len());
        assert!(layer.values.len() <= u16::MAX as usize);
        assert!(layer.merkle.siblings.len() <= u16::MAX as usize);
        out.extend_from_slice(&layer.root);
        out.extend_from_slice(&(layer.values.len() as u16).to_be_bytes());
        for (index, value) in layer.merkle.indices.iter().zip(&layer.values) {
            out.extend_from_slice(&(*index as u32).to_be_bytes());
            for coordinate in value {
                out.extend_from_slice(&coordinate.to_le_bytes());
            }
        }
        out.extend_from_slice(&(layer.merkle.siblings.len() as u16).to_be_bytes());
        for sibling in &layer.merkle.siblings {
            out.extend_from_slice(sibling);
        }
    }
    out
}

struct ProofCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProofCursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("proof offset")?;
        if end > self.bytes.len() {
            return Err("truncated successor FRI proof".into());
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16_be(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32_be(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn qm31(&mut self) -> Result<Qm31Value, String> {
        let mut value = [0u32; 4];
        for coordinate in &mut value {
            *coordinate = u32::from_le_bytes(self.take(4)?.try_into().unwrap());
            if *coordinate as u64 >= M31 {
                return Err("successor FRI field element".into());
            }
        }
        Ok(value)
    }

    fn m31(&mut self) -> Result<u32, String> {
        let value = u32::from_le_bytes(self.take(4)?.try_into().unwrap());
        if value as u64 >= M31 {
            return Err("successor field element".into());
        }
        Ok(value)
    }
}

pub fn decode_successor_fri_proof(bytes: &[u8]) -> Result<SuccessorFriProof, String> {
    let mut cursor = ProofCursor { bytes, offset: 0 };
    if cursor.take(4)? != SUCCESSOR_FRI_CODEC_MAGIC || cursor.u8()? != SUCCESSOR_FRI_CODEC_VERSION {
        return Err("successor FRI codec".into());
    }
    let layer_count = cursor.u8()? as usize;
    let grind_nonce = cursor.u32_be()?;
    let final_count = cursor.u16_be()? as usize;
    if layer_count == 0 || final_count == 0 || !final_count.is_power_of_two() {
        return Err("successor FRI shape".into());
    }
    let final_coefficients = (0..final_count)
        .map(|_| cursor.qm31())
        .collect::<Result<_, _>>()?;
    let mut layers = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        let root: [u8; 32] = cursor.take(32)?.try_into().unwrap();
        let opening_count = cursor.u16_be()? as usize;
        if opening_count == 0 {
            return Err("successor FRI opening".into());
        }
        let mut indices = Vec::with_capacity(opening_count);
        let mut values = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            indices.push(cursor.u32_be()? as usize);
            values.push(cursor.qm31()?);
        }
        let sibling_count = cursor.u16_be()? as usize;
        let siblings = (0..sibling_count)
            .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
            .collect::<Result<Vec<[u8; 32]>, String>>()?;
        layers.push(SuccessorFriLayerProof {
            root,
            values,
            merkle: CanonicalMerkleMultiProof { indices, siblings },
        });
    }
    if cursor.offset != bytes.len() {
        return Err("trailing successor FRI bytes".into());
    }
    Ok(SuccessorFriProof {
        layers,
        final_coefficients,
        grind_nonce,
    })
}

const LOCAL_WORD_SEALED_PROOF_MAGIC: &[u8; 4] = b"SKLW";
const LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET: usize = 4 + 1 + 1 + 32;
const LOCAL_WORD_SEALED_PROOF_MAX_BYTES: usize = 1_000_000;
const LOCAL_WORD_MATRIX_M31_WIDTHS: [usize; 5] = [
    LOCAL_WORD_PREPROCESSED_COLUMNS,
    LOCAL_WORD_ORIGINAL_COLUMNS,
    LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH,
    LOCAL_WORD_INTERACTION_GLOBAL_M31_WIDTH,
    8,
];
const LOCAL_WORD_MATRIX_LABELS: [&str; 5] = [
    "local-word:preprocessed",
    "local-word:original",
    "local-word:interaction",
    "local-word:interaction-global",
    "local-word:quotient-and-fri-mask",
];
const LOCAL_WORD_MERKLE_FRONTIER_LEVEL: u32 = 4;
const LOCAL_WORD_GLOBAL_MERKLE_FIRST_STAGE_LEVELS: u32 = 1;
const LOCAL_WORD_GLOBAL_MERKLE_STAGE_LEVELS: u32 = 2;
const LOCAL_WORD_FRI_MERKLE_FIRST_STAGE_LEVELS: u32 = 1;
const LOCAL_WORD_FRI_MERKLE_STAGE_LEVELS: u32 = 3;
const LOCAL_WORD_INTERACTION_MERKLE_STAGE_LEVELS: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalWordMerkleStageGeometry {
    first_level: u32,
    levels_per_stage: u32,
}

fn local_word_matrix_merkle_stage_geometry(matrix: usize) -> LocalWordMerkleStageGeometry {
    match matrix {
        2 => LocalWordMerkleStageGeometry {
            first_level: 0,
            levels_per_stage: LOCAL_WORD_INTERACTION_MERKLE_STAGE_LEVELS,
        },
        3 => LocalWordMerkleStageGeometry {
            first_level: LOCAL_WORD_GLOBAL_MERKLE_FIRST_STAGE_LEVELS,
            levels_per_stage: LOCAL_WORD_GLOBAL_MERKLE_STAGE_LEVELS,
        },
        _ => LocalWordMerkleStageGeometry {
            first_level: LOCAL_WORD_MERKLE_FRONTIER_LEVEL,
            levels_per_stage: LOCAL_WORD_MERKLE_FRONTIER_LEVEL,
        },
    }
}

const LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY: LocalWordMerkleStageGeometry =
    LocalWordMerkleStageGeometry {
        first_level: LOCAL_WORD_FRI_MERKLE_FIRST_STAGE_LEVELS,
        levels_per_stage: LOCAL_WORD_FRI_MERKLE_STAGE_LEVELS,
    };

fn canonical_multiproof_sibling_count(
    indices: &[usize],
    row_count: usize,
) -> Result<usize, String> {
    if indices.is_empty()
        || row_count < 2
        || !row_count.is_power_of_two()
        || row_count.ilog2() % 2 != 0
        || indices.iter().any(|index| *index >= row_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("canonical multiproof indices".into());
    }
    let levels = row_count.ilog2() / 2;
    let mut frontier = indices.to_vec();
    let mut siblings = 0usize;
    for _ in 0..levels {
        let mut parents = frontier.iter().map(|index| index >> 2).collect::<Vec<_>>();
        parents.dedup();
        for parent in &parents {
            for child in 0..4 {
                if frontier.binary_search(&(parent * 4 + child)).is_err() {
                    siblings = siblings.checked_add(1).ok_or("canonical multiproof size")?;
                }
            }
        }
        frontier = parents;
    }
    if frontier != [0] {
        return Err("canonical multiproof frontier".into());
    }
    Ok(siblings)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalWordMerkleFrontierSchedule {
    level: u32,
    indices: Vec<usize>,
    sibling_count: usize,
}

fn local_word_merkle_frontier_schedules(
    indices: &[usize],
    row_count: usize,
    geometry: LocalWordMerkleStageGeometry,
) -> Result<Vec<LocalWordMerkleFrontierSchedule>, String> {
    canonical_multiproof_sibling_count(indices, row_count)?;
    let height = row_count.ilog2() / 2;
    if geometry.first_level >= height || geometry.levels_per_stage == 0 {
        return Err("local-word Merkle stage height".into());
    }
    let mut frontier = indices.to_vec();
    let mut sibling_count = 0usize;
    let mut schedules = Vec::new();
    let mut next_cut = geometry.first_level;
    if next_cut == 0 {
        schedules.push(LocalWordMerkleFrontierSchedule {
            level: 0,
            indices: frontier.clone(),
            sibling_count: 0,
        });
        next_cut = geometry.levels_per_stage;
    }
    for current in 0..height {
        let mut parents = frontier.iter().map(|index| index >> 2).collect::<Vec<_>>();
        parents.dedup();
        for parent in &parents {
            for child in 0..4 {
                if frontier.binary_search(&(parent * 4 + child)).is_err() {
                    sibling_count = sibling_count
                        .checked_add(1)
                        .ok_or("local-word Merkle frontier size")?;
                }
            }
        }
        frontier = parents;
        let level = current + 1;
        if level < height && level == next_cut {
            schedules.push(LocalWordMerkleFrontierSchedule {
                level,
                indices: frontier.clone(),
                sibling_count,
            });
            next_cut += geometry.levels_per_stage;
        }
    }
    Ok(schedules)
}

fn encode_local_word_merkle_frontier(
    label: &str,
    indices: &[usize],
    rows: &[Vec<u8>],
    siblings: &[[u8; 32]],
    schedule: &LocalWordMerkleFrontierSchedule,
) -> Result<Vec<u8>, String> {
    use std::collections::BTreeMap;

    if rows.len() != indices.len() {
        return Err("local-word Merkle frontier rows".into());
    }
    let tree_key = canonical_tree_key(label);
    let mut frontier = indices
        .iter()
        .zip(rows)
        .map(|(index, raw)| (*index, raw_leaf(&tree_key, *index, raw)))
        .collect::<BTreeMap<_, _>>();
    let mut sibling_cursor = 0usize;
    for level in 0..schedule.level {
        let mut parents = frontier.keys().map(|index| index >> 2).collect::<Vec<_>>();
        parents.dedup();
        let mut next = BTreeMap::new();
        for parent in parents {
            let mut children = [[0u8; 32]; 4];
            for (child, slot) in children.iter_mut().enumerate() {
                *slot = match frontier.get(&(parent * 4 + child)) {
                    Some(value) => *value,
                    None => {
                        let value = siblings
                            .get(sibling_cursor)
                            .ok_or("local-word Merkle frontier siblings")?;
                        sibling_cursor += 1;
                        *value
                    }
                };
            }
            next.insert(parent, matrix_parent4(&tree_key, level as u8, &children));
        }
        frontier = next;
    }
    if sibling_cursor != schedule.sibling_count
        || frontier.keys().copied().collect::<Vec<_>>() != schedule.indices
    {
        return Err("local-word Merkle frontier schedule".into());
    }
    let mut encoded = Vec::with_capacity(frontier.len() * 36);
    for (index, hash) in frontier {
        encoded.extend_from_slice(
            &u32::try_from(index)
                .map_err(|_| "local-word Merkle frontier index")?
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&hash);
    }
    Ok(encoded)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalWordOpeningFrontierEntry {
    level: u32,
    sibling_cut: usize,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalWordOpeningDirectoryEntry {
    indices_start: usize,
    rows_start: usize,
    siblings_start: usize,
    stage_directory_start: usize,
    end: usize,
    frontiers: Vec<LocalWordOpeningFrontierEntry>,
}

fn local_word_proof_directory(
    queries: &[usize],
    public_word_count: usize,
    parameters: LocalWordProofParameters,
) -> Result<(Vec<u8>, Vec<LocalWordOpeningDirectoryEntry>), String> {
    parameters.validate()?;
    if queries.len() != parameters.fri.queries
        || public_word_count == 0
        || public_word_count > 1_024
    {
        return Err("local-word proof directory shape".into());
    }
    let current = sorted_unique(queries.to_vec());
    let (global, fri_indices) = local_word_opening_schedules(&current, parameters)?;
    let rank = |indices: &[usize], index: usize, label: &str| -> Result<u8, String> {
        let value = indices
            .binary_search(&index)
            .map_err(|_| format!("local-word {label} rank"))?;
        u8::try_from(value).map_err(|_| format!("local-word {label} rank"))
    };
    let predecessors = queries
        .iter()
        .map(|query| {
            stwo::core::utils::offset_bit_reversed_circle_domain_index(
                *query,
                parameters.relation_log,
                parameters.eval_log,
                -1,
            )
        })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    for query in queries {
        bytes.push(rank(&current, *query, "current")?);
    }
    for query in queries {
        bytes.push(rank(&global, *query, "global current")?);
    }
    for previous in &predecessors {
        bytes.push(rank(&global, *previous, "global previous")?);
    }
    let fold_counts = parameters.fri_fold_counts();
    let mut completed_folds = 0u32;
    for (round, indices) in fri_indices.iter().enumerate() {
        let arity = 1usize << fold_counts[round];
        for query in queries {
            bytes.push(rank(
                indices,
                (query >> completed_folds) & !(arity - 1),
                "FRI coset",
            )?);
        }
        completed_folds += fold_counts[round];
    }

    let fri_layers = parameters.fri_layers();
    let final_coefficients = 1usize << parameters.fri.final_log_degree;
    let directory_bytes = parameters.fri.queries * (3 + fri_layers)
        + (LOCAL_WORD_MATRIX_M31_WIDTHS.len() + fri_layers) * 20;
    let transcript_manifest_bytes = LOCAL_WORD_INTERACTION_CHALLENGE_COUNT * 16
        + 32
        + 16
        + 32
        + 16
        + 32
        + fri_layers * 16
        + 32 * 3;
    let mut cursor = LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET
        + 4
        + public_word_count * 16
        + 16
        + LOCAL_WORD_MATRIX_M31_WIDTHS.len() * 32
        + fri_layers * 32
        + final_coefficients * 16
        + 4
        + transcript_manifest_bytes
        + parameters.fri.queries * 4
        + parameters.fri.queries * 4
        + directory_bytes
        + parameters.fri.queries * LOCAL_WORD_AIR_PARTIAL_WIDTHS.len() * 16;
    let mut openings = Vec::with_capacity(LOCAL_WORD_MATRIX_M31_WIDTHS.len() + fri_layers);
    let mut add_opening = |indices: &[usize],
                           row_width: usize,
                           row_count: usize,
                           geometry: LocalWordMerkleStageGeometry,
                           serialize_indices: bool|
     -> Result<(), String> {
        let siblings = canonical_multiproof_sibling_count(indices, row_count)?;
        let frontiers = local_word_merkle_frontier_schedules(indices, row_count, geometry)?;
        let indices_start = cursor;
        let rows_start = indices_start
            + if serialize_indices {
                indices.len() * 4
            } else {
                0
            };
        let siblings_start = rows_start + indices.len() * row_width;
        let stage_directory_start = siblings_start + siblings * 32;
        let mut frontier_cursor = stage_directory_start + frontiers.len() * 12;
        let directory_frontiers = frontiers
            .into_iter()
            .map(|frontier| {
                let start = frontier_cursor;
                frontier_cursor += frontier.indices.len() * 36;
                LocalWordOpeningFrontierEntry {
                    level: frontier.level,
                    sibling_cut: siblings_start + frontier.sibling_count * 32,
                    start,
                    end: frontier_cursor,
                }
            })
            .collect();
        let end = frontier_cursor;
        openings.push(LocalWordOpeningDirectoryEntry {
            indices_start,
            rows_start,
            siblings_start,
            stage_directory_start,
            end,
            frontiers: directory_frontiers,
        });
        cursor = end;
        Ok(())
    };
    for (matrix, width) in LOCAL_WORD_MATRIX_M31_WIDTHS.iter().enumerate() {
        add_opening(
            if matrix == 3 { &global } else { &current },
            width * 4,
            parameters.row_count(),
            local_word_matrix_merkle_stage_geometry(matrix),
            matrix == 3,
        )?;
    }
    let layer_logs = parameters.fri_layer_logs();
    for (round, indices) in fri_indices.iter().enumerate() {
        add_opening(
            indices,
            16,
            1usize << layer_logs[round],
            LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
            true,
        )?;
    }
    for entry in &openings {
        for value in [
            entry.indices_start,
            entry.rows_start,
            entry.siblings_start,
            entry.stage_directory_start,
            entry.end,
        ] {
            bytes.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| "local-word proof directory offset")?
                    .to_be_bytes(),
            );
        }
    }
    if bytes.len() != directory_bytes {
        return Err("local-word proof directory width".into());
    }
    Ok((bytes, openings))
}

fn encode_local_word_merkle_frontier_bundle(
    label: &str,
    indices: &[usize],
    rows: &[Vec<u8>],
    siblings: &[[u8; 32]],
    row_count: usize,
    geometry: LocalWordMerkleStageGeometry,
    entry: &LocalWordOpeningDirectoryEntry,
) -> Result<Vec<u8>, String> {
    let schedules = local_word_merkle_frontier_schedules(indices, row_count, geometry)?;
    if schedules.len() != entry.frontiers.len() {
        return Err("local-word Merkle frontier directory".into());
    }
    let mut blobs = Vec::with_capacity(schedules.len());
    for (schedule, expected) in schedules.iter().zip(&entry.frontiers) {
        let bytes = encode_local_word_merkle_frontier(label, indices, rows, siblings, schedule)?;
        if expected.level != schedule.level
            || expected.sibling_cut != entry.siblings_start + schedule.sibling_count * 32
            || expected.end - expected.start != bytes.len()
        {
            return Err("local-word Merkle frontier schedule".into());
        }
        blobs.push(bytes);
    }
    let mut out = Vec::new();
    for frontier in &entry.frontiers {
        for value in [frontier.sibling_cut, frontier.start, frontier.end] {
            out.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| "local-word Merkle frontier offset")?
                    .to_be_bytes(),
            );
        }
    }
    for blob in blobs {
        out.extend_from_slice(&blob);
    }
    Ok(out)
}

fn encode_local_word_opening_body(
    label: &str,
    opening: &SuccessorMatrixOpening,
    expected_width: usize,
    expected_indices: &[usize],
    row_count: usize,
    geometry: LocalWordMerkleStageGeometry,
    entry: &LocalWordOpeningDirectoryEntry,
    serialize_indices: bool,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let sibling_count = canonical_multiproof_sibling_count(expected_indices, row_count)?;
    if opening.row_width != expected_width
        || opening.indices != expected_indices
        || opening.rows.len() != expected_indices.len()
        || opening.rows.iter().any(|row| {
            row.len() != expected_width
                || row
                    .chunks_exact(4)
                    .any(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()) as u64 >= M31)
        })
        || opening.siblings.len() != sibling_count
    {
        return Err("local-word matrix opening shape".into());
    }
    if serialize_indices {
        for index in expected_indices {
            out.extend_from_slice(
                &u32::try_from(*index)
                    .map_err(|_| "local-word matrix index manifest")?
                    .to_be_bytes(),
            );
        }
    }
    for row in &opening.rows {
        out.extend_from_slice(row);
    }
    for sibling in &opening.siblings {
        out.extend_from_slice(sibling);
    }
    out.extend_from_slice(&encode_local_word_merkle_frontier_bundle(
        label,
        expected_indices,
        &opening.rows,
        &opening.siblings,
        row_count,
        geometry,
        entry,
    )?);
    Ok(())
}

fn decode_local_word_opening_body(
    cursor: &mut ProofCursor<'_>,
    root: [u8; 32],
    label: &str,
    row_width: usize,
    indices: &[usize],
    row_count: usize,
    geometry: LocalWordMerkleStageGeometry,
    entry: &LocalWordOpeningDirectoryEntry,
    serialize_indices: bool,
) -> Result<SuccessorMatrixOpening, String> {
    if serialize_indices {
        for index in indices {
            if cursor.u32_be()? as usize != *index {
                return Err("local-word matrix index manifest".into());
            }
        }
    }
    let mut rows = Vec::with_capacity(indices.len());
    for _ in indices {
        let row = cursor.take(row_width)?.to_vec();
        if row
            .chunks_exact(4)
            .any(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()) as u64 >= M31)
        {
            return Err("local-word matrix field element".into());
        }
        rows.push(row);
    }
    let sibling_count = canonical_multiproof_sibling_count(indices, row_count)?;
    let siblings = (0..sibling_count)
        .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    let expected_frontier = encode_local_word_merkle_frontier_bundle(
        label, indices, &rows, &siblings, row_count, geometry, entry,
    )?;
    if cursor.take(expected_frontier.len())? != expected_frontier {
        return Err("local-word matrix frontier".into());
    }
    Ok(SuccessorMatrixOpening {
        root,
        row_width,
        indices: indices.to_vec(),
        rows,
        siblings,
    })
}

fn local_word_matrix_openings(proof: &LocalWordSealedProof) -> [&SuccessorMatrixOpening; 5] {
    [
        &proof.preprocessed,
        &proof.original,
        &proof.interaction,
        &proof.interaction_global,
        &proof.quotient_and_fri_mask,
    ]
}

fn local_word_opening_schedules(
    current: &[usize],
    parameters: LocalWordProofParameters,
) -> Result<(Vec<usize>, Vec<Vec<usize>>), String> {
    parameters.validate()?;
    if current.is_empty()
        || current.len() != parameters.fri.queries
        || current.windows(2).any(|pair| pair[0] >= pair[1])
        || current.iter().any(|index| *index >= parameters.row_count())
    {
        return Err("local-word query schedule".into());
    }
    let global = sorted_unique(
        current
            .iter()
            .copied()
            .chain(current.iter().map(|index| {
                stwo::core::utils::offset_bit_reversed_circle_domain_index(
                    *index,
                    parameters.relation_log,
                    parameters.eval_log,
                    -1,
                )
            }))
            .collect(),
    );
    let fold_counts = parameters.fri_fold_counts();
    let fri = fri_opening_indices(current.to_vec(), &fold_counts);
    if global.len() != 2 * current.len()
        || fri
            .iter()
            .zip(fold_counts)
            .any(|(indices, folds)| indices.len() != current.len() * (1usize << folds))
    {
        return Err("local-word opening schedule collision".into());
    }
    Ok((global, fri))
}

/// Canonical proof encoding for the local-word successor. The verifier key and
/// public statement supply all fixed widths and statement values. The checked
/// transcript manifest, query schedule, and directory make every later VM
/// role deterministic without duplicating any opening body. Merkle merges are
/// derived from the checked schedules and are not serialized as instructions.
fn encode_local_word_sealed_proof_with_parameters(
    proof: &LocalWordSealedProof,
    parameters: LocalWordProofParameters,
) -> Result<Vec<u8>, String> {
    parameters.validate()?;
    if proof.version != LOCAL_WORD_PROOF_VERSION
        || proof.profile > 2
        || proof.public_boundary_inverses.is_empty()
        || proof.public_boundary_inverses.len() > 1_024
        || proof.fri.layers.len() != parameters.fri_layers()
        || proof.transcript_manifest.interaction_challenges.len()
            != LOCAL_WORD_INTERACTION_CHALLENGE_COUNT
        || proof.transcript_manifest.fri_alphas.len() != parameters.fri_layers()
        || proof.fri.final_coefficients.len() != 1usize << parameters.fri.final_log_degree
        || proof.composition_partials.len() != parameters.fri.queries
    {
        return Err("local-word sealed proof shape".into());
    }
    if proof
        .public_boundary_inverses
        .iter()
        .chain(std::iter::once(&proof.public_boundary_claimed_sum))
        .chain(proof.fri.final_coefficients.iter())
        .chain(proof.composition_partials.iter().flatten())
        .chain(
            proof
                .fri
                .layers
                .iter()
                .flat_map(|layer| layer.values.iter()),
        )
        .flatten()
        .any(|coordinate| *coordinate as u64 >= M31)
    {
        return Err("local-word sealed proof field element".into());
    }
    if proof
        .transcript_manifest
        .interaction_challenges
        .iter()
        .chain(std::iter::once(&proof.transcript_manifest.constraint_alpha))
        .chain(std::iter::once(&proof.transcript_manifest.batch_beta))
        .chain(proof.transcript_manifest.fri_alphas.iter())
        .flatten()
        .any(|coordinate| *coordinate as u64 >= M31)
    {
        return Err("local-word transcript manifest field element".into());
    }

    let current = sorted_unique(proof.queries.clone());
    if current.len() != parameters.fri.queries {
        return Err("local-word query manifest".into());
    }
    let (global, fri_indices) = local_word_opening_schedules(&current, parameters)?;
    let fri_layer_logs = parameters.fri_layer_logs();
    let openings = local_word_matrix_openings(proof);
    for (index, opening) in openings.iter().enumerate() {
        let expected = if index == 3 { &global } else { &current };
        if opening.indices.as_slice() != expected.as_slice() {
            return Err("local-word matrix query schedule".into());
        }
    }
    for (round, (layer, expected)) in proof.fri.layers.iter().zip(&fri_indices).enumerate() {
        if layer.merkle.indices.as_slice() != expected.as_slice()
            || layer.values.len() != expected.len()
            || layer.merkle.siblings.len()
                != canonical_multiproof_sibling_count(expected, 1usize << fri_layer_logs[round])?
        {
            return Err("local-word FRI opening shape".into());
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(LOCAL_WORD_SEALED_PROOF_MAGIC);
    out.push(proof.version);
    out.push(proof.profile);
    out.extend_from_slice(&proof.construction_digest);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&encode_qm31_values(&proof.public_boundary_inverses));
    out.extend_from_slice(&encode_qm31_values(&[proof.public_boundary_claimed_sum]));
    for opening in openings {
        out.extend_from_slice(&opening.root);
    }
    for layer in &proof.fri.layers {
        out.extend_from_slice(&layer.root);
    }
    out.extend_from_slice(&encode_qm31_values(&proof.fri.final_coefficients));
    out.extend_from_slice(&proof.fri.grind_nonce.to_be_bytes());
    out.extend_from_slice(&encode_qm31_values(
        &proof.transcript_manifest.interaction_challenges,
    ));
    out.extend_from_slice(&proof.transcript_manifest.interaction_digest);
    out.extend_from_slice(&encode_qm31_values(&[proof
        .transcript_manifest
        .constraint_alpha]));
    out.extend_from_slice(&proof.transcript_manifest.composition_digest);
    out.extend_from_slice(&encode_qm31_values(&[proof.transcript_manifest.batch_beta]));
    out.extend_from_slice(&proof.transcript_manifest.batch_digest);
    out.extend_from_slice(&encode_qm31_values(&proof.transcript_manifest.fri_alphas));
    out.extend_from_slice(&proof.transcript_manifest.fri_mid_digest);
    out.extend_from_slice(&proof.transcript_manifest.fri_roots_digest);
    out.extend_from_slice(&proof.transcript_manifest.query_digest);
    for query in &proof.queries {
        out.extend_from_slice(&(*query as u32).to_be_bytes());
    }
    for index in &current {
        out.extend_from_slice(&(*index as u32).to_be_bytes());
    }
    let (directory_bytes, directory) = local_word_proof_directory(
        &proof.queries,
        proof.public_boundary_inverses.len(),
        parameters,
    )?;
    out.extend_from_slice(&directory_bytes);
    for partials in &proof.composition_partials {
        out.extend_from_slice(&encode_qm31_values(partials));
    }

    let openings = local_word_matrix_openings(proof);
    for (index, opening) in openings.iter().enumerate() {
        let expected_indices = if index == 3 { &global } else { &current };
        encode_local_word_opening_body(
            LOCAL_WORD_MATRIX_LABELS[index],
            opening,
            LOCAL_WORD_MATRIX_M31_WIDTHS[index] * 4,
            expected_indices,
            parameters.row_count(),
            local_word_matrix_merkle_stage_geometry(index),
            &directory[index],
            index == 3,
            &mut out,
        )?;
    }
    for (round, (layer, expected_indices)) in proof.fri.layers.iter().zip(fri_indices).enumerate() {
        for index in &expected_indices {
            out.extend_from_slice(
                &u32::try_from(*index)
                    .map_err(|_| "local-word FRI index manifest")?
                    .to_be_bytes(),
            );
        }
        for value in &layer.values {
            out.extend_from_slice(&encode_qm31_values(&[*value]));
        }
        let sibling_count =
            canonical_multiproof_sibling_count(&expected_indices, 1usize << fri_layer_logs[round])?;
        if layer.merkle.siblings.len() != sibling_count {
            return Err("local-word FRI sibling count".into());
        }
        for sibling in &layer.merkle.siblings {
            out.extend_from_slice(sibling);
        }
        let rows = layer
            .values
            .iter()
            .map(|value| encode_qm31_values(&[*value]))
            .collect::<Vec<_>>();
        out.extend_from_slice(&encode_local_word_merkle_frontier_bundle(
            &format!("fri:layer:{round}"),
            &expected_indices,
            &rows,
            &layer.merkle.siblings,
            1usize << fri_layer_logs[round],
            LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
            &directory[LOCAL_WORD_MATRIX_M31_WIDTHS.len() + round],
        )?);
    }
    if out.len() > LOCAL_WORD_SEALED_PROOF_MAX_BYTES || out.len() > u32::MAX as usize {
        return Err("local-word sealed proof byte length".into());
    }
    let proof_length = (out.len() as u32).to_be_bytes();
    out[LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET..LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET + 4]
        .copy_from_slice(&proof_length);
    Ok(out)
}

pub fn encode_local_word_sealed_proof(proof: &LocalWordSealedProof) -> Result<Vec<u8>, String> {
    encode_local_word_sealed_proof_with_parameters(proof, LocalWordProofParameters::PRODUCTION)
}

/// Decode the canonical local-word proof using only verifier-key and public
/// statement data. Every serialized derivation aid is replayed and compared.
fn decode_local_word_sealed_proof_with_parameters(
    bytes: &[u8],
    expected_profile: u8,
    transcript_initial: &[u8],
    construction_descriptor: &[u8],
    public_words: &[LocalWordPublicWord],
    expected_preprocessed_root: [u8; 32],
    parameters: LocalWordProofParameters,
) -> Result<LocalWordSealedProof, String> {
    parameters.validate()?;
    if transcript_initial.is_empty()
        || construction_descriptor.is_empty()
        || public_words.is_empty()
        || public_words.len() > 1_024
    {
        return Err("local-word proof context".into());
    }
    let mut cursor = ProofCursor { bytes, offset: 0 };
    if cursor.take(4)? != LOCAL_WORD_SEALED_PROOF_MAGIC {
        return Err("local-word sealed proof codec".into());
    }
    let version = cursor.u8()?;
    let profile = cursor.u8()?;
    if version != LOCAL_WORD_PROOF_VERSION || profile != expected_profile || profile > 2 {
        return Err("local-word sealed proof version".into());
    }
    let construction_digest: [u8; 32] = cursor.take(32)?.try_into().unwrap();
    if construction_digest != <[u8; 32]>::from(Sha256::digest(construction_descriptor)) {
        return Err("local-word construction digest".into());
    }
    let declared_length = cursor.u32_be()? as usize;
    if declared_length != bytes.len() || declared_length > LOCAL_WORD_SEALED_PROOF_MAX_BYTES {
        return Err("local-word sealed proof byte length".into());
    }
    let public_boundary_inverses = (0..public_words.len())
        .map(|_| cursor.qm31())
        .collect::<Result<Vec<_>, _>>()?;
    let public_boundary_claimed_sum = cursor.qm31()?;
    let roots = (0..LOCAL_WORD_MATRIX_M31_WIDTHS.len())
        .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    if roots[0] != expected_preprocessed_root {
        return Err("local-word preprocessed root".into());
    }
    let layer_count = parameters.fri_layers();
    let fri_roots = (0..layer_count)
        .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    let final_coefficients = (0..1usize << parameters.fri.final_log_degree)
        .map(|_| cursor.qm31())
        .collect::<Result<Vec<_>, _>>()?;
    let grind_nonce = cursor.u32_be()?;
    let transcript_manifest = LocalWordTranscriptManifest {
        interaction_challenges: (0..LOCAL_WORD_INTERACTION_CHALLENGE_COUNT)
            .map(|_| cursor.qm31())
            .collect::<Result<Vec<_>, _>>()?,
        interaction_digest: cursor.take(32)?.try_into().unwrap(),
        constraint_alpha: cursor.qm31()?,
        composition_digest: cursor.take(32)?.try_into().unwrap(),
        batch_beta: cursor.qm31()?,
        batch_digest: cursor.take(32)?.try_into().unwrap(),
        fri_alphas: (0..layer_count)
            .map(|_| cursor.qm31())
            .collect::<Result<Vec<_>, _>>()?,
        fri_mid_digest: cursor.take(32)?.try_into().unwrap(),
        fri_roots_digest: cursor.take(32)?.try_into().unwrap(),
        query_digest: cursor.take(32)?.try_into().unwrap(),
    };
    let query_manifest = (0..parameters.fri.queries)
        .map(|_| cursor.u32_be().map(|query| query as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let current_index_manifest = (0..parameters.fri.queries)
        .map(|_| cursor.u32_be().map(|index| index as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let directory_width = parameters.fri.queries * (3 + layer_count)
        + (LOCAL_WORD_MATRIX_M31_WIDTHS.len() + layer_count) * 20;
    let directory_manifest = cursor.take(directory_width)?.to_vec();
    let composition_partials = (0..parameters.fri.queries)
        .map(|_| {
            (0..LOCAL_WORD_AIR_PARTIAL_WIDTHS.len())
                .map(|_| cursor.qm31())
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| "local-word composition partial shape".into())
        })
        .collect::<Result<Vec<[Qm31Value; 3]>, String>>()?;

    let (mut transcript, interaction_challenges, boundary_challenges) =
        local_word_v15_interaction_transcript(
            transcript_initial,
            construction_digest,
            roots[0],
            roots[1],
        );
    if transcript_manifest.interaction_challenges
        != local_word_v15_interaction_challenge_values(
            &interaction_challenges,
            &boundary_challenges,
        )
    {
        return Err("local-word interaction challenge manifest".into());
    }
    let (expected_claimed_sum, expected_inverses) =
        local_word_public_boundary_claim_for_words(public_words, &boundary_challenges)?;
    if public_boundary_inverses != expected_inverses {
        return Err("local-word public boundary inverses".into());
    }
    if public_boundary_claimed_sum != expected_claimed_sum {
        return Err("local-word public boundary claimed sum".into());
    }
    local_word_v15_public_boundary_transcript(&mut transcript, &public_boundary_inverses)?;
    if transcript_manifest.interaction_digest != transcript.digest() {
        return Err("local-word interaction digest manifest".into());
    }
    let (constraint_alpha, composition_digest) =
        local_word_v15_composition_transcript(&mut transcript, roots[2], roots[3]);
    if transcript_manifest.constraint_alpha != constraint_alpha
        || transcript_manifest.composition_digest != composition_digest
    {
        return Err("local-word composition manifest".into());
    }
    transcript.absorb("local-word-quotient-and-fri-mask-root", &roots[4]);
    let batch_beta = transcript.challenge_qm31("local-word-batch-beta");
    if transcript_manifest.batch_beta != batch_beta
        || transcript_manifest.batch_digest != transcript.digest()
    {
        return Err("local-word batch manifest".into());
    }
    let fri_split = fri_roots.len().div_ceil(2);
    let mut fri_alphas = Vec::with_capacity(fri_roots.len());
    let mut fri_mid_digest = [0u8; 32];
    for (round, root) in fri_roots.iter().enumerate() {
        transcript.absorb(&format!("fri-root:{round}"), root);
        fri_alphas.push(transcript.challenge_qm31(&format!("fri-alpha:{round}")));
        if round + 1 == fri_split {
            fri_mid_digest = transcript.digest();
        }
    }
    if transcript_manifest.fri_alphas != fri_alphas
        || transcript_manifest.fri_mid_digest != fri_mid_digest
        || transcript_manifest.fri_roots_digest != transcript.digest()
    {
        return Err("local-word FRI root manifest".into());
    }
    transcript.absorb("fri-final", &encode_qm31_values(&final_coefficients));
    if !transcript.accept_grind(parameters.fri.grind_bits, grind_nonce) {
        return Err("local-word FRI grind".into());
    }
    if transcript_manifest.query_digest != transcript.digest() {
        return Err("local-word query digest manifest".into());
    }
    let queries = local_word_query_indices(&transcript, parameters)?;
    if query_manifest != queries {
        return Err("local-word query manifest".into());
    }
    let current = sorted_unique(queries.clone());
    if current_index_manifest != current {
        return Err("local-word current index manifest".into());
    }
    let (global, fri_indices) = local_word_opening_schedules(&current, parameters)?;
    let fri_layer_logs = parameters.fri_layer_logs();
    let (expected_directory, directory) =
        local_word_proof_directory(&queries, public_words.len(), parameters)?;
    if directory_manifest != expected_directory {
        return Err("local-word proof directory".into());
    }

    let mut openings = Vec::with_capacity(LOCAL_WORD_MATRIX_M31_WIDTHS.len());
    for (index, width) in LOCAL_WORD_MATRIX_M31_WIDTHS.iter().enumerate() {
        let expected_indices = if index == 3 { &global } else { &current };
        openings.push(decode_local_word_opening_body(
            &mut cursor,
            roots[index],
            LOCAL_WORD_MATRIX_LABELS[index],
            width * 4,
            expected_indices,
            parameters.row_count(),
            local_word_matrix_merkle_stage_geometry(index),
            &directory[index],
            index == 3,
        )?);
    }
    let mut layers = Vec::with_capacity(layer_count);
    for (round, expected_indices) in fri_indices.into_iter().enumerate() {
        for index in &expected_indices {
            if cursor.u32_be()? as usize != *index {
                return Err("local-word FRI index manifest".into());
            }
        }
        let values = (0..expected_indices.len())
            .map(|_| cursor.qm31())
            .collect::<Result<Vec<_>, _>>()?;
        let sibling_count =
            canonical_multiproof_sibling_count(&expected_indices, 1usize << fri_layer_logs[round])?;
        let siblings = (0..sibling_count)
            .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
            .collect::<Result<Vec<[u8; 32]>, String>>()?;
        let rows = values
            .iter()
            .map(|value| encode_qm31_values(&[*value]))
            .collect::<Vec<_>>();
        let expected_frontier = encode_local_word_merkle_frontier_bundle(
            &format!("fri:layer:{round}"),
            &expected_indices,
            &rows,
            &siblings,
            1usize << fri_layer_logs[round],
            LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
            &directory[LOCAL_WORD_MATRIX_M31_WIDTHS.len() + round],
        )?;
        if cursor.take(expected_frontier.len())? != expected_frontier {
            return Err("local-word FRI frontier".into());
        }
        layers.push(SuccessorFriLayerProof {
            root: fri_roots[round],
            values,
            merkle: CanonicalMerkleMultiProof {
                indices: expected_indices,
                siblings,
            },
        });
    }
    if cursor.offset != bytes.len() {
        return Err("trailing local-word sealed proof bytes".into());
    }
    let openings: [SuccessorMatrixOpening; 5] = openings
        .try_into()
        .map_err(|_| "local-word matrix opening count")?;
    Ok(LocalWordSealedProof {
        version,
        profile,
        construction_digest,
        public_boundary_inverses,
        public_boundary_claimed_sum,
        preprocessed: openings[0].clone(),
        original: openings[1].clone(),
        interaction: openings[2].clone(),
        interaction_global: openings[3].clone(),
        quotient_and_fri_mask: openings[4].clone(),
        fri: SuccessorFriProof {
            layers,
            final_coefficients,
            grind_nonce,
        },
        transcript_manifest,
        queries,
        composition_partials,
    })
}

pub fn decode_local_word_sealed_proof(
    bytes: &[u8],
    expected_profile: u8,
    transcript_initial: &[u8],
    construction_descriptor: &[u8],
    public_words: &[LocalWordPublicWord],
    expected_preprocessed_root: [u8; 32],
) -> Result<LocalWordSealedProof, String> {
    decode_local_word_sealed_proof_with_parameters(
        bytes,
        expected_profile,
        transcript_initial,
        construction_descriptor,
        public_words,
        expected_preprocessed_root,
        LocalWordProofParameters::PRODUCTION,
    )
}

pub fn verify_local_word_sealed_proof_bytes(
    bytes: &[u8],
    profile: u8,
    transcript_initial: &[u8],
    construction_descriptor: &[u8],
    public_words: &[LocalWordPublicWord],
    expected_preprocessed_root: [u8; 32],
) -> Result<(), String> {
    let proof = decode_local_word_sealed_proof(
        bytes,
        profile,
        transcript_initial,
        construction_descriptor,
        public_words,
        expected_preprocessed_root,
    )?;
    verify_local_word_sealed_proof(
        &proof,
        profile,
        transcript_initial,
        construction_descriptor,
        public_words,
        expected_preprocessed_root,
    )
}

/// Small exact proof used to cross-check independent verifier implementations.
/// It uses the production relation and codec, with only the verifier-key domain
/// geometry reduced. No fixture-specific value is serialized into the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWordReferenceFixture {
    pub proof_bytes: Vec<u8>,
    pub profile: u8,
    pub transcript_initial: Vec<u8>,
    pub construction_descriptor: Vec<u8>,
    pub public_words: Vec<LocalWordPublicWord>,
    pub expected_preprocessed_root: [u8; 32],
    pub relation_log: u32,
    pub eval_log: u32,
    pub quotient_degree_rows: usize,
    pub fri: SuccessorFriConfig,
}

pub fn build_local_word_reference_fixture() -> Result<LocalWordReferenceFixture, String> {
    let parameters = LocalWordProofParameters {
        relation_log: 11,
        eval_log: 16,
        quotient_degree_rows: 1 << 14,
        fri: SuccessorFriConfig {
            log_blowup: 2,
            final_log_degree: 3,
            fold_log: 2,
            query_orbit_log: 11,
            queries: 8,
            grind_bits: 0,
        },
    };
    parameters.validate()?;
    let program = LocalShaProgram {
        rows: vec![
            LocalShaOperation::Input { input: 0 },
            LocalShaOperation::Constant {
                literal: 0x0f0f_0f0f,
            },
            LocalShaOperation::Xor { a: 0, b: 1 },
        ],
        input_count: 1,
        copy_aliases: vec![],
        word_aliases: vec![],
    };
    let public_words = vec![LocalWordPublicWord {
        id: 1,
        row: 0,
        expected: 0x1234_5678,
    }];
    let bundle = LocalWordProverBundle {
        profile: 0,
        relation_rows: 1 << parameters.relation_log,
        transcript_initial: b"local-word-e2e-transcript-v1".to_vec(),
        construction_descriptor: b"local-word-e2e-construction-v1".to_vec(),
        program_bytes: vec![3],
        program: program.clone(),
        inputs: vec![public_words[0].expected],
        public_words: public_words.clone(),
    };
    let directory = std::env::temp_dir().join(format!(
        "shieldkit-local-word-reference-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("local-word fixture clock: {error}"))?
            .as_nanos(),
    ));
    std::fs::create_dir(&directory)
        .map_err(|error| format!("create local-word fixture: {error}"))?;
    let result = (|| -> Result<LocalWordReferenceFixture, String> {
        let wires = execute_local_sha_program(&program, &bundle.inputs)?;
        let permutation = compile_local_sha_word_copy_permutation_for_rows(
            &program,
            bundle.relation_rows,
        )?;
        let multiplicities = local_sha_table_multiplicities(&program, &wires)?;
        let relation =
            build_local_word_relation_matrices(&bundle, &wires, &permutation, &multiplicities)?;
        let expected_preprocessed = build_disk_matrix_commitment(
            "local-word:preprocessed",
            &relation.preprocessed,
            DiskColumnExtension::PublicRelation {
                eval_log: parameters.eval_log,
            },
            &directory.join("verifier-key-preprocessed"),
        )?;
        drop(relation);
        let proved = prove_local_word_bundle_with_parameters(
            bundle.clone(),
            &directory.join("prover"),
            parameters,
        )?;
        if proved.proof.preprocessed.root != expected_preprocessed.root {
            return Err("local-word fixture preprocessed root".into());
        }
        let proof_bytes =
            encode_local_word_sealed_proof_with_parameters(&proved.proof, parameters)?;
        let decoded = decode_local_word_sealed_proof_with_parameters(
            &proof_bytes,
            bundle.profile,
            &bundle.transcript_initial,
            &bundle.construction_descriptor,
            &public_words,
            expected_preprocessed.root,
            parameters,
        )?;
        verify_local_word_sealed_proof_with_parameters(
            &decoded,
            bundle.profile,
            &bundle.transcript_initial,
            &bundle.construction_descriptor,
            &public_words,
            expected_preprocessed.root,
            parameters,
        )?;
        Ok(LocalWordReferenceFixture {
            proof_bytes,
            profile: bundle.profile,
            transcript_initial: bundle.transcript_initial,
            construction_descriptor: bundle.construction_descriptor,
            public_words,
            expected_preprocessed_root: expected_preprocessed.root,
            relation_log: parameters.relation_log,
            eval_log: parameters.eval_log,
            quotient_degree_rows: parameters.quotient_degree_rows,
            fri: parameters.fri,
        })
    })();
    let cleanup = std::fs::remove_dir_all(&directory)
        .map_err(|error| format!("remove local-word fixture: {error}"));
    match (result, cleanup) {
        (Ok(fixture), Ok(())) => Ok(fixture),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Fold a canonical Circle/QM31 codeword using Stwo's pinned folding kernels.
/// ShieldKit owns the SHA commitments and wire format; this function owns no
/// transcript state and therefore cannot accidentally fork Fiat-Shamir.
pub fn successor_fri_fold_layers(
    natural_values: &[Qm31Value],
    folding_alphas: &[Qm31Value],
    log_blowup: u32,
    final_log_degree: u32,
) -> Result<SuccessorFriLayers, &'static str> {
    if !natural_values.len().is_power_of_two() || natural_values.len() < 4 {
        return Err("FRI input size");
    }
    if natural_values
        .iter()
        .flatten()
        .any(|value| (*value as u64) >= M31)
    {
        return Err("FRI input field");
    }
    let input_log_size = natural_values.len().ilog2();
    let final_log_domain = final_log_degree
        .checked_add(log_blowup)
        .ok_or("FRI final domain")?;
    if final_log_domain >= input_log_size {
        return Err("FRI fold count");
    }
    let expected_folds = (input_log_size - final_log_domain) as usize;
    if folding_alphas.len() != expected_folds {
        return Err("FRI alpha count");
    }

    let domain = CanonicCoset::new(input_log_size).circle_domain();
    let natural: CpuCircleEvaluation<SecureField, NaturalOrder> = CpuCircleEvaluation::new(
        domain,
        natural_values.iter().copied().map(qm31_to_secure).collect(),
    );
    let generic_circle = natural.bit_reverse();
    let circle: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::new(domain, generic_circle.values.into_iter().collect());
    let mut layers = vec![circle
        .values
        .to_vec()
        .into_iter()
        .map(secure_to_qm31)
        .collect()];
    let mut line = fold_circle_into_line_cpu(&circle, qm31_to_secure(folding_alphas[0]));

    for alpha in &folding_alphas[1..] {
        layers.push(
            line.values
                .to_vec()
                .into_iter()
                .map(secure_to_qm31)
                .collect(),
        );
        line = fold_line_cpu(&line, qm31_to_secure(*alpha));
    }
    if line.len().ilog2() != final_log_domain {
        return Err("FRI final domain");
    }
    let coefficients = line.interpolate().into_ordered_coefficients();
    let degree_bound = 1usize << final_log_degree;
    if coefficients[degree_bound..]
        .iter()
        .any(|value| secure_to_qm31(*value) != [0; 4])
    {
        return Err("FRI final degree");
    }
    Ok(SuccessorFriLayers {
        layers,
        final_coefficients: coefficients[..degree_bound]
            .iter()
            .copied()
            .map(secure_to_qm31)
            .collect(),
    })
}

/// O(n log n) Circle FFT low-degree extension on Stwo's canonical cosets.
/// Input and output are in natural CircleDomain order.
pub fn circle_lde(values: &[u32], log_blowup: u32) -> Vec<u32> {
    assert!(values.len().is_power_of_two());
    let trace_log = values.len().ilog2();
    assert!(trace_log >= 1);
    let trace_domain = CanonicCoset::new(trace_log).circle_domain();
    let natural: CpuCircleEvaluation<BaseField, NaturalOrder> = CpuCircleEvaluation::new(
        trace_domain,
        values
            .iter()
            .copied()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    );
    let evaluation = natural.bit_reverse();
    let polynomial = evaluation.interpolate();
    let eval_domain = CanonicCoset::new(trace_log + log_blowup).circle_domain();
    polynomial
        .evaluate(eval_domain)
        .bit_reverse()
        .values
        .into_iter()
        .map(|value| value.0)
        .collect()
}

fn logical_coset_values_to_circle_order(values: &[u32]) -> Vec<BaseField> {
    let logical: Vec<BaseField> = values
        .iter()
        .copied()
        .map(BaseField::from_u32_unchecked)
        .collect();
    stwo::core::utils::coset_order_to_circle_domain_order(&logical)
}

/// Interpolate one logical cyclic trace on the canonical Circle domain and
/// evaluate it on the successor LDE domain.
pub fn relation_trace_lde(values: &[u32], eval_log_size: u32) -> Vec<u32> {
    assert!(values.len().is_power_of_two());
    let relation_log = values.len().ilog2();
    assert!(eval_log_size > relation_log);
    let relation_domain = CanonicCoset::new(relation_log).circle_domain();
    let natural: CpuCircleEvaluation<BaseField, NaturalOrder> = CpuCircleEvaluation::new(
        relation_domain,
        logical_coset_values_to_circle_order(values),
    );
    let polynomial = natural.bit_reverse().interpolate();
    polynomial
        .evaluate(CanonicCoset::new(eval_log_size).circle_domain())
        .bit_reverse()
        .values
        .into_iter()
        .map(|value| value.0)
        .collect()
}

pub fn bit_reverse_m31_columns(columns: &mut [Vec<u32>]) {
    columns
        .par_iter_mut()
        .for_each(|column| stwo::core::utils::bit_reverse(column));
}

fn circle_eval_natural(poly: &CpuCirclePoly, log_size: u32) -> Vec<BaseField> {
    poly.evaluate(CanonicCoset::new(log_size).circle_domain())
        .bit_reverse()
        .values
}

fn fresh_m31() -> BaseField {
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("OS randomness for ZK seal");
        let candidate = u32::from_le_bytes(bytes);
        if candidate < M31 as u32 {
            return BaseField::from_u32_unchecked(candidate);
        }
    }
}

/// Seal one trace column as `w_hat = w + Z_H r` on a disjoint canonical coset.
///
/// `log_domain_expansion` is measured from the original trace rows. The mask
/// raises the polynomial into the next power-of-two degree bucket, so callers
/// need expansion 5 to retain an effective blowup of 16.
#[cfg(test)]
fn seal_circle_lde(values: &[u32], log_domain_expansion: u32, mask_log_size: u32) -> Vec<u32> {
    let coeffs = (0..1usize << mask_log_size).map(|_| fresh_m31()).collect();
    seal_circle_lde_with_coeffs(values, log_domain_expansion, coeffs)
}

/// Canonical successor membrane: `w_hat = w + Z_H r`, where `w` is the
/// logical cyclic trace, `H` is its canonical relation coset, and `r` has one
/// independently sampled coefficient per relation row. The extra degree bit
/// is explicit; `log_blowup` is measured from that sealed degree bucket.
pub fn seal_relation_trace_lde(values: &[u32], log_blowup: u32) -> Vec<u32> {
    assert!(values.len().is_power_of_two());
    let randomizer_coeffs = (0..values.len()).map(|_| fresh_m31()).collect();
    seal_circle_lde_with_coeffs(values, log_blowup + 1, randomizer_coeffs)
}

/// Seal a complete private table in parallel. Columns remain separate so the
/// prover can evaluate AIR offsets without transposing a half-gigabyte matrix.
pub fn seal_relation_trace_matrix_lde(columns: &[Vec<u32>], log_blowup: u32) -> Vec<Vec<u32>> {
    assert!(!columns.is_empty());
    let rows = columns[0].len();
    assert!(rows.is_power_of_two());
    assert!(columns.iter().all(|column| column.len() == rows));
    assert!(columns.iter().flatten().all(|value| (*value as u64) < M31));
    columns
        .par_iter()
        .map(|column| seal_relation_trace_lde(column, log_blowup))
        .collect()
}

pub fn seal_relation_trace_matrix_lde_bit_reversed(
    columns: &[Vec<u32>],
    log_blowup: u32,
) -> Vec<Vec<u32>> {
    let mut sealed = seal_relation_trace_matrix_lde(columns, log_blowup);
    bit_reverse_m31_columns(&mut sealed);
    sealed
}

pub(crate) fn canonical_tree_key(label: &str) -> [u8; 32] {
    assert!(!label.is_empty() && label.len() <= 96);
    sha256(&[b"ShieldKit/CanonicalMerkle/v1", label.as_bytes()])
}

fn matrix_leaf(tree_key: &[u8; 32], columns: &[Vec<u32>], row: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(tree_key);
    hasher.update((row as u32).to_be_bytes());
    for column in columns {
        hasher.update(column[row].to_le_bytes());
    }
    hasher.finalize().into()
}

pub(crate) fn raw_leaf(tree_key: &[u8; 32], index: usize, raw: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(tree_key);
    hasher.update((index as u32).to_be_bytes());
    hasher.update(raw);
    hasher.finalize().into()
}

pub(crate) fn matrix_parent(
    tree_key: &[u8; 32],
    level: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(tree_key);
    hasher.update([level]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub(crate) fn matrix_parent4(tree_key: &[u8; 32], level: u8, children: &[[u8; 32]; 4]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([2]);
    hasher.update(tree_key);
    hasher.update([level]);
    for child in children {
        hasher.update(child);
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalMerkleMultiProof {
    pub indices: Vec<usize>,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct CanonicalMerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

impl CanonicalMerkleTree {
    fn from_leaves(label: &str, leaves: Vec<[u8; 32]>) -> Self {
        assert!(leaves.len() >= 2 && leaves.len().is_power_of_two());
        let tree_key = canonical_tree_key(label);
        let mut layers = vec![leaves];
        let mut level = 0u8;
        while layers.last().unwrap().len() > 1 {
            let next = layers
                .last()
                .unwrap()
                .par_chunks_exact(2)
                .map(|pair| matrix_parent(&tree_key, level, &pair[0], &pair[1]))
                .collect();
            layers.push(next);
            level += 1;
        }
        Self { layers }
    }

    pub fn from_qm31(label: &str, values: &[Qm31Value]) -> Self {
        assert!(values.len() >= 2 && values.len().is_power_of_two());
        let tree_key = canonical_tree_key(label);
        let leaves = values
            .par_iter()
            .enumerate()
            .map(|(index, value)| qm31_leaf(&tree_key, index, value))
            .collect();
        Self::from_leaves(label, leaves)
    }

    pub fn from_matrix(label: &str, columns: &[Vec<u32>]) -> Self {
        assert!(!columns.is_empty());
        let rows = columns[0].len();
        assert!(rows >= 2 && rows.is_power_of_two());
        assert!(columns.iter().all(|column| column.len() == rows));
        let tree_key = canonical_tree_key(label);
        let leaves = (0..rows)
            .into_par_iter()
            .map(|row| matrix_leaf(&tree_key, columns, row))
            .collect();
        Self::from_leaves(label, leaves)
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    pub fn row_count(&self) -> usize {
        self.layers[0].len()
    }

    pub fn multiproof(&self, indices: &[usize]) -> CanonicalMerkleMultiProof {
        assert!(!indices.is_empty());
        let mut frontier = indices.to_vec();
        frontier.sort_unstable();
        assert!(frontier.iter().all(|index| *index < self.row_count()));
        assert!(frontier.windows(2).all(|pair| pair[0] != pair[1]));
        let original = frontier.clone();
        let mut siblings = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            for &index in &frontier {
                let sibling = index ^ 1;
                if frontier.binary_search(&sibling).is_err() {
                    siblings.push(layer[sibling]);
                }
            }
            frontier = frontier.into_iter().map(|index| index >> 1).collect();
            frontier.dedup();
        }
        CanonicalMerkleMultiProof {
            indices: original,
            siblings,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalMerkleTree4 {
    layers: Vec<Vec<[u8; 32]>>,
}

impl CanonicalMerkleTree4 {
    fn from_leaves(label: &str, leaves: Vec<[u8; 32]>) -> Self {
        assert!(
            leaves.len() >= 4 && leaves.len().is_power_of_two() && leaves.len().ilog2() % 2 == 0
        );
        let tree_key = canonical_tree_key(label);
        let mut layers = vec![leaves];
        let mut level = 0u8;
        while layers.last().unwrap().len() > 1 {
            let next = layers
                .last()
                .unwrap()
                .par_chunks_exact(4)
                .map(|children| matrix_parent4(&tree_key, level, children.try_into().unwrap()))
                .collect();
            layers.push(next);
            level += 1;
        }
        Self { layers }
    }

    pub fn from_qm31(label: &str, values: &[Qm31Value]) -> Self {
        let tree_key = canonical_tree_key(label);
        let leaves = values
            .par_iter()
            .enumerate()
            .map(|(index, value)| qm31_leaf(&tree_key, index, value))
            .collect::<Vec<_>>();
        Self::from_leaves(label, leaves)
    }

    pub fn from_matrix(label: &str, columns: &[Vec<u32>]) -> Self {
        assert!(!columns.is_empty());
        let rows = columns[0].len();
        assert!(columns.iter().all(|column| column.len() == rows));
        let tree_key = canonical_tree_key(label);
        let leaves = (0..rows)
            .into_par_iter()
            .map(|row| matrix_leaf(&tree_key, columns, row))
            .collect();
        Self::from_leaves(label, leaves)
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    pub fn multiproof(&self, indices: &[usize]) -> CanonicalMerkleMultiProof {
        assert!(!indices.is_empty());
        let mut frontier = indices.to_vec();
        frontier.sort_unstable();
        assert!(frontier.iter().all(|index| *index < self.layers[0].len()));
        assert!(frontier.windows(2).all(|pair| pair[0] != pair[1]));
        let original = frontier.clone();
        let mut siblings = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            let present = frontier
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            let mut parents = frontier.iter().map(|index| index >> 2).collect::<Vec<_>>();
            parents.dedup();
            for parent in &parents {
                for child in 0..4 {
                    let index = parent * 4 + child;
                    if !present.contains(&index) {
                        siblings.push(layer[index]);
                    }
                }
            }
            frontier = parents;
        }
        CanonicalMerkleMultiProof {
            indices: original,
            siblings,
        }
    }
}

/// SHA-256 row commitment for an already sealed column-major matrix.
pub fn sealed_matrix_root(label: &str, columns: &[Vec<u32>]) -> [u8; 32] {
    CanonicalMerkleTree::from_matrix(label, columns).root()
}

pub fn encode_matrix_rows(columns: &[Vec<u32>], indices: &[usize]) -> Vec<Vec<u8>> {
    assert!(!columns.is_empty());
    let row_count = columns[0].len();
    assert!(columns.iter().all(|column| column.len() == row_count));
    indices
        .iter()
        .map(|index| {
            assert!(*index < row_count);
            columns
                .iter()
                .flat_map(|column| column[*index].to_le_bytes())
                .collect()
        })
        .collect()
}

pub fn verify_matrix_multiproof(
    label: &str,
    rows: &[(usize, Vec<u8>)],
    proof: &CanonicalMerkleMultiProof,
    row_count: usize,
    root: [u8; 32],
) -> bool {
    use std::collections::BTreeMap;

    if rows.is_empty() || row_count < 2 || !row_count.is_power_of_two() {
        return false;
    }
    let indices: Vec<usize> = rows.iter().map(|(index, _)| *index).collect();
    if indices != proof.indices
        || indices.iter().any(|index| *index >= row_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    let tree_key = canonical_tree_key(label);
    let mut frontier: BTreeMap<usize, [u8; 32]> = rows
        .iter()
        .map(|(index, raw)| (*index, raw_leaf(&tree_key, *index, raw)))
        .collect();
    let mut sibling_cursor = 0usize;
    for level in 0..row_count.ilog2() {
        let mut next = BTreeMap::new();
        for (&index, &value) in &frontier {
            if index & 1 == 1 && frontier.contains_key(&(index ^ 1)) {
                continue;
            }
            let sibling = match frontier.get(&(index ^ 1)) {
                Some(value) => *value,
                None => match proof.siblings.get(sibling_cursor) {
                    Some(value) => {
                        sibling_cursor += 1;
                        *value
                    }
                    None => return false,
                },
            };
            let parent = if index & 1 == 0 {
                matrix_parent(&tree_key, level as u8, &value, &sibling)
            } else {
                matrix_parent(&tree_key, level as u8, &sibling, &value)
            };
            next.insert(index >> 1, parent);
        }
        frontier = next;
    }
    sibling_cursor == proof.siblings.len()
        && frontier.len() == 1
        && frontier.get(&0).copied() == Some(root)
}

pub fn verify_matrix_multiproof4(
    label: &str,
    rows: &[(usize, Vec<u8>)],
    proof: &CanonicalMerkleMultiProof,
    row_count: usize,
    root: [u8; 32],
) -> bool {
    use std::collections::BTreeMap;

    if rows.is_empty()
        || row_count < 4
        || !row_count.is_power_of_two()
        || row_count.ilog2() % 2 != 0
    {
        return false;
    }
    let indices: Vec<usize> = rows.iter().map(|(index, _)| *index).collect();
    if indices != proof.indices
        || indices.iter().any(|index| *index >= row_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    let tree_key = canonical_tree_key(label);
    let mut frontier: BTreeMap<usize, [u8; 32]> = rows
        .iter()
        .map(|(index, raw)| (*index, raw_leaf(&tree_key, *index, raw)))
        .collect();
    let mut sibling_cursor = 0usize;
    for level in 0..row_count.ilog2() / 2 {
        let mut parents = frontier.keys().map(|index| index >> 2).collect::<Vec<_>>();
        parents.dedup();
        let mut next = BTreeMap::new();
        for parent in parents {
            let mut children = [[0u8; 32]; 4];
            for child in 0..4 {
                let index = parent * 4 + child;
                children[child] = match frontier.get(&index) {
                    Some(value) => *value,
                    None => match proof.siblings.get(sibling_cursor) {
                        Some(value) => {
                            sibling_cursor += 1;
                            *value
                        }
                        None => return false,
                    },
                };
            }
            next.insert(parent, matrix_parent4(&tree_key, level as u8, &children));
        }
        frontier = next;
    }
    sibling_cursor == proof.siblings.len()
        && frontier.len() == 1
        && frontier.get(&0).copied() == Some(root)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorMatrixOpening {
    pub root: [u8; 32],
    pub row_width: usize,
    pub indices: Vec<usize>,
    pub rows: Vec<Vec<u8>>,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorSealedProof {
    pub profile: u8,
    pub air_program_hash: [u8; 32],
    pub transcript_initial: Vec<u8>,
    pub preprocessed: SuccessorMatrixOpening,
    pub sha: SuccessorMatrixOpening,
    pub sha_aux: SuccessorMatrixOpening,
    pub bus: SuccessorMatrixOpening,
    pub quotient: SuccessorMatrixOpening,
    pub fri_mask: SuccessorMatrixOpening,
    pub constraint_alpha: Qm31Value,
    pub constraint_transcript_digest: [u8; 32],
    pub constraint_coefficient_seed: [u8; 32],
    pub partial_challenges: [[u32; POOL_AIR_HORNER_LANES]; 8],
    pub compression_challenges: [Qm31Value; POOL_AIR_HORNER_LANES],
    pub composition_partials: Vec<[[u32; POOL_AIR_HORNER_LANES]; 8]>,
    pub batch_beta: Qm31Value,
    pub fri_transcript_digest: [u8; 32],
    pub fri_alphas: Vec<Qm31Value>,
    pub query_digest: [u8; 32],
    pub queries: Vec<usize>,
    pub fri: SuccessorFriProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorProveResult {
    pub proof: SuccessorSealedProof,
    pub quotient_degree_bound: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalSuccessorSealedProof {
    pub profile: u8,
    pub air_program_hash: [u8; 32],
    pub transcript_initial: Vec<u8>,
    pub preprocessed: SuccessorMatrixOpening,
    pub sha: SuccessorMatrixOpening,
    pub sha_segments: Vec<VerticalShaSegment>,
    pub boundary: SuccessorMatrixOpening,
    pub interaction: SuccessorMatrixOpening,
    pub quotient: SuccessorMatrixOpening,
    pub fri_mask: SuccessorMatrixOpening,
    pub boundary_beta: [u32; VERTICAL_AIR_HORNER_LANES],
    pub boundary_gamma: [u32; VERTICAL_AIR_HORNER_LANES],
    pub boundary_inverse_products: [u32; VERTICAL_AIR_HORNER_LANES],
    pub boundary_transcript_digest: [u8; 32],
    pub constraint_alpha: Qm31Value,
    pub constraint_coefficient_seed: [u8; 32],
    pub horner_challenges: [u32; VERTICAL_AIR_HORNER_LANES],
    pub compression_challenges: [Qm31Value; VERTICAL_AIR_HORNER_LANES],
    pub batch_beta: Qm31Value,
    pub fri_transcript_digest: [u8; 32],
    pub fri_alphas: Vec<Qm31Value>,
    pub query_digest: [u8; 32],
    pub queries: Vec<usize>,
    pub composition_lanes: Vec<[u32; VERTICAL_AIR_HORNER_LANES]>,
    pub fri: SuccessorFriProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalShaSegment {
    pub root: [u8; 32],
    pub groups: Vec<VerticalShaGroup>,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalShaGroup {
    pub index: usize,
    pub root: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerticalSuccessorProveResult {
    pub proof: VerticalSuccessorSealedProof,
    pub quotient_degree_bound: usize,
}

pub const VERTICAL_SUCCESSOR_FRI_CONFIG: SuccessorFriConfig = SuccessorFriConfig {
    log_blowup: 4,
    final_log_degree: 3,
    fold_log: 1,
    query_orbit_log: 1,
    queries: 28,
    grind_bits: 20,
};

pub const LOCAL_WORD_FRI_CONFIG: SuccessorFriConfig = SuccessorFriConfig {
    log_blowup: 4,
    final_log_degree: 3,
    fold_log: 2,
    query_orbit_log: 17,
    queries: 28,
    grind_bits: 20,
};

const PREPROCESSED_ORACLE_LABELS: [&str; 3] = [
    "oracle:preprocessed:deposit",
    "oracle:preprocessed:withdraw-full",
    "oracle:preprocessed:withdraw-change",
];
const SHA_ORACLE_LABEL: &str = "oracle:sha";
const SHA_AUX_ORACLE_LABEL: &str = "oracle:sha-aux";
const BUS_ORACLE_LABEL: &str = "oracle:bus";
const QUOTIENT_ORACLE_LABEL: &str = "oracle:quotient";
const FRI_MASK_ORACLE_LABEL: &str = "oracle:fri-mask";

const VERTICAL_PREPROCESSED_ORACLE_LABELS: [&str; 3] = [
    "vertical:preprocessed:deposit",
    "vertical:preprocessed:withdraw-full",
    "vertical:preprocessed:withdraw-change",
];
const VERTICAL_SHA_ORACLE_LABEL: &str = "vertical:sha";
const VERTICAL_BOUNDARY_ORACLE_LABEL: &str = "vertical:boundary";
const VERTICAL_INTERACTION_ORACLE_LABEL: &str = "vertical:interaction";
const VERTICAL_QUOTIENT_ORACLE_LABEL: &str = "vertical:quotient";
const VERTICAL_FRI_MASK_ORACLE_LABEL: &str = "vertical:fri-mask";
fn qm31_values_to_columns(values: &[Qm31Value]) -> Vec<Vec<u32>> {
    (0..4)
        .map(|coordinate| values.iter().map(|value| value[coordinate]).collect())
        .collect()
}

fn matrix_opening(
    tree: &CanonicalMerkleTree,
    columns: &[Vec<u32>],
    indices: &[usize],
) -> SuccessorMatrixOpening {
    let merkle = tree.multiproof(indices);
    SuccessorMatrixOpening {
        root: tree.root(),
        row_width: columns.len() * 4,
        indices: merkle.indices,
        rows: encode_matrix_rows(columns, indices),
        siblings: merkle.siblings,
    }
}

const VERTICAL_SHA_SEGMENT_LOG: usize = 18;
const VERTICAL_SHA_SEGMENTS: usize = 64;
const VERTICAL_SHA_GROUP_LOG: usize = 9;
const VERTICAL_SHA_GROUPS_PER_SEGMENT: usize =
    1 << (VERTICAL_SHA_SEGMENT_LOG - VERTICAL_SHA_GROUP_LOG);

fn vertical_sha_opening(
    tree: &CanonicalMerkleTree,
    columns: &[Vec<u32>],
    indices: &[usize],
) -> (SuccessorMatrixOpening, Vec<VerticalShaSegment>) {
    assert_eq!(tree.row_count(), 1 << 24);
    assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
    let opening = SuccessorMatrixOpening {
        root: tree.root(),
        row_width: columns.len() * 4,
        indices: indices.to_vec(),
        rows: encode_matrix_rows(columns, indices),
        siblings: Vec::new(),
    };
    let segments = (0..VERTICAL_SHA_SEGMENTS)
        .map(|segment| {
            let start = segment << VERTICAL_SHA_SEGMENT_LOG;
            let end = start + (1 << VERTICAL_SHA_SEGMENT_LOG);
            let segment_indices: Vec<usize> = indices
                .iter()
                .copied()
                .filter(|index| *index >= start && *index < end)
                .collect();
            let mut group_indices: Vec<usize> = segment_indices
                .iter()
                .map(|index| (index - start) >> VERTICAL_SHA_GROUP_LOG)
                .collect();
            group_indices.dedup();
            let groups = group_indices
                .iter()
                .map(|group| {
                    let group_start = start + (group << VERTICAL_SHA_GROUP_LOG);
                    let group_end = group_start + (1 << VERTICAL_SHA_GROUP_LOG);
                    let mut frontier: Vec<usize> = segment_indices
                        .iter()
                        .copied()
                        .filter(|index| *index >= group_start && *index < group_end)
                        .collect();
                    let mut siblings = Vec::new();
                    for level in 0..VERTICAL_SHA_GROUP_LOG {
                        for &index in &frontier {
                            let sibling = index ^ 1;
                            if frontier.binary_search(&sibling).is_err() {
                                siblings.push(tree.layers[level][sibling]);
                            }
                        }
                        frontier = frontier.into_iter().map(|index| index >> 1).collect();
                        frontier.dedup();
                    }
                    let global_group =
                        (segment << (VERTICAL_SHA_SEGMENT_LOG - VERTICAL_SHA_GROUP_LOG)) + group;
                    assert_eq!(frontier, vec![global_group]);
                    VerticalShaGroup {
                        index: *group,
                        root: tree.layers[VERTICAL_SHA_GROUP_LOG][global_group],
                        siblings,
                    }
                })
                .collect();
            let mut frontier: Vec<usize> = group_indices
                .iter()
                .map(|group| {
                    (segment << (VERTICAL_SHA_SEGMENT_LOG - VERTICAL_SHA_GROUP_LOG)) + group
                })
                .collect();
            let mut siblings = Vec::new();
            for level in VERTICAL_SHA_GROUP_LOG..VERTICAL_SHA_SEGMENT_LOG {
                for &index in &frontier {
                    let sibling = index ^ 1;
                    if frontier.binary_search(&sibling).is_err() {
                        siblings.push(tree.layers[level][sibling]);
                    }
                }
                frontier = frontier.into_iter().map(|index| index >> 1).collect();
                frontier.dedup();
            }
            if !frontier.is_empty() {
                assert_eq!(frontier, vec![segment]);
            }
            VerticalShaSegment {
                root: tree.layers[VERTICAL_SHA_SEGMENT_LOG][segment],
                groups,
                siblings,
            }
        })
        .collect();
    (opening, segments)
}

fn sorted_unique(mut values: Vec<usize>) -> Vec<usize> {
    values.sort_unstable();
    values.dedup();
    values
}

fn canonical_merkle_program(indices: &[usize], sibling_count: usize, row_count: usize) -> Vec<u8> {
    assert!(row_count >= 2 && row_count.is_power_of_two() && !indices.is_empty());
    assert!(indices.iter().all(|index| *index < row_count));
    assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
    let mut frontier = indices.to_vec();
    let mut consumed_siblings = 0usize;
    let mut program = Vec::new();
    for level in 0..row_count.ilog2() {
        let present: std::collections::HashSet<usize> = frontier.iter().copied().collect();
        let mut next = Vec::new();
        for index in &frontier {
            if index & 1 == 1 && present.contains(&(index ^ 1)) {
                continue;
            }
            let from_proof = !present.contains(&(index ^ 1));
            if from_proof {
                consumed_siblings += 1;
            }
            program.push(((level as u8) << 2) | (((index & 1) as u8) << 1) | from_proof as u8);
            next.push(index >> 1);
        }
        next.dedup();
        frontier = next;
    }
    assert_eq!(frontier, vec![0]);
    assert_eq!(consumed_siblings, sibling_count);
    assert_eq!(program.len(), indices.len() + sibling_count - 1);
    program
}

/// The AIR program is the sole owner of the oracle opening schedule.  This
/// deliberately avoids a second, hand-maintained list of SHA/bus offsets in
/// either the prover or verifier.
pub fn successor_oracle_opening_indices(
    program: &PoolAirProgram,
    oracle: u8,
    queries: &[usize],
    relation_trace_log: u32,
    eval_log: u32,
) -> Vec<usize> {
    assert!(oracle < 4 && relation_trace_log < eval_log);
    let mut offsets: Vec<isize> = program
        .nodes
        .iter()
        .filter_map(|node| match *node {
            PoolAirNode::Input {
                oracle: node_oracle,
                offset,
                ..
            } if node_oracle == oracle => Some(offset as isize),
            _ => None,
        })
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    sorted_unique(
        queries
            .iter()
            .flat_map(|query| {
                offsets.iter().map(|offset| {
                    if *offset == 0 {
                        *query
                    } else {
                        stwo::core::utils::offset_bit_reversed_circle_domain_index(
                            *query,
                            relation_trace_log,
                            eval_log,
                            *offset,
                        )
                    }
                })
            })
            .collect(),
    )
}

fn absorb_successor_oracle_roots(
    transcript: &mut SuccessorTranscript,
    air_program_hash: &[u8; 32],
    preprocessed_root: &[u8; 32],
    sha_root: &[u8; 32],
    sha_aux_root: &[u8; 32],
    bus_root: &[u8; 32],
) {
    transcript.absorb("air-program", air_program_hash);
    transcript.absorb("preprocessed-root", preprocessed_root);
    transcript.absorb("sha-root", sha_root);
    transcript.absorb("sha-aux-root", sha_aux_root);
    transcript.absorb("bus-root", bus_root);
}

fn batch_successor_oracles_natural(
    sha: &[Vec<u32>],
    sha_aux: &[Vec<u32>],
    bus: &[Vec<u32>],
    quotient: &[Qm31Value],
    fri_mask: &[Qm31Value],
    beta: Qm31Value,
) -> Vec<Qm31Value> {
    let rows = quotient.len();
    assert!(rows.is_power_of_two() && fri_mask.len() == rows);
    let log_rows = rows.ilog2();
    let beta = qm31_to_secure(beta);
    let mut power = SecureField::from_u32_unchecked(1, 0, 0, 0);
    let coefficients: Vec<SecureField> = (0..sha.len() + sha_aux.len() + bus.len() + 1)
        .map(|_| {
            let current = power;
            power *= beta;
            current
        })
        .collect();
    (0..rows)
        .into_par_iter()
        .map(|natural_row| {
            let row = bit_reverse_index(natural_row, log_rows);
            let mut accumulator = qm31_to_secure(fri_mask[row]);
            let mut coefficient = 0usize;
            for columns in [sha, sha_aux, bus] {
                for column in columns {
                    accumulator +=
                        coefficients[coefficient] * BaseField::from_u32_unchecked(column[row]);
                    coefficient += 1;
                }
            }
            accumulator += coefficients[coefficient] * qm31_to_secure(quotient[row]);
            secure_to_qm31(accumulator)
        })
        .collect()
}

pub fn prove_successor_bundle(
    bundle: SuccessorProverBundle,
) -> Result<SuccessorProveResult, String> {
    if bundle.trace_rows != 8192 {
        return Err("successor trace geometry".into());
    }
    let trace_log = bundle.trace_rows.ilog2();
    let eval_log = 20u32;
    let SuccessorProverBundle {
        transcript_initial,
        program_bytes,
        program,
        public_inputs,
        sha,
        sha_aux,
        bus,
        preprocessed,
        ..
    } = bundle;
    let sha_lde = seal_relation_trace_matrix_lde_bit_reversed(&sha, 6);
    let sha_aux_lde = seal_relation_trace_matrix_lde_bit_reversed(&sha_aux, 6);
    let bus_lde = seal_relation_trace_matrix_lde_bit_reversed(&bus, 6);
    let mut preprocessed_lde: Vec<Vec<u32>> = preprocessed
        .par_iter()
        .map(|column| relation_trace_lde(column, eval_log))
        .collect();
    bit_reverse_m31_columns(&mut preprocessed_lde);

    let preprocessed_label = PREPROCESSED_ORACLE_LABELS[program.profile as usize];
    let preprocessed_tree = CanonicalMerkleTree::from_matrix(preprocessed_label, &preprocessed_lde);
    let sha_tree = CanonicalMerkleTree::from_matrix(SHA_ORACLE_LABEL, &sha_lde);
    let sha_aux_tree = CanonicalMerkleTree::from_matrix(SHA_AUX_ORACLE_LABEL, &sha_aux_lde);
    let bus_tree = CanonicalMerkleTree::from_matrix(BUS_ORACLE_LABEL, &bus_lde);
    let air_program_hash = sha256(&[&program_bytes]);
    let mut transcript = SuccessorTranscript::new(&transcript_initial);
    absorb_successor_oracle_roots(
        &mut transcript,
        &air_program_hash,
        &preprocessed_tree.root(),
        &sha_tree.root(),
        &sha_aux_tree.root(),
        &bus_tree.root(),
    );
    let constraint_alpha = transcript.challenge_qm31("constraint-alpha");
    let constraint_transcript_digest = transcript.digest();
    let constraint_coefficient_seed = pool_air_coefficient_seed(constraint_alpha);
    let composition = pool_composition_lde_bit_reversed(
        &program,
        &public_inputs,
        PoolAirOracleLdes {
            sha: &sha_lde,
            sha_aux: &sha_aux_lde,
            bus: &bus_lde,
            preprocessed: &preprocessed_lde,
        },
        trace_log,
        constraint_coefficient_seed,
    );
    let quotient = divide_composition_by_trace_zerofier_bit_reversed(&composition, trace_log);
    let quotient_degree_bound = qm31_circle_degree_bound_bit_reversed(&quotient);
    if quotient_degree_bound > 1 << 15 {
        return Err(format!("successor quotient degree {quotient_degree_bound}"));
    }
    let quotient_columns = qm31_values_to_columns(&quotient);
    let quotient_tree = CanonicalMerkleTree::from_matrix(QUOTIENT_ORACLE_LABEL, &quotient_columns);
    transcript.absorb("quotient-root", &quotient_tree.root());

    let mut fri_mask_natural = fresh_qm31_lde(1 << 15, 5);
    let mut fri_mask = fri_mask_natural.clone();
    stwo::core::utils::bit_reverse(&mut fri_mask);
    let fri_mask_columns = qm31_values_to_columns(&fri_mask);
    let fri_mask_tree = CanonicalMerkleTree::from_matrix(FRI_MASK_ORACLE_LABEL, &fri_mask_columns);
    transcript.absorb("fri-mask-root", &fri_mask_tree.root());
    let beta = transcript.challenge_qm31("batch-beta");
    let fri_transcript_digest = transcript.digest();
    let mut fri_manifest_transcript = transcript.clone();
    let batch = batch_successor_oracles_natural(
        &sha_lde,
        &sha_aux_lde,
        &bus_lde,
        &quotient,
        &fri_mask,
        beta,
    );
    // The natural mask vector is no longer needed after the batch is formed.
    fri_mask_natural.clear();
    let fri = prove_successor_fri(&batch, &mut transcript, SuccessorFriConfig::PRODUCTION)
        .map_err(str::to_owned)?;
    let mut fri_alphas = Vec::with_capacity(fri.layers.len());
    for (round, layer) in fri.layers.iter().enumerate() {
        fri_manifest_transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        fri_alphas.push(fri_manifest_transcript.challenge_qm31(&format!("fri-alpha:{round}")));
    }
    fri_manifest_transcript.absorb("fri-final", &encode_qm31_values(&fri.final_coefficients));
    if !fri_manifest_transcript
        .accept_grind(SuccessorFriConfig::PRODUCTION.grind_bits, fri.grind_nonce)
    {
        return Err("successor FRI manifest grind".into());
    }
    let query_digest = fri_manifest_transcript.digest();
    let queries = fri_manifest_transcript
        .query_indices(1 << eval_log, SuccessorFriConfig::PRODUCTION.queries);
    if queries != transcript.query_indices(1 << eval_log, SuccessorFriConfig::PRODUCTION.queries) {
        return Err("successor FRI manifest queries".into());
    }
    let sha_indices = successor_oracle_opening_indices(&program, 0, &queries, trace_log, eval_log);
    let aux_indices = successor_oracle_opening_indices(&program, 1, &queries, trace_log, eval_log);
    let bus_indices = successor_oracle_opening_indices(&program, 2, &queries, trace_log, eval_log);
    let preprocessed_indices =
        successor_oracle_opening_indices(&program, 3, &queries, trace_log, eval_log);
    let current_indices = sorted_unique(queries.clone());
    let partial_ranges = pool_air_partial_ranges(&program)?;
    let partial_challenges = pool_air_partial_challenges(constraint_coefficient_seed);
    let compression_challenges = pool_air_compression_challenges(constraint_coefficient_seed);
    let partial_oracles = PoolAirOracleLdes {
        sha: &sha_lde,
        sha_aux: &sha_aux_lde,
        bus: &bus_lde,
        preprocessed: &preprocessed_lde,
    };
    let composition_partials: Vec<[[u32; POOL_AIR_HORNER_LANES]; 8]> = current_indices
        .par_iter()
        .map(|row| {
            let residuals =
                evaluate_pool_air_program(&program, &public_inputs, |oracle, column, offset| {
                    let location = if offset == 0 {
                        *row
                    } else {
                        stwo::core::utils::offset_bit_reversed_circle_domain_index(
                            *row,
                            trace_log,
                            eval_log,
                            offset as isize,
                        )
                    };
                    partial_oracles.columns(oracle)[column as usize][location]
                });
            pool_air_horner_partials(&residuals, &partial_challenges, &partial_ranges)
        })
        .collect();
    let proof = SuccessorSealedProof {
        profile: program.profile,
        air_program_hash,
        transcript_initial,
        preprocessed: matrix_opening(&preprocessed_tree, &preprocessed_lde, &preprocessed_indices),
        sha: matrix_opening(&sha_tree, &sha_lde, &sha_indices),
        sha_aux: matrix_opening(&sha_aux_tree, &sha_aux_lde, &aux_indices),
        bus: matrix_opening(&bus_tree, &bus_lde, &bus_indices),
        quotient: matrix_opening(&quotient_tree, &quotient_columns, &current_indices),
        fri_mask: matrix_opening(&fri_mask_tree, &fri_mask_columns, &current_indices),
        constraint_alpha,
        constraint_transcript_digest,
        constraint_coefficient_seed,
        partial_challenges,
        compression_challenges,
        composition_partials,
        batch_beta: beta,
        fri_transcript_digest,
        fri_alphas,
        query_digest,
        queries,
        fri,
    };
    Ok(SuccessorProveResult {
        proof,
        quotient_degree_bound,
    })
}

fn absorb_vertical_base_roots(
    transcript: &mut VerticalTranscript,
    air_program_hash: &[u8; 32],
    preprocessed_root: &[u8; 32],
    sha_root: &[u8; 32],
    boundary_root: &[u8; 32],
) {
    transcript.absorb("vertical-air-program", air_program_hash);
    transcript.absorb("vertical-preprocessed-root", preprocessed_root);
    transcript.absorb("vertical-sha-root", sha_root);
    transcript.absorb("vertical-boundary-root", boundary_root);
}

fn vertical_boundary_challenges(
    transcript: &mut VerticalTranscript,
) -> (
    [u32; VERTICAL_AIR_HORNER_LANES],
    [u32; VERTICAL_AIR_HORNER_LANES],
) {
    let beta = std::array::from_fn(|lane| {
        transcript.challenge_qm31(&format!("vertical-boundary-beta-{lane}"))[0]
    });
    let gamma = std::array::from_fn(|lane| {
        transcript.challenge_qm31(&format!("vertical-boundary-gamma-{lane}"))[0]
    });
    (beta, gamma)
}

fn build_vertical_boundary_interaction(
    rows: usize,
    boundary: &[Vec<u32>],
    cells: &[VerticalPublicCell],
    beta: &[u32; VERTICAL_AIR_HORNER_LANES],
    gamma: &[u32; VERTICAL_AIR_HORNER_LANES],
) -> Result<(Vec<Vec<u32>>, [u32; VERTICAL_AIR_HORNER_LANES]), String> {
    let by_row: std::collections::HashMap<usize, (usize, usize)> = cells
        .iter()
        .enumerate()
        .map(|(index, cell)| (cell.row, (index + 1, cell.column)))
        .collect();
    let mut inverse_products = [0u32; VERTICAL_AIR_HORNER_LANES];
    let mut columns = Vec::with_capacity(VERTICAL_AIR_HORNER_LANES);
    for lane in 0..VERTICAL_AIR_HORNER_LANES {
        let mut public_product = 1u32;
        for (index, cell) in cells.iter().enumerate() {
            let factor = add_m31_fast(
                add_m31_fast(gamma[lane], (index + 1) as u32),
                mul_m31_fast(beta[lane], cell.value),
            );
            public_product = mul_m31_fast(public_product, factor);
        }
        if public_product == 0 {
            return Err("vertical boundary zero product".into());
        }
        inverse_products[lane] = inv_m(public_product as u64) as u32;
        let mut column = vec![0u32; rows];
        column[0] = 1;
        for row in 0..rows - 1 {
            let factor = match by_row.get(&row) {
                Some((id, boundary_column)) => add_m31_fast(
                    add_m31_fast(gamma[lane], *id as u32),
                    mul_m31_fast(beta[lane], boundary[*boundary_column][row]),
                ),
                None => 1,
            };
            column[row + 1] = mul_m31_fast(column[row], factor);
        }
        if mul_m31_fast(column[rows - 1], inverse_products[lane]) != 1 {
            return Err("vertical boundary product".into());
        }
        columns.push(column);
    }
    Ok((columns, inverse_products))
}

pub fn prove_vertical_successor_bundle(
    bundle: VerticalSuccessorProverBundle,
) -> Result<VerticalSuccessorProveResult, String> {
    if bundle.trace_rows != 1 << 18 {
        return Err("vertical successor trace geometry".into());
    }
    let trace_log = 18u32;
    let eval_log = 24u32;
    let VerticalSuccessorProverBundle {
        transcript_initial,
        program_bytes,
        program,
        mut base_public_inputs,
        public_cells,
        sha,
        boundary,
        preprocessed,
        ..
    } = bundle;
    let sha_lde = seal_relation_trace_matrix_lde_bit_reversed(&sha, 5);
    let boundary_lde = seal_relation_trace_matrix_lde_bit_reversed(&boundary, 5);
    let mut preprocessed_lde: Vec<Vec<u32>> = preprocessed
        .par_iter()
        .map(|column| relation_trace_lde(column, eval_log))
        .collect();
    bit_reverse_m31_columns(&mut preprocessed_lde);

    let preprocessed_label = VERTICAL_PREPROCESSED_ORACLE_LABELS[program.profile as usize];
    let preprocessed_tree = CanonicalMerkleTree::from_matrix(preprocessed_label, &preprocessed_lde);
    let sha_tree = CanonicalMerkleTree::from_matrix(VERTICAL_SHA_ORACLE_LABEL, &sha_lde);
    let boundary_tree =
        CanonicalMerkleTree::from_matrix(VERTICAL_BOUNDARY_ORACLE_LABEL, &boundary_lde);
    let air_program_hash = sha256(&[&program_bytes]);
    let mut transcript = VerticalTranscript::new(&transcript_initial);
    absorb_vertical_base_roots(
        &mut transcript,
        &air_program_hash,
        &preprocessed_tree.root(),
        &sha_tree.root(),
        &boundary_tree.root(),
    );
    let (boundary_beta, boundary_gamma) = vertical_boundary_challenges(&mut transcript);
    let boundary_transcript_digest = transcript.digest();
    let (interaction, inverse_products) = build_vertical_boundary_interaction(
        1 << trace_log,
        &boundary,
        &public_cells,
        &boundary_beta,
        &boundary_gamma,
    )?;
    for lane in 0..VERTICAL_AIR_HORNER_LANES {
        base_public_inputs.extend_from_slice(&[
            boundary_beta[lane],
            boundary_gamma[lane],
            inverse_products[lane],
        ]);
    }
    if base_public_inputs.len() != program.public_input_count {
        return Err("vertical successor derived public inputs".into());
    }
    let interaction_lde = seal_relation_trace_matrix_lde_bit_reversed(&interaction, 5);
    let interaction_tree =
        CanonicalMerkleTree::from_matrix(VERTICAL_INTERACTION_ORACLE_LABEL, &interaction_lde);
    transcript.absorb("vertical-interaction-root", &interaction_tree.root());

    let constraint_alpha = transcript.challenge_qm31("vertical-constraint-alpha");
    let constraint_coefficient_seed = pool_air_coefficient_seed(constraint_alpha);
    let composition = vertical_composition_lde_bit_reversed(
        &program,
        &base_public_inputs,
        PoolAirOracleLdes {
            sha: &sha_lde,
            sha_aux: &boundary_lde,
            bus: &interaction_lde,
            preprocessed: &preprocessed_lde,
        },
        trace_log,
        constraint_coefficient_seed,
    );
    let quotient = divide_composition_by_trace_zerofier_bit_reversed(&composition, trace_log);
    let quotient_degree_bound = qm31_circle_degree_bound_bit_reversed(&quotient);
    if quotient_degree_bound > 1 << 20 {
        return Err(format!(
            "vertical successor quotient degree {quotient_degree_bound}"
        ));
    }
    let quotient_columns = qm31_values_to_columns(&quotient);
    let quotient_tree =
        CanonicalMerkleTree::from_matrix(VERTICAL_QUOTIENT_ORACLE_LABEL, &quotient_columns);
    transcript.absorb("vertical-quotient-root", &quotient_tree.root());

    let mut fri_mask_natural = fresh_qm31_lde(1 << 20, 4);
    let mut fri_mask = fri_mask_natural.clone();
    stwo::core::utils::bit_reverse(&mut fri_mask);
    let fri_mask_columns = qm31_values_to_columns(&fri_mask);
    let fri_mask_tree =
        CanonicalMerkleTree::from_matrix(VERTICAL_FRI_MASK_ORACLE_LABEL, &fri_mask_columns);
    transcript.absorb("vertical-fri-mask-root", &fri_mask_tree.root());
    let beta = transcript.challenge_qm31("vertical-batch-beta");
    let mut fri_manifest_transcript = transcript.clone();
    let fri_transcript_digest = fri_manifest_transcript.digest();
    let batch = batch_successor_oracles_natural(
        &sha_lde,
        &boundary_lde,
        &interaction_lde,
        &quotient,
        &fri_mask,
        beta,
    );
    fri_mask_natural.clear();
    let fri = prove_successor_fri(&batch, &mut transcript, VERTICAL_SUCCESSOR_FRI_CONFIG)
        .map_err(str::to_owned)?;
    let queries = transcript.query_indices(1 << eval_log, VERTICAL_SUCCESSOR_FRI_CONFIG.queries);
    let mut fri_alphas = Vec::with_capacity(fri.layers.len());
    for (round, layer) in fri.layers.iter().enumerate() {
        fri_manifest_transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        fri_alphas.push(fri_manifest_transcript.challenge_qm31(&format!("fri-alpha:{round}")));
    }
    fri_manifest_transcript.absorb("fri-final", &encode_qm31_values(&fri.final_coefficients));
    if !fri_manifest_transcript
        .accept_grind(VERTICAL_SUCCESSOR_FRI_CONFIG.grind_bits, fri.grind_nonce)
        || fri_manifest_transcript
            .query_indices(1 << eval_log, VERTICAL_SUCCESSOR_FRI_CONFIG.queries)
            != queries
    {
        return Err("vertical successor FRI manifest".into());
    }
    let query_digest = fri_manifest_transcript.digest();
    let sha_indices = successor_oracle_opening_indices(&program, 0, &queries, trace_log, eval_log);
    let boundary_indices =
        successor_oracle_opening_indices(&program, 1, &queries, trace_log, eval_log);
    let interaction_indices =
        successor_oracle_opening_indices(&program, 2, &queries, trace_log, eval_log);
    let preprocessed_indices =
        successor_oracle_opening_indices(&program, 3, &queries, trace_log, eval_log);
    let current_indices = sorted_unique(queries.clone());
    let horner_challenges = vertical_air_horner_challenges(constraint_coefficient_seed);
    let compression_challenges = vertical_air_compression_challenges(constraint_coefficient_seed);
    let oracles = PoolAirOracleLdes {
        sha: &sha_lde,
        sha_aux: &boundary_lde,
        bus: &interaction_lde,
        preprocessed: &preprocessed_lde,
    };
    let composition_lanes: Vec<[u32; VERTICAL_AIR_HORNER_LANES]> = current_indices
        .par_iter()
        .map_init(
            || Vec::<u32>::with_capacity(program.nodes.len()),
            |values, row| {
                let residuals = evaluate_air_residuals_at_lde_row(
                    &program,
                    &base_public_inputs,
                    &oracles,
                    trace_log,
                    eval_log,
                    *row,
                    values,
                );
                vertical_air_horner(&residuals, &horner_challenges)
            },
        )
        .collect();
    let (sha, sha_segments) = vertical_sha_opening(&sha_tree, &sha_lde, &sha_indices);
    let proof = VerticalSuccessorSealedProof {
        profile: program.profile,
        air_program_hash,
        transcript_initial,
        preprocessed: matrix_opening(&preprocessed_tree, &preprocessed_lde, &preprocessed_indices),
        sha,
        sha_segments,
        boundary: matrix_opening(&boundary_tree, &boundary_lde, &boundary_indices),
        interaction: matrix_opening(&interaction_tree, &interaction_lde, &interaction_indices),
        quotient: matrix_opening(&quotient_tree, &quotient_columns, &current_indices),
        fri_mask: matrix_opening(&fri_mask_tree, &fri_mask_columns, &current_indices),
        boundary_beta,
        boundary_gamma,
        boundary_inverse_products: inverse_products,
        boundary_transcript_digest,
        constraint_alpha,
        constraint_coefficient_seed,
        horner_challenges,
        compression_challenges,
        batch_beta: beta,
        fri_transcript_digest,
        fri_alphas,
        query_digest,
        queries,
        composition_lanes,
        fri,
    };
    Ok(VerticalSuccessorProveResult {
        proof,
        quotient_degree_bound,
    })
}

const SUCCESSOR_SEALED_PROOF_MAGIC: &[u8; 4] = b"SKSP";
const SUCCESSOR_SEALED_PROOF_VERSION: u8 = 7;

fn encode_successor_matrix_opening(opening: &SuccessorMatrixOpening, out: &mut Vec<u8>) {
    assert!(opening.row_width > 0 && opening.row_width <= u16::MAX as usize);
    assert_eq!(opening.indices.len(), opening.rows.len());
    assert!(opening.indices.len() <= u16::MAX as usize);
    assert!(opening.siblings.len() <= u16::MAX as usize);
    assert!(opening
        .indices
        .windows(2)
        .all(|indices| indices[0] < indices[1]));
    assert!(opening
        .rows
        .iter()
        .all(|row| row.len() == opening.row_width));
    out.extend_from_slice(&(opening.row_width as u16).to_be_bytes());
    out.extend_from_slice(&(opening.indices.len() as u16).to_be_bytes());
    for (index, row) in opening.indices.iter().zip(&opening.rows) {
        out.extend_from_slice(&(*index as u32).to_be_bytes());
        out.extend_from_slice(row);
    }
    out.extend_from_slice(&(opening.siblings.len() as u16).to_be_bytes());
    for sibling in &opening.siblings {
        out.extend_from_slice(sibling);
    }
}

/// One canonical byte string crosses the proof/carrier boundary.  The AIR
/// program and public statement are verifier-key inputs, never duplicated
/// inside the proof.
pub fn encode_successor_sealed_proof(proof: &SuccessorSealedProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SUCCESSOR_SEALED_PROOF_MAGIC);
    out.push(SUCCESSOR_SEALED_PROOF_VERSION);
    out.push(proof.profile);
    out.extend_from_slice(&proof.air_program_hash);
    let openings = [
        &proof.preprocessed,
        &proof.sha,
        &proof.sha_aux,
        &proof.bus,
        &proof.quotient,
        &proof.fri_mask,
    ];
    for opening in openings {
        out.extend_from_slice(&opening.root);
    }
    for opening in openings {
        encode_successor_matrix_opening(opening, &mut out);
    }
    assert!(!proof.transcript_initial.is_empty());
    assert!(proof.transcript_initial.len() <= u16::MAX as usize);
    out.extend_from_slice(&(proof.transcript_initial.len() as u16).to_be_bytes());
    out.extend_from_slice(&proof.transcript_initial);
    out.extend_from_slice(&encode_qm31_values(&[proof.constraint_alpha]));
    out.extend_from_slice(&proof.constraint_transcript_digest);
    out.extend_from_slice(&proof.constraint_coefficient_seed);
    for partial in &proof.partial_challenges {
        for value in partial {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out.extend_from_slice(&encode_qm31_values(&proof.compression_challenges));
    assert_eq!(
        proof.composition_partials.len(),
        proof.quotient.indices.len()
    );
    for partials in &proof.composition_partials {
        for partial in partials {
            for value in partial {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    out.extend_from_slice(&encode_qm31_values(&[proof.batch_beta]));
    out.extend_from_slice(&proof.fri_transcript_digest);
    assert!(!proof.fri_alphas.is_empty() && proof.fri_alphas.len() <= u8::MAX as usize);
    assert_eq!(proof.fri_alphas.len(), proof.fri.layers.len());
    out.push(proof.fri_alphas.len() as u8);
    out.extend_from_slice(&encode_qm31_values(&proof.fri_alphas));
    out.extend_from_slice(&proof.query_digest);
    assert_eq!(proof.queries.len(), SuccessorFriConfig::PRODUCTION.queries);
    out.push(proof.queries.len() as u8);
    for query in &proof.queries {
        assert!(*query <= u32::MAX as usize);
        out.extend_from_slice(&(*query as u32).to_be_bytes());
    }
    let fri = encode_successor_fri_proof(&proof.fri);
    assert!(fri.len() <= u32::MAX as usize);
    out.extend_from_slice(&(fri.len() as u32).to_be_bytes());
    out.extend_from_slice(&fri);
    out
}

const VERTICAL_SUCCESSOR_PROOF_MAGIC: &[u8; 4] = b"SKVP";
const VERTICAL_SUCCESSOR_PROOF_VERSION: u8 = 6;
const VERTICAL_SUCCESSOR_DIRECTORY_WORDS: usize = 1 + 6 + 1 + 17;

fn encode_vertical_matrix_opening(opening: &SuccessorMatrixOpening, out: &mut Vec<u8>) {
    assert!(opening.row_width > 0 && opening.row_width <= u16::MAX as usize);
    assert_eq!(opening.indices.len(), opening.rows.len());
    assert!(opening.indices.len() <= u16::MAX as usize);
    assert!(opening.siblings.len() <= u16::MAX as usize);
    out.extend_from_slice(&(opening.row_width as u16).to_le_bytes());
    out.extend_from_slice(&(opening.indices.len() as u16).to_le_bytes());
    for (index, row) in opening.indices.iter().zip(&opening.rows) {
        out.extend_from_slice(&(*index as u32).to_le_bytes());
        out.extend_from_slice(row);
    }
    out.extend_from_slice(&(opening.siblings.len() as u16).to_le_bytes());
    for sibling in &opening.siblings {
        out.extend_from_slice(sibling);
    }
}

pub fn encode_vertical_successor_sealed_proof(proof: &VerticalSuccessorSealedProof) -> Vec<u8> {
    let openings = [
        &proof.preprocessed,
        &proof.sha,
        &proof.boundary,
        &proof.interaction,
        &proof.quotient,
        &proof.fri_mask,
    ];
    assert!(proof.transcript_initial.len() <= u16::MAX as usize);
    assert_eq!(proof.fri.layers.len(), 17);
    assert_eq!(proof.fri_alphas.len(), proof.fri.layers.len());
    assert_eq!(
        proof.fri.final_coefficients.len(),
        1 << VERTICAL_SUCCESSOR_FRI_CONFIG.final_log_degree
    );
    assert_eq!(proof.queries.len(), VERTICAL_SUCCESSOR_FRI_CONFIG.queries);
    assert_eq!(proof.composition_lanes.len(), proof.quotient.indices.len());
    assert!(proof.sha.siblings.is_empty());
    assert_eq!(proof.sha_segments.len(), VERTICAL_SHA_SEGMENTS);

    let mut metadata = Vec::new();
    metadata.extend_from_slice(&(proof.transcript_initial.len() as u16).to_le_bytes());
    metadata.extend_from_slice(&proof.transcript_initial);
    for value in proof.boundary_beta {
        metadata.extend_from_slice(&value.to_le_bytes());
    }
    for value in proof.boundary_gamma {
        metadata.extend_from_slice(&value.to_le_bytes());
    }
    for value in proof.boundary_inverse_products {
        metadata.extend_from_slice(&value.to_le_bytes());
    }
    metadata.extend_from_slice(&proof.boundary_transcript_digest);
    metadata.extend_from_slice(&encode_qm31_values(&[proof.constraint_alpha]));
    metadata.extend_from_slice(&proof.constraint_coefficient_seed);
    for challenge in proof.horner_challenges {
        metadata.extend_from_slice(&challenge.to_le_bytes());
    }
    metadata.extend_from_slice(&encode_qm31_values(&proof.compression_challenges));
    metadata.extend_from_slice(&encode_qm31_values(&[proof.batch_beta]));
    metadata.extend_from_slice(&proof.fri_transcript_digest);
    metadata.push(proof.fri.layers.len() as u8);
    for ((layer, alpha), round) in proof.fri.layers.iter().zip(&proof.fri_alphas).zip(0..) {
        assert!(round < 17);
        metadata.extend_from_slice(&layer.root);
        metadata.extend_from_slice(&encode_qm31_values(&[*alpha]));
    }
    metadata.push(proof.fri.final_coefficients.len() as u8);
    metadata.extend_from_slice(&encode_qm31_values(&proof.fri.final_coefficients));
    metadata.extend_from_slice(&proof.fri.grind_nonce.to_le_bytes());
    metadata.extend_from_slice(&proof.query_digest);
    metadata.push(proof.queries.len() as u8);
    for query in &proof.queries {
        assert!(*query <= u32::MAX as usize);
        metadata.extend_from_slice(&(*query as u32).to_le_bytes());
    }

    let mut sections: Vec<Vec<u8>> = Vec::with_capacity(VERTICAL_SUCCESSOR_DIRECTORY_WORDS - 1);
    for (matrix, opening) in openings.iter().enumerate() {
        if matrix == 1 {
            const HEADER_BYTES: usize = 2 + 2 + 1 + (VERTICAL_SHA_SEGMENTS + 1) * 4;
            let mut bodies = Vec::with_capacity(VERTICAL_SHA_SEGMENTS);
            for (segment_index, segment) in proof.sha_segments.iter().enumerate() {
                let start = segment_index << VERTICAL_SHA_SEGMENT_LOG;
                let mut body = Vec::new();
                body.extend_from_slice(&segment.root);
                body.extend_from_slice(&(segment.groups.len() as u16).to_le_bytes());
                let mut group_bodies = Vec::with_capacity(segment.groups.len());
                for group in &segment.groups {
                    let group_start = start + (group.index << VERTICAL_SHA_GROUP_LOG);
                    let group_end = group_start + (1 << VERTICAL_SHA_GROUP_LOG);
                    let positions: Vec<usize> = opening
                        .indices
                        .iter()
                        .enumerate()
                        .filter_map(|(position, index)| {
                            (*index >= group_start && *index < group_end).then_some(position)
                        })
                        .collect();
                    assert!(!positions.is_empty());
                    let local_indices: Vec<usize> = positions
                        .iter()
                        .map(|position| opening.indices[*position] - group_start)
                        .collect();
                    let lower_program = canonical_merkle_program(
                        &local_indices,
                        group.siblings.len(),
                        1 << VERTICAL_SHA_GROUP_LOG,
                    );
                    let mut group_body = Vec::new();
                    group_body.extend_from_slice(&(group.index as u16).to_le_bytes());
                    group_body.extend_from_slice(&group.root);
                    group_body.extend_from_slice(&(positions.len() as u16).to_le_bytes());
                    for position in positions {
                        group_body
                            .extend_from_slice(&(opening.indices[position] as u32).to_le_bytes());
                        group_body.extend_from_slice(&opening.rows[position]);
                    }
                    group_body.extend_from_slice(&(group.siblings.len() as u16).to_le_bytes());
                    for sibling in &group.siblings {
                        group_body.extend_from_slice(sibling);
                    }
                    group_body.extend_from_slice(&(lower_program.len() as u16).to_le_bytes());
                    group_body.extend_from_slice(&lower_program);
                    group_bodies.push(group_body);
                }
                let mut group_offset = 32 + 2 + (segment.groups.len() + 1) * 4;
                body.extend_from_slice(&(group_offset as u32).to_le_bytes());
                for group_body in &group_bodies {
                    group_offset += group_body.len();
                    body.extend_from_slice(&(group_offset as u32).to_le_bytes());
                }
                for group_body in group_bodies {
                    body.extend_from_slice(&group_body);
                }
                let group_indices: Vec<usize> =
                    segment.groups.iter().map(|group| group.index).collect();
                let upper_program = if group_indices.is_empty() {
                    assert!(segment.siblings.is_empty());
                    Vec::new()
                } else {
                    canonical_merkle_program(
                        &group_indices,
                        segment.siblings.len(),
                        VERTICAL_SHA_GROUPS_PER_SEGMENT,
                    )
                };
                body.extend_from_slice(&(segment.siblings.len() as u16).to_le_bytes());
                for sibling in &segment.siblings {
                    body.extend_from_slice(sibling);
                }
                body.extend_from_slice(&(upper_program.len() as u16).to_le_bytes());
                body.extend_from_slice(&upper_program);
                bodies.push(body);
            }
            let mut offsets = Vec::with_capacity(VERTICAL_SHA_SEGMENTS + 1);
            let mut offset = HEADER_BYTES;
            offsets.push(offset);
            for body in &bodies {
                offset += body.len();
                offsets.push(offset);
            }
            let mut section = Vec::with_capacity(offset);
            section.extend_from_slice(&(opening.row_width as u16).to_le_bytes());
            section.extend_from_slice(&(opening.indices.len() as u16).to_le_bytes());
            section.push(VERTICAL_SHA_SEGMENTS as u8);
            for offset in offsets {
                section.extend_from_slice(&(offset as u32).to_le_bytes());
            }
            for body in bodies {
                section.extend_from_slice(&body);
            }
            sections.push(section);
        } else {
            let mut section = Vec::new();
            encode_vertical_matrix_opening(opening, &mut section);
            let program =
                canonical_merkle_program(&opening.indices, opening.siblings.len(), 1 << 24);
            section.extend_from_slice(&(program.len() as u16).to_le_bytes());
            section.extend_from_slice(&program);
            sections.push(section);
        }
    }
    let mut composition = Vec::new();
    for lanes in &proof.composition_lanes {
        for value in lanes {
            composition.extend_from_slice(&value.to_le_bytes());
        }
    }
    sections.push(composition);
    for (round, layer) in proof.fri.layers.iter().enumerate() {
        assert_eq!(layer.values.len(), layer.merkle.indices.len());
        assert!(!layer.values.is_empty() && layer.values.len() <= u16::MAX as usize);
        assert!(layer.merkle.siblings.len() <= u16::MAX as usize);
        let mut section = Vec::new();
        section.extend_from_slice(&(layer.values.len() as u16).to_le_bytes());
        for (index, value) in layer.merkle.indices.iter().zip(&layer.values) {
            section.extend_from_slice(&(*index as u32).to_le_bytes());
            section.extend_from_slice(&encode_qm31_values(&[*value]));
        }
        section.extend_from_slice(&(layer.merkle.siblings.len() as u16).to_le_bytes());
        for sibling in &layer.merkle.siblings {
            section.extend_from_slice(sibling);
        }
        let program = canonical_merkle_program(
            &layer.merkle.indices,
            layer.merkle.siblings.len(),
            (1 << 24) >> round,
        );
        section.extend_from_slice(&(program.len() as u16).to_le_bytes());
        section.extend_from_slice(&program);
        sections.push(section);
    }
    assert_eq!(sections.len(), VERTICAL_SUCCESSOR_DIRECTORY_WORDS - 1);

    let fixed_prefix_bytes = 4 + 1 + 1 + 32 + 6 * 32 + VERTICAL_SUCCESSOR_DIRECTORY_WORDS * 4;
    let mut offset = fixed_prefix_bytes + metadata.len();
    let mut directory = Vec::with_capacity(VERTICAL_SUCCESSOR_DIRECTORY_WORDS);
    directory.push(0usize);
    for section in &sections {
        directory.push(offset);
        offset += section.len();
    }
    directory[0] = offset;
    assert!(directory.iter().all(|word| *word <= u32::MAX as usize));

    let mut out = Vec::with_capacity(offset);
    out.extend_from_slice(VERTICAL_SUCCESSOR_PROOF_MAGIC);
    out.push(VERTICAL_SUCCESSOR_PROOF_VERSION);
    out.push(proof.profile);
    out.extend_from_slice(&proof.air_program_hash);
    for opening in openings {
        out.extend_from_slice(&opening.root);
    }
    for word in directory {
        out.extend_from_slice(&(word as u32).to_le_bytes());
    }
    out.extend_from_slice(&metadata);
    for section in sections {
        out.extend_from_slice(&section);
    }
    assert_eq!(out.len(), offset);
    out
}

fn decode_successor_matrix_opening(
    cursor: &mut ProofCursor<'_>,
    root: [u8; 32],
) -> Result<SuccessorMatrixOpening, String> {
    let row_width = cursor.u16_be()? as usize;
    let opening_count = cursor.u16_be()? as usize;
    if row_width == 0
        || row_width % 4 != 0
        || row_width > 8192
        || opening_count == 0
        || opening_count > 4096
    {
        return Err("successor matrix opening shape".into());
    }
    let mut indices = Vec::with_capacity(opening_count);
    let mut rows = Vec::with_capacity(opening_count);
    for _ in 0..opening_count {
        let index = cursor.u32_be()? as usize;
        let row = cursor.take(row_width)?.to_vec();
        if row
            .chunks_exact(4)
            .any(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()) as u64 >= M31)
        {
            return Err("successor matrix field element".into());
        }
        indices.push(index);
        rows.push(row);
    }
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("successor matrix opening indices".into());
    }
    let sibling_count = cursor.u16_be()? as usize;
    if sibling_count > 4096 {
        return Err("successor matrix sibling count".into());
    }
    let siblings = (0..sibling_count)
        .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    Ok(SuccessorMatrixOpening {
        root,
        row_width,
        indices,
        rows,
        siblings,
    })
}

pub fn decode_successor_sealed_proof(bytes: &[u8]) -> Result<SuccessorSealedProof, String> {
    let mut cursor = ProofCursor { bytes, offset: 0 };
    if cursor.take(4)? != SUCCESSOR_SEALED_PROOF_MAGIC
        || cursor.u8()? != SUCCESSOR_SEALED_PROOF_VERSION
    {
        return Err("successor sealed proof codec".into());
    }
    let profile = cursor.u8()?;
    if profile > 2 {
        return Err("successor sealed proof profile".into());
    }
    let air_program_hash = cursor.take(32)?.try_into().unwrap();
    let roots = (0..6)
        .map(|_| Ok(cursor.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    let preprocessed = decode_successor_matrix_opening(&mut cursor, roots[0])?;
    let sha = decode_successor_matrix_opening(&mut cursor, roots[1])?;
    let sha_aux = decode_successor_matrix_opening(&mut cursor, roots[2])?;
    let bus = decode_successor_matrix_opening(&mut cursor, roots[3])?;
    let quotient = decode_successor_matrix_opening(&mut cursor, roots[4])?;
    let fri_mask = decode_successor_matrix_opening(&mut cursor, roots[5])?;
    let transcript_initial_len = cursor.u16_be()? as usize;
    if transcript_initial_len == 0 {
        return Err("successor transcript initial".into());
    }
    let transcript_initial = cursor.take(transcript_initial_len)?.to_vec();
    let constraint_alpha = cursor.qm31()?;
    let constraint_transcript_digest = cursor.take(32)?.try_into().unwrap();
    let constraint_coefficient_seed = cursor.take(32)?.try_into().unwrap();
    let mut partial_challenge_rows = Vec::with_capacity(8);
    for _ in 0..8 {
        let values = (0..POOL_AIR_HORNER_LANES)
            .map(|_| cursor.m31())
            .collect::<Result<Vec<_>, _>>()?;
        partial_challenge_rows.push(
            values
                .try_into()
                .map_err(|_| "successor partial challenge shape")?,
        );
    }
    let partial_challenges = partial_challenge_rows
        .try_into()
        .map_err(|_| "successor partial challenge shape")?;
    let compression_challenges = (0..POOL_AIR_HORNER_LANES)
        .map(|_| cursor.qm31())
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "successor compression challenge shape")?;
    let mut composition_partials = Vec::with_capacity(quotient.indices.len());
    for _ in 0..quotient.indices.len() {
        let mut partials = Vec::with_capacity(8);
        for _ in 0..8 {
            let values = (0..POOL_AIR_HORNER_LANES)
                .map(|_| cursor.m31())
                .collect::<Result<Vec<_>, _>>()?;
            partials.push(
                values
                    .try_into()
                    .map_err(|_| "successor composition partial shape")?,
            );
        }
        composition_partials.push(
            partials
                .try_into()
                .map_err(|_| "successor composition partial shape")?,
        );
    }
    let batch_beta = cursor.qm31()?;
    let fri_transcript_digest = cursor.take(32)?.try_into().unwrap();
    let fri_alpha_count = cursor.u8()? as usize;
    if fri_alpha_count == 0 || fri_alpha_count > 32 {
        return Err("successor FRI alpha count".into());
    }
    let fri_alphas = (0..fri_alpha_count)
        .map(|_| cursor.qm31())
        .collect::<Result<Vec<_>, _>>()?;
    let query_digest = cursor.take(32)?.try_into().unwrap();
    let query_count = cursor.u8()? as usize;
    if query_count != SuccessorFriConfig::PRODUCTION.queries {
        return Err("successor query count".into());
    }
    let queries = (0..query_count)
        .map(|_| cursor.u32_be().map(|query| query as usize))
        .collect::<Result<Vec<_>, _>>()?;
    let fri_len = cursor.u32_be()? as usize;
    if fri_len == 0 || fri_len > 1 << 24 {
        return Err("successor sealed FRI length".into());
    }
    let fri = decode_successor_fri_proof(cursor.take(fri_len)?)?;
    if fri_alphas.len() != fri.layers.len() {
        return Err("successor FRI alpha shape".into());
    }
    if cursor.offset != bytes.len() {
        return Err("trailing successor sealed proof bytes".into());
    }
    Ok(SuccessorSealedProof {
        profile,
        air_program_hash,
        transcript_initial,
        preprocessed,
        sha,
        sha_aux,
        bus,
        quotient,
        fri_mask,
        constraint_alpha,
        constraint_transcript_digest,
        constraint_coefficient_seed,
        partial_challenges,
        compression_challenges,
        composition_partials,
        batch_beta,
        fri_transcript_digest,
        fri_alphas,
        query_digest,
        queries,
        fri,
    })
}

fn decode_matrix_row(row: &[u8]) -> Vec<u32> {
    row.chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn verify_and_decode_matrix_opening(
    opening: &SuccessorMatrixOpening,
    label: &str,
    expected_columns: usize,
    expected_indices: &[usize],
    row_count: usize,
    quaternary: bool,
) -> Result<std::collections::BTreeMap<usize, Vec<u32>>, String> {
    if expected_columns == 0
        || opening.row_width != expected_columns * 4
        || opening.indices != expected_indices
        || opening.rows.len() != opening.indices.len()
        || opening
            .rows
            .iter()
            .any(|row| row.len() != opening.row_width)
    {
        return Err(format!("{label} opening shape"));
    }
    let raw_rows: Vec<(usize, Vec<u8>)> = opening
        .indices
        .iter()
        .copied()
        .zip(opening.rows.iter().cloned())
        .collect();
    let merkle = CanonicalMerkleMultiProof {
        indices: opening.indices.clone(),
        siblings: opening.siblings.clone(),
    };
    let merkle_ok = if quaternary {
        verify_matrix_multiproof4(label, &raw_rows, &merkle, row_count, opening.root)
    } else {
        verify_matrix_multiproof(label, &raw_rows, &merkle, row_count, opening.root)
    };
    if !merkle_ok {
        return Err(format!("{label} Merkle"));
    }
    Ok(opening
        .indices
        .iter()
        .copied()
        .zip(opening.rows.iter().map(|row| decode_matrix_row(row)))
        .collect())
}

pub fn trace_zerofier_at_bit_reversed(
    index: usize,
    eval_log: u32,
    relation_trace_log: u32,
) -> BaseField {
    let eval_domain = CanonicCoset::new(eval_log).circle_domain();
    let point = eval_domain.at(bit_reverse_index(index, eval_log));
    coset_vanishing(CanonicCoset::new(relation_trace_log).coset, point)
}

fn composition_partials_at_opened_query(
    program: &PoolAirProgram,
    public_inputs: &[u32],
    matrices: &[std::collections::BTreeMap<usize, Vec<u32>>; 4],
    query: usize,
    relation_trace_log: u32,
    eval_log: u32,
    coefficient_seed: [u8; 32],
) -> Result<[[u32; POOL_AIR_HORNER_LANES]; 8], String> {
    let mut values = Vec::with_capacity(program.nodes.len());
    if public_inputs.len() != program.public_input_count {
        return Err("successor AIR public inputs".into());
    }
    for node in &program.nodes {
        let value = match *node {
            PoolAirNode::Constant(value) => value,
            PoolAirNode::Public(index) => public_inputs[index as usize],
            PoolAirNode::Input {
                oracle,
                column,
                offset,
            } => {
                let location = if offset == 0 {
                    query
                } else {
                    stwo::core::utils::offset_bit_reversed_circle_domain_index(
                        query,
                        relation_trace_log,
                        eval_log,
                        offset as isize,
                    )
                };
                *matrices[oracle as usize]
                    .get(&location)
                    .and_then(|row| row.get(column as usize))
                    .ok_or("successor AIR opening")?
            }
            PoolAirNode::Add { left, right } => {
                add_m31_fast(values[left as usize], values[right as usize])
            }
            PoolAirNode::Sub { left, right } => {
                sub_m31_fast(values[left as usize], values[right as usize])
            }
            PoolAirNode::Mul { left, right } => {
                mul_m31_fast(values[left as usize], values[right as usize])
            }
        };
        values.push(value);
    }
    let residuals: Vec<u32> = program
        .outputs
        .iter()
        .map(|(node, _)| values[*node as usize])
        .collect();
    let ranges = pool_air_partial_ranges(program)?;
    let partial_challenges = pool_air_partial_challenges(coefficient_seed);
    Ok(pool_air_horner_partials(
        &residuals,
        &partial_challenges,
        &ranges,
    ))
}

fn qm31_from_opened_row(row: &[u32]) -> Result<Qm31Value, String> {
    row.try_into()
        .map_err(|_| "successor QM31 row width".into())
}

fn batch_at_opened_query(
    sha: &[u32],
    sha_aux: &[u32],
    bus: &[u32],
    quotient: Qm31Value,
    fri_mask: Qm31Value,
    beta: Qm31Value,
) -> Qm31Value {
    let beta = qm31_to_secure(beta);
    let mut power = SecureField::from_u32_unchecked(1, 0, 0, 0);
    let mut accumulator = qm31_to_secure(fri_mask);
    for value in sha.iter().chain(sha_aux).chain(bus) {
        accumulator += power * BaseField::from_u32_unchecked(*value);
        power *= beta;
    }
    accumulator += power * qm31_to_secure(quotient);
    secure_to_qm31(accumulator)
}

/// Reference verifier for the exact sealed successor artifact.  Public
/// preprocessing and transcript framing are explicit verifier-key inputs, so
/// neither can be substituted by proof-controlled bytes.
pub fn verify_successor_sealed_proof(
    proof: &SuccessorSealedProof,
    transcript_initial: &[u8],
    expected_program_bytes: &[u8],
    public_inputs: &[u32],
    expected_preprocessed_root: [u8; 32],
) -> Result<(), String> {
    const TRACE_LOG: u32 = 13;
    const EVAL_LOG: u32 = 20;
    const ROW_COUNT: usize = 1 << EVAL_LOG;

    if transcript_initial.is_empty() {
        return Err("successor transcript initial".into());
    }
    if proof.transcript_initial != transcript_initial {
        return Err("successor transcript initial".into());
    }
    let program = decode_pool_air_program(expected_program_bytes)?;
    if proof.profile != program.profile
        || proof.air_program_hash != sha256(&[expected_program_bytes])
        || proof.preprocessed.root != expected_preprocessed_root
    {
        return Err("successor verifier key".into());
    }
    let widths = pool_air_program_widths(&program);
    if widths.iter().any(|width| *width == 0) {
        return Err("successor AIR oracle width".into());
    }

    let mut transcript = SuccessorTranscript::new(transcript_initial);
    absorb_successor_oracle_roots(
        &mut transcript,
        &proof.air_program_hash,
        &proof.preprocessed.root,
        &proof.sha.root,
        &proof.sha_aux.root,
        &proof.bus.root,
    );
    let constraint_alpha = transcript.challenge_qm31("constraint-alpha");
    if proof.constraint_alpha != constraint_alpha
        || proof.constraint_transcript_digest != transcript.digest()
    {
        return Err("successor constraint transcript manifest".into());
    }
    let constraint_coefficient_seed = pool_air_coefficient_seed(constraint_alpha);
    if proof.constraint_coefficient_seed != constraint_coefficient_seed {
        return Err("successor constraint coefficient seed".into());
    }
    let partial_challenges = pool_air_partial_challenges(constraint_coefficient_seed);
    let compression_challenges = pool_air_compression_challenges(constraint_coefficient_seed);
    if proof.partial_challenges != partial_challenges
        || proof.compression_challenges != compression_challenges
    {
        return Err("successor composition challenges".into());
    }
    transcript.absorb("quotient-root", &proof.quotient.root);
    transcript.absorb("fri-mask-root", &proof.fri_mask.root);
    let beta = transcript.challenge_qm31("batch-beta");
    if proof.batch_beta != beta || proof.fri_transcript_digest != transcript.digest() {
        return Err("successor FRI transcript manifest".into());
    }
    let mut manifest_transcript = transcript.clone();
    let mut fri_alphas = Vec::with_capacity(proof.fri.layers.len());
    for (round, layer) in proof.fri.layers.iter().enumerate() {
        manifest_transcript.absorb(&format!("fri-root:{round}"), &layer.root);
        fri_alphas.push(manifest_transcript.challenge_qm31(&format!("fri-alpha:{round}")));
    }
    manifest_transcript.absorb(
        "fri-final",
        &encode_qm31_values(&proof.fri.final_coefficients),
    );
    if !manifest_transcript.accept_grind(
        SuccessorFriConfig::PRODUCTION.grind_bits,
        proof.fri.grind_nonce,
    ) {
        return Err("successor FRI manifest grind".into());
    }
    let manifest_queries =
        manifest_transcript.query_indices(ROW_COUNT, SuccessorFriConfig::PRODUCTION.queries);
    if proof.fri_alphas != fri_alphas
        || proof.query_digest != manifest_transcript.digest()
        || proof.queries != manifest_queries
    {
        return Err("successor FRI transcript manifest".into());
    }
    verify_successor_fri(
        &proof.fri,
        EVAL_LOG,
        &mut transcript,
        SuccessorFriConfig::PRODUCTION,
    )
    .map_err(str::to_owned)?;

    let queries = transcript.query_indices(ROW_COUNT, SuccessorFriConfig::PRODUCTION.queries);
    let expected: [Vec<usize>; 4] = std::array::from_fn(|oracle| {
        successor_oracle_opening_indices(&program, oracle as u8, &queries, TRACE_LOG, EVAL_LOG)
    });
    let current_indices = sorted_unique(queries.clone());
    let matrices = [
        verify_and_decode_matrix_opening(
            &proof.sha,
            SHA_ORACLE_LABEL,
            widths[0],
            &expected[0],
            ROW_COUNT,
            false,
        )?,
        verify_and_decode_matrix_opening(
            &proof.sha_aux,
            SHA_AUX_ORACLE_LABEL,
            widths[1],
            &expected[1],
            ROW_COUNT,
            false,
        )?,
        verify_and_decode_matrix_opening(
            &proof.bus,
            BUS_ORACLE_LABEL,
            widths[2],
            &expected[2],
            ROW_COUNT,
            false,
        )?,
        verify_and_decode_matrix_opening(
            &proof.preprocessed,
            PREPROCESSED_ORACLE_LABELS[program.profile as usize],
            widths[3],
            &expected[3],
            ROW_COUNT,
            false,
        )?,
    ];
    let quotient = verify_and_decode_matrix_opening(
        &proof.quotient,
        QUOTIENT_ORACLE_LABEL,
        4,
        &current_indices,
        ROW_COUNT,
        false,
    )?;
    let fri_mask = verify_and_decode_matrix_opening(
        &proof.fri_mask,
        FRI_MASK_ORACLE_LABEL,
        4,
        &current_indices,
        ROW_COUNT,
        false,
    )?;
    let fri_layer_zero: std::collections::BTreeMap<usize, Qm31Value> = proof.fri.layers[0]
        .merkle
        .indices
        .iter()
        .copied()
        .zip(proof.fri.layers[0].values.iter().copied())
        .collect();
    if proof.composition_partials.len() != current_indices.len() {
        return Err("successor composition partial shape".into());
    }
    let composition_partials: std::collections::BTreeMap<usize, [[u32; POOL_AIR_HORNER_LANES]; 8]> =
        current_indices
            .iter()
            .copied()
            .zip(proof.composition_partials.iter().copied())
            .collect();

    for query in queries {
        let calculated_partials = composition_partials_at_opened_query(
            &program,
            public_inputs,
            &matrices,
            query,
            TRACE_LOG,
            EVAL_LOG,
            constraint_coefficient_seed,
        )?;
        let carried_partials = composition_partials
            .get(&query)
            .ok_or("successor composition partial")?;
        if carried_partials != &calculated_partials {
            return Err("successor composition partial".into());
        }
        let composition = qm31_to_secure(pool_air_compress_partials(
            carried_partials,
            &compression_challenges,
        ));
        let quotient_value =
            qm31_from_opened_row(quotient.get(&query).ok_or("successor quotient opening")?)?;
        let z = trace_zerofier_at_bit_reversed(query, EVAL_LOG, TRACE_LOG);
        if composition != qm31_to_secure(quotient_value) * z {
            return Err("successor quotient identity".into());
        }
        let mask_value =
            qm31_from_opened_row(fri_mask.get(&query).ok_or("successor FRI mask opening")?)?;
        let batched = batch_at_opened_query(
            matrices[0]
                .get(&query)
                .ok_or("successor SHA batch opening")?,
            matrices[1]
                .get(&query)
                .ok_or("successor SHA auxiliary batch opening")?,
            matrices[2]
                .get(&query)
                .ok_or("successor bus batch opening")?,
            quotient_value,
            mask_value,
            beta,
        );
        if fri_layer_zero.get(&query) != Some(&batched) {
            return Err("successor FRI batch link".into());
        }
    }
    Ok(())
}

/// Coordinate-wise Circle FFT is valid for QM31 because the interpolation
/// basis is over M31. This keeps the extension field exact without a second FFT.
pub fn circle_lde_qm31(values: &[Qm31Value], log_blowup: u32) -> Vec<Qm31Value> {
    assert!(values.len().is_power_of_two());
    let coordinates: Vec<Vec<u32>> = (0..4)
        .map(|coordinate| values.iter().map(|value| value[coordinate]).collect())
        .collect();
    let extended: Vec<Vec<u32>> = coordinates
        .par_iter()
        .map(|coordinate| circle_lde(coordinate, log_blowup))
        .collect();
    (0..extended[0].len())
        .map(|row| std::array::from_fn(|coordinate| extended[coordinate][row]))
        .collect()
}

pub fn fresh_qm31_lde(degree_rows: usize, log_blowup: u32) -> Vec<Qm31Value> {
    assert!(degree_rows.is_power_of_two());
    let values: Vec<Qm31Value> = (0..degree_rows)
        .map(|_| std::array::from_fn(|_| fresh_m31().0))
        .collect();
    circle_lde_qm31(&values, log_blowup)
}

pub fn trace_zerofier_values(eval_log_size: u32, trace_log_size: u32) -> Vec<u32> {
    assert!(eval_log_size > trace_log_size);
    let eval_domain = CanonicCoset::new(eval_log_size).circle_domain();
    let relation_coset = CanonicCoset::new(trace_log_size).coset;
    eval_domain
        .iter()
        .map(|point| coset_vanishing(relation_coset, point).0)
        .collect()
}

pub fn divide_composition_by_trace_zerofier(
    composition_lde: &[Qm31Value],
    trace_log_size: u32,
) -> Vec<Qm31Value> {
    assert!(composition_lde.len().is_power_of_two());
    let eval_log_size = composition_lde.len().ilog2();
    let zerofier = trace_zerofier_values(eval_log_size, trace_log_size);
    composition_lde
        .par_iter()
        .zip(zerofier)
        .map(|(value, z)| {
            let inverse = inv_m(z as u64);
            std::array::from_fn(|coordinate| mul_m(value[coordinate] as u64, inverse) as u32)
        })
        .collect()
}

pub fn divide_composition_by_trace_zerofier_bit_reversed(
    composition_lde: &[Qm31Value],
    trace_log_size: u32,
) -> Vec<Qm31Value> {
    assert!(composition_lde.len().is_power_of_two());
    let mut zerofier = trace_zerofier_values(composition_lde.len().ilog2(), trace_log_size);
    stwo::core::utils::bit_reverse(&mut zerofier);
    composition_lde
        .par_iter()
        .zip(zerofier)
        .map(|(value, z)| {
            let inverse = inv_m(z as u64);
            std::array::from_fn(|coordinate| mul_m31_fast(value[coordinate], inverse as u32))
        })
        .collect()
}

pub fn qm31_circle_degree_bound_bit_reversed(values: &[Qm31Value]) -> usize {
    assert!(values.len().is_power_of_two());
    let log_size = values.len().ilog2();
    let domain = CanonicCoset::new(log_size).circle_domain();
    (0..4)
        .into_par_iter()
        .map(|coordinate| {
            let evaluation: CpuCircleEvaluation<BaseField, BitReversedOrder> =
                CpuCircleEvaluation::new(
                    domain,
                    values
                        .iter()
                        .map(|value| BaseField::from_u32_unchecked(value[coordinate]))
                        .collect(),
                );
            evaluation
                .interpolate()
                .coeffs
                .iter()
                .rposition(|coefficient| coefficient.0 != 0)
                .map_or(0, |degree| degree + 1)
        })
        .max()
        .unwrap()
}

fn qm31_leaf(tree_key: &[u8; 32], index: usize, value: &Qm31Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(tree_key);
    hasher.update((index as u32).to_be_bytes());
    for coordinate in value {
        hasher.update(coordinate.to_le_bytes());
    }
    hasher.finalize().into()
}

pub fn qm31_oracle_root(label: &str, values: &[Qm31Value]) -> [u8; 32] {
    CanonicalMerkleTree::from_qm31(label, values).root()
}

pub fn verify_qm31_multiproof(
    label: &str,
    rows: &[(usize, Qm31Value)],
    proof: &CanonicalMerkleMultiProof,
    row_count: usize,
    root: [u8; 32],
) -> bool {
    use std::collections::BTreeMap;

    if rows.is_empty() || row_count < 2 || !row_count.is_power_of_two() {
        return false;
    }
    let indices: Vec<usize> = rows.iter().map(|(index, _)| *index).collect();
    if indices != proof.indices
        || indices.iter().any(|index| *index >= row_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    let tree_key = canonical_tree_key(label);
    let mut frontier: BTreeMap<usize, [u8; 32]> = rows
        .iter()
        .map(|(index, value)| (*index, qm31_leaf(&tree_key, *index, value)))
        .collect();
    let mut sibling_cursor = 0usize;
    for level in 0..row_count.ilog2() {
        let mut next = BTreeMap::new();
        for (&index, &value) in &frontier {
            if index & 1 == 1 && frontier.contains_key(&(index ^ 1)) {
                continue;
            }
            let sibling = match frontier.get(&(index ^ 1)) {
                Some(value) => *value,
                None => match proof.siblings.get(sibling_cursor) {
                    Some(value) => {
                        sibling_cursor += 1;
                        *value
                    }
                    None => return false,
                },
            };
            let parent = if index & 1 == 0 {
                matrix_parent(&tree_key, level as u8, &value, &sibling)
            } else {
                matrix_parent(&tree_key, level as u8, &sibling, &value)
            };
            next.insert(index >> 1, parent);
        }
        frontier = next;
    }
    sibling_cursor == proof.siblings.len()
        && frontier.len() == 1
        && frontier.get(&0).copied() == Some(root)
}

pub fn verify_qm31_multiproof4(
    label: &str,
    rows: &[(usize, Qm31Value)],
    proof: &CanonicalMerkleMultiProof,
    row_count: usize,
    root: [u8; 32],
) -> bool {
    use std::collections::BTreeMap;

    if rows.is_empty()
        || row_count < 4
        || !row_count.is_power_of_two()
        || row_count.ilog2() % 2 != 0
    {
        return false;
    }
    let indices: Vec<usize> = rows.iter().map(|(index, _)| *index).collect();
    if indices != proof.indices
        || indices.iter().any(|index| *index >= row_count)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    let tree_key = canonical_tree_key(label);
    let mut frontier: BTreeMap<usize, [u8; 32]> = rows
        .iter()
        .map(|(index, value)| (*index, qm31_leaf(&tree_key, *index, value)))
        .collect();
    let mut sibling_cursor = 0usize;
    for level in 0..row_count.ilog2() / 2 {
        let mut parents = frontier.keys().map(|index| index >> 2).collect::<Vec<_>>();
        parents.dedup();
        let mut next = BTreeMap::new();
        for parent in parents {
            let mut children = [[0u8; 32]; 4];
            for child in 0..4 {
                let index = parent * 4 + child;
                children[child] = match frontier.get(&index) {
                    Some(value) => *value,
                    None => match proof.siblings.get(sibling_cursor) {
                        Some(value) => {
                            sibling_cursor += 1;
                            *value
                        }
                        None => return false,
                    },
                };
            }
            next.insert(parent, matrix_parent4(&tree_key, level as u8, &children));
        }
        frontier = next;
    }
    sibling_cursor == proof.siblings.len()
        && frontier.len() == 1
        && frontier.get(&0).copied() == Some(root)
}

fn seal_circle_lde_with_coeffs(
    values: &[u32],
    log_domain_expansion: u32,
    randomizer_coeffs: Vec<BaseField>,
) -> Vec<u32> {
    assert!(values.len().is_power_of_two());
    assert!(randomizer_coeffs.len().is_power_of_two());
    let trace_log = values.len().ilog2();
    let eval_log = trace_log + log_domain_expansion;
    assert!(log_domain_expansion >= 1);
    assert!(randomizer_coeffs.len() <= values.len());

    let trace_domain = CanonicCoset::new(trace_log).circle_domain();
    let natural: CpuCircleEvaluation<BaseField, NaturalOrder> =
        CpuCircleEvaluation::new(trace_domain, logical_coset_values_to_circle_order(values));
    let witness = natural.bit_reverse().interpolate();
    let randomizer = CpuCirclePoly::new(randomizer_coeffs);
    let witness_lde = circle_eval_natural(&witness, eval_log);
    let randomizer_lde = circle_eval_natural(&randomizer, eval_log);
    let eval_domain = CanonicCoset::new(eval_log).circle_domain();
    let trace_coset = CanonicCoset::new(trace_log).coset;
    eval_domain
        .iter()
        .zip(witness_lde)
        .zip(randomizer_lde)
        .map(|((point, witness_value), randomizer_value)| {
            (witness_value + coset_vanishing(trace_coset, point) * randomizer_value).0
        })
        .collect()
}

#[cfg(test)]
fn interpolate_natural(values: Vec<u32>) -> CpuCirclePoly {
    let log_size = values.len().ilog2();
    let evaluation: CpuCircleEvaluation<BaseField, NaturalOrder> = CpuCircleEvaluation::new(
        CanonicCoset::new(log_size).circle_domain(),
        values
            .into_iter()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    );
    evaluation.bit_reverse().interpolate()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: u64,
    pub y: u64,
}

pub fn add_m(a: u64, b: u64) -> u64 {
    (a + b) % M31
}

pub fn sub_m(a: u64, b: u64) -> u64 {
    (a + M31 - b) % M31
}

pub fn mul_m(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % M31 as u128) as u64
}

pub fn inv_m(a: u64) -> u64 {
    assert_ne!(a, 0);
    let mut old_r = a as i128;
    let mut r = M31 as i128;
    let mut old_t: i128 = 1;
    let mut t: i128 = 0;
    while r != 0 {
        let q = old_r / r;
        let nr = old_r - q * r;
        old_r = r;
        r = nr;
        let nt = old_t - q * t;
        old_t = t;
        t = nt;
    }
    assert_eq!(old_r, 1);
    ((old_t % M31 as i128 + M31 as i128) % M31 as i128) as u64
}

pub fn on_circle(p: Point) -> bool {
    add_m(mul_m(p.x, p.x), mul_m(p.y, p.y)) == 1
}

pub fn add_points(a: Point, b: Point) -> Point {
    Point {
        x: sub_m(mul_m(a.x, b.x), mul_m(a.y, b.y)),
        y: add_m(mul_m(a.x, b.y), mul_m(a.y, b.x)),
    }
}

pub fn double_point(p: Point) -> Point {
    add_points(p, p)
}

pub fn scalar_mul(p: Point, mut k: u64) -> Point {
    let mut acc = Point { x: 1, y: 0 };
    let mut base = p;
    while k > 0 {
        if k & 1 == 1 {
            acc = add_points(acc, base);
        }
        base = double_point(base);
        k >>= 1;
    }
    acc
}

pub fn project_pi(p: Point) -> Point {
    Point {
        x: sub_m(mul_m(p.x, p.x), mul_m(p.y, p.y)),
        y: mul_m(2, mul_m(p.x, p.y)),
    }
}

pub fn fold_pair(p: Point, f_at_p: u64, f_at_conj: u64, lambda: u64) -> (Point, u64) {
    let two_inv = inv_m(2);
    let even = mul_m(add_m(f_at_p, f_at_conj), two_inv);
    let odd = mul_m(sub_m(f_at_p, f_at_conj), two_inv);
    let denom = if p.x != 0 { p.x } else { p.y };
    assert_ne!(denom, 0);
    (
        project_pi(p),
        add_m(even, mul_m(lambda, mul_m(odd, inv_m(denom)))),
    )
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hash_to_m31(parts: &[&[u8]]) -> u64 {
    let h = sha256(parts);
    let mut n: u128 = 0;
    for b in &h[..8] {
        n = (n << 8) | *b as u128;
    }
    (n % M31 as u128) as u64
}

pub fn statement_coeffs(bytes: &[u8]) -> [u64; 16] {
    let mut coeffs = [0u64; 16];
    for i in 0..16 {
        let h = sha256(&[bytes, &[i as u8]]);
        let mut c: u128 = 0;
        for b in &h[..8] {
            c = (c << 8) | *b as u128;
        }
        coeffs[i] = (c % M31 as u128) as u64;
    }
    coeffs
}

pub fn eval_on_circle(coeffs: &[u64; 16], p: Point) -> u64 {
    let mut acc = 0u64;
    let mut pow = 1u64;
    for c in coeffs {
        acc = add_m(acc, mul_m(*c, pow));
        pow = mul_m(pow, p.x);
    }
    acc
}

pub fn circle_domain() -> Vec<Point> {
    let g = scalar_mul(CIRCLE_GEN, 1 << 26);
    (0..FRI_N).map(|i| scalar_mul(g, i as u64)).collect()
}

fn partner_index(i: usize, n: usize) -> usize {
    (i + n / 2) % n
}

fn encode_le(v: u64) -> [u8; 4] {
    (v as u32).to_le_bytes()
}

fn leaf_hash(v: u64) -> [u8; 32] {
    sha256(&[&encode_le(v)])
}

struct MerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    fn new(values: &[u64]) -> Self {
        let mut cur: Vec<[u8; 32]> = values.iter().copied().map(leaf_hash).collect();
        let mut layers = vec![cur.clone()];
        while cur.len() > 1 {
            let mut next = Vec::with_capacity(cur.len() / 2);
            for i in (0..cur.len()).step_by(2) {
                next.push(sha256(&[&cur[i], &cur[i + 1]]));
            }
            layers.push(next.clone());
            cur = next;
        }
        Self { layers }
    }

    fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    fn path(&self, mut index: usize) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for d in 0..self.layers.len() - 1 {
            out.push(self.layers[d][index ^ 1]);
            index >>= 1;
        }
        out
    }
}

pub struct FriProof {
    pub version: u8,
    pub layer_roots: Vec<[u8; 32]>,
    pub final_vals: Vec<u64>,
    pub queries: Vec<(u16, Vec<(u64, u64, Vec<[u8; 32]>, Vec<[u8; 32]>)>)>,
}

pub fn prove_bytes(statement: &[u8]) -> FriProof {
    let digest = sha256(&[statement]);
    let mut domain = circle_domain();
    let coeffs = statement_coeffs(statement);
    let mut evals: Vec<u64> = domain.iter().map(|p| eval_on_circle(&coeffs, *p)).collect();
    let mut trees = Vec::new();
    let mut layers = Vec::new();

    for r in 0..FRI_LOG_N - 1 {
        let tree = MerkleTree::new(&evals);
        let lambda = hash_to_m31(&[&digest, &[r as u8], &tree.root(), b"lambda"]);
        let next_n = evals.len() / 2;
        let mut next_e = Vec::with_capacity(next_n);
        let mut next_d = Vec::with_capacity(next_n);
        for i in 0..next_n {
            let j = partner_index(i, evals.len());
            let (nd, nv) = fold_pair(domain[i], evals[i], evals[j], lambda);
            next_e.push(nv);
            next_d.push(nd);
        }
        trees.push(tree);
        layers.push(evals);
        evals = next_e;
        domain = next_d;
    }

    let layer_roots: Vec<[u8; 32]> = trees.iter().map(|t| t.root()).collect();
    let mut seed_parts: Vec<&[u8]> = vec![&digest];
    let root_store = layer_roots.clone();
    for r in &root_store {
        seed_parts.push(r);
    }
    seed_parts.push(b"queries");
    let seed = sha256(&seed_parts);

    let mut queries = Vec::new();
    for q in 0..FRI_QUERIES {
        let start = seed[q] as usize % FRI_N;
        let mut q_layers = Vec::new();
        let mut index = start;
        for r in 0..trees.len() {
            let n = layers[r].len();
            let i = index % n;
            let j = partner_index(i, n);
            q_layers.push((
                layers[r][i],
                layers[r][j],
                trees[r].path(i),
                trees[r].path(j),
            ));
            index = i % (n / 2);
        }
        queries.push((start as u16, q_layers));
    }

    FriProof {
        version: FRI_VERSION,
        layer_roots,
        final_vals: evals,
        queries,
    }
}

pub fn encode_proof(p: &FriProof) -> Vec<u8> {
    let mut out = vec![
        p.version,
        p.layer_roots.len() as u8,
        p.final_vals.len() as u8,
        p.queries.len() as u8,
    ];
    for r in &p.layer_roots {
        out.extend_from_slice(r);
    }
    for f in &p.final_vals {
        out.extend_from_slice(&encode_le(*f));
    }
    for (index, layers) in &p.queries {
        out.extend_from_slice(&index.to_be_bytes());
        out.push(layers.len() as u8);
        for (value, partner, path, partner_path) in layers {
            out.extend_from_slice(&encode_le(*value));
            out.extend_from_slice(&encode_le(*partner));
            out.push(path.len() as u8);
            for n in path {
                out.extend_from_slice(n);
            }
            out.push(partner_path.len() as u8);
            for n in partner_path {
                out.extend_from_slice(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::qm31::SecureField;

    #[test]
    fn m31_wraps() {
        assert_eq!(add_m(M31 - 1, 2), 1);
        assert_eq!(mul_m(2, inv_m(2)), 1);
    }

    #[test]
    fn generator_on_circle() {
        assert!(on_circle(CIRCLE_GEN));
        assert!(on_circle(Point { x: 1, y: 0 }));
        for p in circle_domain() {
            assert!(on_circle(p));
        }
    }

    #[test]
    fn prove_structure() {
        let proof = prove_bytes(b"PAA1STMT-fixture");
        assert_eq!(proof.version, 1);
        assert_eq!(proof.layer_roots.len(), FRI_LOG_N - 1);
        assert_eq!(proof.queries.len(), FRI_QUERIES);
        assert!(encode_proof(&proof).len() > 100);
    }

    #[test]
    fn hello_coeffs_nonzero() {
        let c = statement_coeffs(b"hello");
        assert!(c.iter().any(|x| *x != 0));
    }

    #[test]
    fn local_word_proof_codec_is_canonical_and_transcript_scheduled() {
        let transcript_initial = b"local-word-codec-transcript-v1";
        let construction_descriptor = b"local-word-codec-construction-v1";
        let construction_digest: [u8; 32] = Sha256::digest(construction_descriptor).into();
        let public_words = vec![LocalWordPublicWord {
            id: 1,
            row: 0,
            expected: 0x1234_5678,
        }];
        let matrix_roots: [[u8; 32]; 5] =
            std::array::from_fn(|index| sha256(&[b"local-word-codec-matrix-root", &[index as u8]]));
        let layer_count = LocalWordProofParameters::PRODUCTION.fri_layers();
        let fri_roots = (0..layer_count)
            .map(|index| sha256(&[b"local-word-codec-fri-root", &[index as u8]]))
            .collect::<Vec<_>>();
        let final_coefficients = vec![[0; 4]; 1 << LOCAL_WORD_FRI_CONFIG.final_log_degree];

        let (mut transcript, interaction_challenges, boundary_challenges) =
            local_word_v15_interaction_transcript(
                transcript_initial,
                construction_digest,
                matrix_roots[0],
                matrix_roots[1],
            );
        let (public_boundary_claimed_sum, public_boundary_inverses) =
            local_word_public_boundary_claim_for_words(&public_words, &boundary_challenges)
                .unwrap();
        local_word_v15_public_boundary_transcript(&mut transcript, &public_boundary_inverses)
            .unwrap();
        let interaction_digest = transcript.digest();
        let (constraint_alpha, composition_digest) = local_word_v15_composition_transcript(
            &mut transcript,
            matrix_roots[2],
            matrix_roots[3],
        );
        transcript.absorb("local-word-quotient-and-fri-mask-root", &matrix_roots[4]);
        let batch_beta = transcript.challenge_qm31("local-word-batch-beta");
        let batch_digest = transcript.digest();
        let mut fri_alphas = Vec::with_capacity(fri_roots.len());
        let mut fri_mid_digest = [0u8; 32];
        for (round, root) in fri_roots.iter().enumerate() {
            transcript.absorb(&format!("fri-root:{round}"), root);
            fri_alphas.push(transcript.challenge_qm31(&format!("fri-alpha:{round}")));
            if round + 1 == fri_roots.len().div_ceil(2) {
                fri_mid_digest = transcript.digest();
            }
        }
        let fri_roots_digest = transcript.digest();
        transcript.absorb("fri-final", &encode_qm31_values(&final_coefficients));
        // Production conditioned grinding is covered separately; pin its known
        // nonce here so the canonical byte KAT stays fast.
        let grind_nonce = 441_546;
        assert!(transcript.accept_grind(LOCAL_WORD_FRI_CONFIG.grind_bits, grind_nonce));
        let transcript_manifest = LocalWordTranscriptManifest {
            interaction_challenges: local_word_v15_interaction_challenge_values(
                &interaction_challenges,
                &boundary_challenges,
            ),
            interaction_digest,
            constraint_alpha,
            composition_digest,
            batch_beta,
            batch_digest,
            fri_alphas,
            fri_mid_digest,
            fri_roots_digest,
            query_digest: transcript.digest(),
        };
        let queries =
            local_word_query_indices(&transcript, LocalWordProofParameters::PRODUCTION).unwrap();
        let current = sorted_unique(queries.clone());
        let (global, fri_indices) =
            local_word_opening_schedules(&current, LocalWordProofParameters::PRODUCTION).unwrap();

        let fake_matrix = |index: usize, indices: &[usize]| {
            let row_width = LOCAL_WORD_MATRIX_M31_WIDTHS[index] * 4;
            SuccessorMatrixOpening {
                root: matrix_roots[index],
                row_width,
                indices: indices.to_vec(),
                rows: vec![vec![0; row_width]; indices.len()],
                siblings: vec![
                    [0; 32];
                    canonical_multiproof_sibling_count(
                        indices,
                        1 << LOCAL_WORD_EVAL_LOG,
                    )
                    .unwrap()
                ],
            }
        };
        let matrix_openings = (0..5)
            .map(|index| fake_matrix(index, if index == 3 { &global } else { &current }))
            .collect::<Vec<_>>();
        let fri_layers = fri_indices
            .iter()
            .enumerate()
            .map(|(round, indices)| SuccessorFriLayerProof {
                root: fri_roots[round],
                values: vec![[0; 4]; indices.len()],
                merkle: CanonicalMerkleMultiProof {
                    indices: indices.clone(),
                    siblings: vec![
                        [0; 32];
                        canonical_multiproof_sibling_count(
                            indices,
                            1usize << LocalWordProofParameters::PRODUCTION.fri_layer_logs()[round],
                        )
                        .unwrap()
                    ],
                },
            })
            .collect::<Vec<_>>();
        let proof = LocalWordSealedProof {
            version: LOCAL_WORD_PROOF_VERSION,
            profile: 0,
            construction_digest,
            public_boundary_inverses,
            public_boundary_claimed_sum,
            preprocessed: matrix_openings[0].clone(),
            original: matrix_openings[1].clone(),
            interaction: matrix_openings[2].clone(),
            interaction_global: matrix_openings[3].clone(),
            quotient_and_fri_mask: matrix_openings[4].clone(),
            fri: SuccessorFriProof {
                layers: fri_layers,
                final_coefficients,
                grind_nonce,
            },
            transcript_manifest,
            queries,
            composition_partials: vec![[[0; 4]; 3]; LOCAL_WORD_FRI_CONFIG.queries],
        };

        let encoded = encode_local_word_sealed_proof(&proof).unwrap();
        eprintln!(
            "local-word canonical synthetic bytes {} sha256 {}",
            encoded.len(),
            hex::encode(Sha256::digest(&encoded)),
        );
        assert_eq!(encoded.len(), 333_854);
        assert_eq!(
            hex::encode(Sha256::digest(&encoded)),
            "97b48f0e10ba4f61b0787830981088f99bb9d45b097afd11503afb438788ece0",
        );
        let decoded = decode_local_word_sealed_proof(
            &encoded,
            0,
            transcript_initial,
            construction_descriptor,
            &public_words,
            matrix_roots[0],
        )
        .unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(encode_local_word_sealed_proof(&decoded).unwrap(), encoded);
        assert_eq!(
            u32::from_be_bytes(
                encoded[LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET
                    ..LOCAL_WORD_SEALED_PROOF_LENGTH_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ) as usize,
            encoded.len(),
        );

        let (directory_bytes, directory) = local_word_proof_directory(
            &proof.queries,
            proof.public_boundary_inverses.len(),
            LocalWordProofParameters::PRODUCTION,
        )
        .unwrap();
        let fixed_bytes = 4
            + 1
            + 1
            + 32
            + 4
            + proof.public_boundary_inverses.len() * 16
            + 16
            + matrix_roots.len() * 32
            + fri_roots.len() * 32
            + proof.fri.final_coefficients.len() * 16
            + 4
            + proof.transcript_manifest.interaction_challenges.len() * 16
            + 32
            + 16
            + 32
            + 16
            + 32
            + proof.transcript_manifest.fri_alphas.len() * 16
            + 32 * 3
            + proof.queries.len() * 4
            + current.len() * 4
            + directory_bytes.len()
            + proof.composition_partials.len() * LOCAL_WORD_AIR_PARTIAL_WIDTHS.len() * 16;
        let matrix_body_bytes = local_word_matrix_openings(&proof)
            .iter()
            .enumerate()
            .map(|(matrix, opening)| {
                (if matrix == 3 {
                    opening.indices.len() * 4
                } else {
                    0
                }) + opening.rows.len() * opening.row_width
                    + opening.siblings.len() * 32
                    + encode_local_word_merkle_frontier_bundle(
                        LOCAL_WORD_MATRIX_LABELS[matrix],
                        &opening.indices,
                        &opening.rows,
                        &opening.siblings,
                        LocalWordProofParameters::PRODUCTION.row_count(),
                        local_word_matrix_merkle_stage_geometry(matrix),
                        &directory[matrix],
                    )
                    .unwrap()
                    .len()
            })
            .sum::<usize>();
        let fri_body_bytes = proof
            .fri
            .layers
            .iter()
            .enumerate()
            .map(|(round, layer)| {
                let rows = layer
                    .values
                    .iter()
                    .map(|value| encode_qm31_values(&[*value]))
                    .collect::<Vec<_>>();
                layer.merkle.indices.len() * 4
                    + layer.values.len() * 16
                    + layer.merkle.siblings.len() * 32
                    + encode_local_word_merkle_frontier_bundle(
                        &format!("fri:layer:{round}"),
                        &layer.merkle.indices,
                        &rows,
                        &layer.merkle.siblings,
                        1usize << LocalWordProofParameters::PRODUCTION.fri_layer_logs()[round],
                        LOCAL_WORD_FRI_MERKLE_STAGE_GEOMETRY,
                        &directory[LOCAL_WORD_MATRIX_M31_WIDTHS.len() + round],
                    )
                    .unwrap()
                    .len()
            })
            .sum::<usize>();
        assert_eq!(
            encoded.len(),
            fixed_bytes + matrix_body_bytes + fri_body_bytes
        );
        for root in matrix_roots.iter().chain(&fri_roots) {
            assert_eq!(
                encoded.windows(32).filter(|window| *window == root).count(),
                1
            );
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_local_word_sealed_proof(
            &trailing,
            0,
            transcript_initial,
            construction_descriptor,
            &public_words,
            matrix_roots[0],
        )
        .is_err());
        assert!(decode_local_word_sealed_proof(
            &encoded[..encoded.len() - 1],
            0,
            transcript_initial,
            construction_descriptor,
            &public_words,
            matrix_roots[0],
        )
        .is_err());
        let mut non_field = encoded.clone();
        non_field[42..46].copy_from_slice(&(M31 as u32).to_le_bytes());
        assert!(decode_local_word_sealed_proof(
            &non_field,
            0,
            transcript_initial,
            construction_descriptor,
            &public_words,
            matrix_roots[0],
        )
        .is_err());
    }

    #[test]
    fn local_word_canonical_bytes_verify_end_to_end() {
        let parameters = LocalWordProofParameters {
            relation_log: 11,
            eval_log: 14,
            quotient_degree_rows: 1 << 13,
            fri: SuccessorFriConfig {
                log_blowup: 1,
                final_log_degree: 3,
                fold_log: 2,
                query_orbit_log: 10,
                queries: 8,
                grind_bits: 0,
            },
        };
        let program = LocalShaProgram {
            rows: vec![
                LocalShaOperation::Input { input: 0 },
                LocalShaOperation::Constant {
                    literal: 0x0f0f_0f0f,
                },
                LocalShaOperation::Xor { a: 0, b: 1 },
            ],
            input_count: 1,
            copy_aliases: vec![],
            word_aliases: vec![],
        };
        let public_words = vec![LocalWordPublicWord {
            id: 1,
            row: 0,
            expected: 0x1234_5678,
        }];
        let bundle = LocalWordProverBundle {
            profile: 0,
            relation_rows: 1 << parameters.relation_log,
            transcript_initial: b"local-word-e2e-transcript-v1".to_vec(),
            construction_descriptor: b"local-word-e2e-construction-v1".to_vec(),
            program_bytes: vec![3],
            program: program.clone(),
            inputs: vec![public_words[0].expected],
            public_words: public_words.clone(),
        };
        let directory = std::env::temp_dir().join(format!(
            "shieldkit-local-word-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let result = (|| -> Result<(), String> {
            let wires = execute_local_sha_program(&program, &bundle.inputs)?;
            let permutation = compile_local_sha_word_copy_permutation(&program)?;
            let multiplicities = local_sha_table_multiplicities(&program, &wires)?;
            let relation =
                build_local_word_relation_matrices(&bundle, &wires, &permutation, &multiplicities)?;
            let expected_preprocessed = build_disk_matrix_commitment(
                "local-word:preprocessed",
                &relation.preprocessed,
                DiskColumnExtension::PublicRelation {
                    eval_log: parameters.eval_log,
                },
                &directory.join("verifier-key-preprocessed"),
            )?;
            drop(relation);

            let proved = prove_local_word_bundle_with_parameters(
                bundle.clone(),
                &directory.join("prover"),
                parameters,
            )?;
            if proved.proof.preprocessed.root != expected_preprocessed.root {
                return Err("local-word E2E preprocessed root".into());
            }
            let proof_bytes =
                encode_local_word_sealed_proof_with_parameters(&proved.proof, parameters)?;
            let decoded = decode_local_word_sealed_proof_with_parameters(
                &proof_bytes,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            )?;
            verify_local_word_sealed_proof_with_parameters(
                &decoded,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            )?;
            if encode_local_word_sealed_proof_with_parameters(&decoded, parameters)? != proof_bytes
            {
                return Err("local-word E2E canonical re-encoding".into());
            }

            let mut altered_mask = decoded.clone();
            altered_mask.quotient_and_fri_mask.rows[0][16] ^= 1;
            if verify_local_word_sealed_proof_with_parameters(
                &altered_mask,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            )
            .is_ok()
            {
                return Err("altered local-word mask accepted".into());
            }

            let mut altered_partial = decoded.clone();
            altered_partial.composition_partials[0][0][0] ^= 1;
            if verify_local_word_sealed_proof_with_parameters(
                &altered_partial,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            )
            .is_ok()
            {
                return Err("altered local-word composition partial accepted".into());
            }

            let mut altered_fold = decoded.clone();
            altered_fold.fri.layers[0].values[0][0] ^= 1;
            if verify_local_word_sealed_proof_with_parameters(
                &altered_fold,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            )
            .is_ok()
            {
                return Err("altered local-word FRI fold accepted".into());
            }

            let mut false_words = public_words.clone();
            false_words[0].expected ^= 1;
            if decode_local_word_sealed_proof_with_parameters(
                &proof_bytes,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &false_words,
                expected_preprocessed.root,
                parameters,
            )
            .is_ok()
            {
                return Err("false local-word statement decoded".into());
            }

            let mut altered_bytes = proof_bytes.clone();
            *altered_bytes.last_mut().unwrap() ^= 1;
            if let Ok(altered) = decode_local_word_sealed_proof_with_parameters(
                &altered_bytes,
                bundle.profile,
                &bundle.transcript_initial,
                &bundle.construction_descriptor,
                &public_words,
                expected_preprocessed.root,
                parameters,
            ) {
                if verify_local_word_sealed_proof_with_parameters(
                    &altered,
                    bundle.profile,
                    &bundle.transcript_initial,
                    &bundle.construction_descriptor,
                    &public_words,
                    expected_preprocessed.root,
                    parameters,
                )
                .is_ok()
                {
                    return Err("altered local-word proof bytes accepted".into());
                }
            }
            Ok(())
        })();
        let cleanup = std::fs::remove_dir_all(&directory);
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn local_word_relation_matrices_equal_exact_frames() {
        let program = LocalShaProgram {
            rows: vec![
                LocalShaOperation::Input { input: 0 },
                LocalShaOperation::Constant {
                    literal: 0x0f0f_0f0f,
                },
                LocalShaOperation::Xor { a: 0, b: 1 },
            ],
            input_count: 1,
            copy_aliases: vec![],
            word_aliases: vec![],
        };
        let inputs = vec![0x1234_5678];
        let wires = execute_local_sha_program(&program, &inputs).unwrap();
        let permutation = compile_local_sha_word_copy_permutation(&program).unwrap();
        let multiplicities = local_sha_table_multiplicities(&program, &wires).unwrap();
        let bundle = LocalWordProverBundle {
            profile: 0,
            relation_rows: 2_048,
            transcript_initial: vec![1],
            construction_descriptor: vec![2],
            program_bytes: vec![3],
            program: program.clone(),
            inputs,
            public_words: vec![LocalWordPublicWord {
                id: 1,
                row: 0,
                expected: 0x1234_5678,
            }],
        };
        let matrices =
            build_local_word_relation_matrices(&bundle, &wires, &permutation, &multiplicities)
                .unwrap();
        assert_eq!(
            (matrices.original.len(), matrices.preprocessed.len()),
            (34, 43)
        );
        for row in 0..bundle.relation_rows {
            let frame = local_sha_word_relation_frame_at(
                &program,
                &wires,
                &permutation,
                &multiplicities,
                row,
            )
            .unwrap();
            assert_eq!(
                frame.original,
                matrices
                    .original
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                frame.preprocessed,
                matrices.preprocessed[..40]
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(matrices.preprocessed[40][..4], [1, 0, 0, 0]);
        assert_eq!(matrices.preprocessed[41][..4], [1, 0, 0, 0]);
        assert_eq!(matrices.preprocessed[42][..4], [1, 0, 0, 0]);

        let interaction_challenges = LocalShaV14InteractionChallenges {
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
                    [
                        43 + 18 * limb as u32,
                        47 + 18 * limb as u32,
                        53 + 18 * limb as u32,
                        59 + 18 * limb as u32,
                    ]
                }),
            },
        };
        let boundary_challenges = LocalWordBoundaryChallenges {
            gamma: [11, 13, 17, 19],
            identity: [23, 29, 31, 37],
            limbs: std::array::from_fn(|limb| {
                [
                    41 + 18 * limb as u32,
                    43 + 18 * limb as u32,
                    47 + 18 * limb as u32,
                    53 + 18 * limb as u32,
                ]
            }),
        };
        let interaction = build_local_word_interaction_matrix(
            &bundle,
            &wires,
            &permutation,
            &multiplicities,
            &interaction_challenges,
            &boundary_challenges,
        )
        .unwrap();
        assert_eq!(interaction.columns.len(), 68);
        let samples = local_sha_v14_interaction_samples(
            &program,
            &wires,
            &permutation,
            &multiplicities,
            &interaction_challenges,
            &[0, 1, 2, 2_047],
        )
        .unwrap();
        for sample in samples.samples {
            for (column, value) in sample.columns.iter().enumerate() {
                for coordinate in 0..4 {
                    assert_eq!(
                        interaction.columns[column * 4 + coordinate][sample.row],
                        value[coordinate]
                    );
                }
            }
        }
        let boundary =
            local_word_boundary_samples(&bundle, &wires, &boundary_challenges, &[0, 1, 2, 2_047])
                .unwrap();
        assert_eq!(interaction.boundary_claimed_sum, boundary.claimed_sum);
        for (row, values) in boundary.samples {
            for boundary_column in 0..2 {
                for coordinate in 0..4 {
                    assert_eq!(
                        interaction.columns[60 + boundary_column * 4 + coordinate][row],
                        values[boundary_column][coordinate],
                    );
                }
            }
        }

        let frame_at = |row: usize| {
            let previous = if row == 0 {
                bundle.relation_rows - 1
            } else {
                row - 1
            };
            let original = matrices
                .original
                .iter()
                .map(|column| column[row])
                .collect::<Vec<_>>();
            let preprocessed = matrices
                .preprocessed
                .iter()
                .map(|column| column[row])
                .collect::<Vec<_>>();
            let interaction_row = (0..LOCAL_WORD_INTERACTION_COLUMNS)
                .map(|column| {
                    std::array::from_fn(|coordinate| {
                        interaction.columns[column * 4 + coordinate][row]
                    })
                })
                .collect::<Vec<_>>();
            let interaction_previous = (0..LOCAL_WORD_INTERACTION_COLUMNS)
                .map(|column| {
                    std::array::from_fn(|coordinate| {
                        interaction.columns[column * 4 + coordinate][previous]
                    })
                })
                .collect::<Vec<_>>();
            (
                original,
                preprocessed,
                interaction_row,
                interaction_previous,
            )
        };
        for row in 0..bundle.relation_rows {
            let (original, preprocessed, interaction_row, interaction_previous) = frame_at(row);
            let residuals = local_word_v14_air_residuals(
                &original,
                &preprocessed,
                &interaction_row,
                &interaction_previous,
                &interaction_challenges,
                &boundary_challenges,
                interaction.boundary_claimed_sum,
            )
            .unwrap();
            assert!(
                residuals.iter().all(|residual| *residual == [0; 4]),
                "AIR row {row}"
            );
            assert_eq!(
                mix_local_word_v14_air_residuals(&residuals, [5, 7, 11, 13]).unwrap(),
                [0; 4]
            );
            let partials =
                local_word_v14_air_composition_partials(&residuals, [5, 7, 11, 13]).unwrap();
            assert_eq!(
                combine_local_word_v14_air_composition_partials(partials, [5, 7, 11, 13]),
                mix_local_word_v14_air_residuals(&residuals, [5, 7, 11, 13]).unwrap(),
            );
        }

        let (mut altered_original, preprocessed, interaction_row, interaction_previous) =
            frame_at(2);
        altered_original[16] = add_m31_fast(altered_original[16], 1);
        assert!(local_word_v14_air_residuals(
            &altered_original,
            &preprocessed,
            &interaction_row,
            &interaction_previous,
            &interaction_challenges,
            &boundary_challenges,
            interaction.boundary_claimed_sum,
        )
        .unwrap()
        .iter()
        .any(|residual| *residual != [0; 4]));

        let (original, mut altered_preprocessed, interaction_row, interaction_previous) =
            frame_at(2_047);
        altered_preprocessed[25] = add_m31_fast(altered_preprocessed[25], 1);
        assert!(local_word_v14_air_residuals(
            &original,
            &altered_preprocessed,
            &interaction_row,
            &interaction_previous,
            &interaction_challenges,
            &boundary_challenges,
            interaction.boundary_claimed_sum,
        )
        .unwrap()
        .iter()
        .any(|residual| *residual != [0; 4]));

        let (original, mut altered_preprocessed, interaction_row, interaction_previous) =
            frame_at(0);
        altered_preprocessed[42] = add_m31_fast(altered_preprocessed[42], 1);
        assert!(local_word_v14_air_residuals(
            &original,
            &altered_preprocessed,
            &interaction_row,
            &interaction_previous,
            &interaction_challenges,
            &boundary_challenges,
            interaction.boundary_claimed_sum,
        )
        .unwrap()
        .iter()
        .any(|residual| *residual != [0; 4]));
    }

    #[test]
    fn disk_matrix_commitment_matches_canonical_tree_and_opening() {
        let columns = vec![
            (0..16).map(|row| row * 17 + 3).collect::<Vec<u32>>(),
            (0..16).map(|row| row * row + 11).collect::<Vec<u32>>(),
        ];
        let mut expected = columns
            .iter()
            .map(|column| relation_trace_lde(column, 6))
            .collect::<Vec<_>>();
        bit_reverse_m31_columns(&mut expected);
        let tree = CanonicalMerkleTree4::from_matrix("disk-matrix-test", &expected);
        let directory = std::env::temp_dir().join(format!(
            "shieldkit-disk-matrix-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let result = (|| -> Result<(), String> {
            let disk = build_disk_matrix_commitment(
                "disk-matrix-test",
                &columns,
                DiskColumnExtension::PublicRelation { eval_log: 6 },
                &directory,
            )?;
            assert_eq!(disk.root, tree.root());
            assert_eq!((disk.row_count, disk.column_count), (64, 2));
            let opening = disk.opening(&[1, 7, 23])?;
            let rows = opening
                .indices
                .iter()
                .zip(&opening.rows)
                .map(|(index, row)| (*index, row.clone()))
                .collect::<Vec<_>>();
            let multiproof = CanonicalMerkleMultiProof {
                indices: opening.indices.clone(),
                siblings: opening.siblings.clone(),
            };
            assert!(verify_matrix_multiproof4(
                "disk-matrix-test",
                &rows,
                &multiproof,
                disk.row_count,
                disk.root,
            ));
            Ok(())
        })();
        let cleanup = std::fs::remove_dir_all(&directory);
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn local_word_committed_rows_reconstruct_composition_and_quotient() {
        let program = LocalShaProgram {
            rows: vec![
                LocalShaOperation::Input { input: 0 },
                LocalShaOperation::Constant {
                    literal: 0x0f0f_0f0f,
                },
                LocalShaOperation::Xor { a: 0, b: 1 },
            ],
            input_count: 1,
            copy_aliases: vec![],
            word_aliases: vec![],
        };
        let inputs = vec![0x1234_5678];
        let bundle = LocalWordProverBundle {
            profile: 0,
            relation_rows: 2_048,
            transcript_initial: vec![1],
            construction_descriptor: vec![2],
            program_bytes: vec![3],
            program: program.clone(),
            inputs: inputs.clone(),
            public_words: vec![LocalWordPublicWord {
                id: 1,
                row: 0,
                expected: inputs[0],
            }],
        };
        let interaction_challenges = LocalShaV14InteractionChallenges {
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
                    [
                        43 + 18 * limb as u32,
                        47 + 18 * limb as u32,
                        53 + 18 * limb as u32,
                        59 + 18 * limb as u32,
                    ]
                }),
            },
        };
        let boundary_challenges = LocalWordBoundaryChallenges {
            gamma: [11, 13, 17, 19],
            identity: [23, 29, 31, 37],
            limbs: std::array::from_fn(|limb| {
                [
                    41 + 18 * limb as u32,
                    43 + 18 * limb as u32,
                    47 + 18 * limb as u32,
                    53 + 18 * limb as u32,
                ]
            }),
        };
        let wires = execute_local_sha_program(&program, &inputs).unwrap();
        let permutation = compile_local_sha_word_copy_permutation(&program).unwrap();
        let multiplicities = local_sha_table_multiplicities(&program, &wires).unwrap();
        let relation =
            build_local_word_relation_matrices(&bundle, &wires, &permutation, &multiplicities)
                .unwrap();
        let interaction = build_local_word_interaction_matrix(
            &bundle,
            &wires,
            &permutation,
            &multiplicities,
            &interaction_challenges,
            &boundary_challenges,
        )
        .unwrap();
        let boundary_claimed_sum = interaction.boundary_claimed_sum;
        let boundary_inverses = interaction.boundary_inverses.clone();
        let mut tail_at_zero = Vec::new();
        for column in LOCAL_WORD_GLOBAL_INTERACTION_QM31_COLUMNS {
            for coordinate in 0..4 {
                tail_at_zero.push(interaction.columns[column * 4 + coordinate][0]);
            }
        }
        let ordered = local_word_interaction_commit_order(interaction.columns).unwrap();
        assert_eq!(
            ordered[56..68]
                .iter()
                .map(|column| column[0])
                .collect::<Vec<_>>(),
            tail_at_zero
        );

        let directory = std::env::temp_dir().join(format!(
            "shieldkit-local-word-composition-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let result = (|| -> Result<(), String> {
            let preprocessed = build_disk_matrix_commitment(
                "local-word-test:preprocessed",
                &relation.preprocessed,
                DiskColumnExtension::PublicRelation { eval_log: 12 },
                &directory.join("preprocessed"),
            )?;
            let original = build_disk_matrix_commitment(
                "local-word-test:original",
                &relation.original,
                DiskColumnExtension::SealedRelation { log_blowup: 0 },
                &directory.join("original"),
            )?;
            let interaction = build_disk_matrix_commitment(
                "local-word-test:interaction",
                &ordered[..LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH],
                DiskColumnExtension::SealedRelation { log_blowup: 0 },
                &directory.join("interaction"),
            )?;
            let interaction_global = build_disk_matrix_commitment(
                "local-word-test:interaction-global",
                &ordered[LOCAL_WORD_INTERACTION_CURRENT_M31_WIDTH..],
                DiskColumnExtension::SealedRelation { log_blowup: 0 },
                &directory.join("interaction-global"),
            )?;
            let committed = LocalWordCommittedRelation {
                preprocessed,
                original,
                interaction,
                interaction_global,
                interaction_challenges,
                boundary_challenges,
                boundary_claimed_sum,
                boundary_inverses,
                interaction_transcript_digest: [0; 32],
                constraint_alpha: [5, 7, 11, 13],
                composition_transcript_digest: [0; 32],
            };
            let sample_indices = [0, 1, 17, 2_048, 4_095];
            let mut expected_quotients = Vec::new();
            let mut composition_samples = Vec::new();
            for index in sample_indices {
                let evaluated =
                    local_word_composition_at_committed_row_with_trace_log(&committed, index, 11)?;
                assert_eq!(
                    qm31_to_secure(evaluated.quotient)
                        * BaseField::from_u32_unchecked(evaluated.zerofier),
                    qm31_to_secure(evaluated.composition),
                );
                expected_quotients.push(evaluated.quotient);
                composition_samples.push(evaluated);
            }
            let raw = build_local_word_raw_quotient_with_trace_log(
                &committed,
                &directory.join("raw-quotient"),
                11,
            )?;
            let raw_values = raw.values()?;
            assert_eq!(raw_values.len(), 4_096);
            assert_eq!(
                sample_indices
                    .iter()
                    .map(|index| raw_values[*index])
                    .collect::<Vec<_>>(),
                expected_quotients,
            );
            let sealed = build_local_word_quotient_seal_with_degree(
                &raw,
                &directory.join("quotient-seal-0"),
                2_048,
            )?;
            for (sample, index) in composition_samples.iter().zip(sample_indices) {
                let quotient: Qm31Value = sealed.quotient.row_values(index)?.try_into().unwrap();
                assert_eq!(quotient, sample.quotient);
                assert!(local_word_quotient_identity(
                    sample.composition,
                    sample.zerofier,
                    quotient,
                ));
            }
            let fresh = build_local_word_quotient_seal_with_degree(
                &raw,
                &directory.join("quotient-seal-1"),
                2_048,
            )?;
            assert_ne!(fresh.fri_mask.root, sealed.fri_mask.root);
            assert_eq!(fresh.quotient.root, sealed.quotient.root);
            let beta = [101, 103, 107, 109];
            let batch = build_local_word_fri_batch_at_rows(
                &committed,
                &sealed,
                beta,
                &directory.join("fri-batch"),
            )?;
            let batch_values = batch.values()?;
            for index in sample_indices {
                let original = committed.original.row_values(index)?;
                let current = committed.interaction.row_values(index)?;
                let global = committed.interaction_global.row_values(index)?;
                let quotient: Qm31Value = sealed.quotient.row_values(index)?.try_into().unwrap();
                let fri_mask: Qm31Value =
                    sealed.fri_mask.row_values(index)?.try_into().unwrap();
                assert_eq!(
                    batch_values[index],
                    local_word_fri_batch_value(
                        &original,
                        [&current[..20], &current[20..40], &current[40..56], &global,],
                        quotient,
                        fri_mask,
                        beta,
                    )?,
                );
            }
            Ok(())
        })();
        let cleanup = std::fs::remove_dir_all(&directory);
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn stwo_circle_lde_is_stable_at_zero_blowup() {
        let values: Vec<u32> = (0..64).map(|i| (i * i + 3 * i + 7) as u32).collect();
        assert_eq!(circle_lde(&values, 0), values);
        assert_eq!(circle_lde(&values, 4).len(), 1024);
    }

    #[test]
    fn successor_column_lde_shape() {
        let values: Vec<u32> = (0..8192)
            .map(|i| ((i * 17 + 9) % M31 as usize) as u32)
            .collect();
        let lde = circle_lde(&values, 4);
        assert_eq!(lde.len(), 131_072);
        assert!(lde.iter().all(|value| (*value as u64) < M31));
    }

    #[test]
    fn secret_seal_preserves_trace_and_uses_next_degree_bucket() {
        let trace_log = 6;
        let values: Vec<u32> = (0..1 << trace_log)
            .map(|i| (i * i + 11 * i + 5) as u32)
            .collect();
        let mask: Vec<BaseField> = (0..64)
            .map(|i| BaseField::from((i * 29 + 3) as u32))
            .collect();
        let sealed = seal_circle_lde_with_coeffs(&values, 5, mask);
        let sealed_poly = interpolate_natural(sealed);
        let trace_domain = CanonicCoset::new(trace_log).circle_domain();
        let expected = logical_coset_values_to_circle_order(&values);
        for (point, value) in trace_domain.iter().zip(expected) {
            assert_eq!(
                sealed_poly.eval_at_point(point.into_ef()),
                SecureField::from(value)
            );
        }

        let highest = sealed_poly
            .coeffs
            .iter()
            .rposition(|value| value.0 != 0)
            .unwrap();
        assert!(
            highest >= 1 << trace_log,
            "mask must leave the original degree bucket"
        );
        assert!(
            highest < 1 << (trace_log + 1),
            "seal must fit the next degree bucket"
        );
    }

    #[test]
    fn fresh_seals_do_not_repeat() {
        let values: Vec<u32> = (0..64).map(|i| i as u32).collect();
        assert_ne!(
            seal_circle_lde(&values, 5, 4),
            seal_circle_lde(&values, 5, 4)
        );
    }

    #[test]
    fn successor_polynomial_mask_column_shape() {
        let values: Vec<u32> = (0..8192)
            .map(|i| ((i * 31 + 7) % M31 as usize) as u32)
            .collect();
        let sealed = seal_circle_lde(&values, 6, 9);
        assert_eq!(sealed.len(), 524_288);
    }

    #[test]
    fn successor_relation_seal_column_shape() {
        let values: Vec<u32> = (0..8192)
            .map(|i| ((i * 31 + 7) % M31 as usize) as u32)
            .collect();
        assert_eq!(seal_relation_trace_lde(&values, 5).len(), 524_288);
    }

    #[test]
    fn relation_trace_uses_canonical_coset_order_and_membrane_equation() {
        let trace_log = 6;
        let values: Vec<u32> = (0..1 << trace_log)
            .map(|i| (i * i + 13 * i + 1) as u32)
            .collect();
        let sealed = seal_relation_trace_lde(&values, 4);
        assert_eq!(sealed.len(), 1 << (trace_log + 1 + 4));
        let sealed_poly = interpolate_natural(sealed);
        let relation_domain = CanonicCoset::new(trace_log).circle_domain();
        let expected = logical_coset_values_to_circle_order(&values);
        for (point, value) in relation_domain.iter().zip(expected) {
            assert_eq!(
                sealed_poly.eval_at_point(point.into_ef()),
                SecureField::from(value)
            );
        }
    }

    #[test]
    fn canonical_relation_zerofier_selects_exactly_the_trace_coset() {
        let trace_log = 6;
        let relation_coset = CanonicCoset::new(trace_log).coset;
        let z = |point| coset_vanishing(relation_coset, point);
        assert!(CanonicCoset::new(trace_log)
            .circle_domain()
            .iter()
            .all(|point| z(point).0 == 0));
        assert!(CanonicCoset::new(trace_log + 1)
            .circle_domain()
            .iter()
            .all(|point| z(point).0 != 0));
    }

    #[test]
    fn relation_trace_seals_are_fresh() {
        let values: Vec<u32> = (0..64).map(|i| i as u32).collect();
        assert_ne!(
            seal_relation_trace_lde(&values, 4),
            seal_relation_trace_lde(&values, 4)
        );
    }

    #[test]
    fn successor_matrix_seal_is_parallel_fresh_and_row_committed() {
        let columns: Vec<Vec<u32>> = (0..4)
            .map(|column| {
                (0..64)
                    .map(|row| (column * 1000 + row * 17 + 3) as u32)
                    .collect()
            })
            .collect();
        let first = seal_relation_trace_matrix_lde(&columns, 1);
        let second = seal_relation_trace_matrix_lde(&columns, 1);
        assert_eq!(first.len(), 4);
        assert!(first.iter().all(|column| column.len() == 256));
        assert_ne!(first, second);
        assert_ne!(
            sealed_matrix_root("sealed-test", &first),
            sealed_matrix_root("sealed-test", &second)
        );

        let mut changed = first.clone();
        changed[2][19] ^= 1;
        assert_ne!(
            sealed_matrix_root("sealed-test", &first),
            sealed_matrix_root("sealed-test", &changed)
        );
    }

    #[test]
    fn canonical_matrix_merkle_matches_typescript_known_answer() {
        let columns = vec![vec![3, 17, 31, 45], vec![1003, 1017, 1031, 1045]];
        assert_eq!(
            hex::encode(sealed_matrix_root("kat-matrix", &columns)),
            "2068701f436d3535d7444aed74a1bee641bd92e6c61f3c79e4f71eb82ccc6401"
        );
    }

    #[test]
    fn canonical_qm31_multiproof_shares_frontier_and_rejects_mutations() {
        let values: Vec<Qm31Value> = (0..16)
            .map(|row| std::array::from_fn(|coordinate| (row * 101 + coordinate * 17 + 9) as u32))
            .collect();
        let tree = CanonicalMerkleTree::from_qm31("fri:layer:0", &values);
        let proof = tree.multiproof(&[0, 1, 2, 7, 8, 15]);
        let rows: Vec<(usize, Qm31Value)> = proof
            .indices
            .iter()
            .map(|index| (*index, values[*index]))
            .collect();
        assert!(proof.siblings.len() < proof.indices.len() * 4);
        assert!(verify_qm31_multiproof(
            "fri:layer:0",
            &rows,
            &proof,
            16,
            tree.root()
        ));

        let mut changed_rows = rows.clone();
        changed_rows[2].1[0] ^= 1;
        assert!(!verify_qm31_multiproof(
            "fri:layer:0",
            &changed_rows,
            &proof,
            16,
            tree.root()
        ));
        let mut changed_proof = proof.clone();
        changed_proof.siblings[0][0] ^= 1;
        assert!(!verify_qm31_multiproof(
            "fri:layer:0",
            &rows,
            &changed_proof,
            16,
            tree.root()
        ));
        assert!(!verify_qm31_multiproof(
            "fri:layer:1",
            &rows,
            &proof,
            16,
            tree.root()
        ));
    }

    #[test]
    fn canonical_qm31_merkle4_matches_typescript_and_rejects_mutations() {
        let values: Vec<Qm31Value> = (0..16)
            .map(|row| std::array::from_fn(|coordinate| (row * 101 + coordinate * 17 + 9) as u32))
            .collect();
        let tree = CanonicalMerkleTree4::from_qm31("fri:layer:0", &values);
        assert_eq!(
            hex::encode(tree.root()),
            "8e85e234ddfe4efce5b2fc1f640d008976de4b8142b11ca8ebac26ba8dd8967f"
        );
        let proof = tree.multiproof(&[0, 1, 2, 7, 8, 15]);
        assert_eq!(proof.siblings.len(), 10);
        let rows: Vec<(usize, Qm31Value)> = proof
            .indices
            .iter()
            .map(|index| (*index, values[*index]))
            .collect();
        assert!(verify_qm31_multiproof4(
            "fri:layer:0",
            &rows,
            &proof,
            16,
            tree.root()
        ));

        let mut changed_rows = rows.clone();
        changed_rows[2].1[0] ^= 1;
        assert!(!verify_qm31_multiproof4(
            "fri:layer:0",
            &changed_rows,
            &proof,
            16,
            tree.root()
        ));
        let mut changed_proof = proof.clone();
        changed_proof.siblings[0][0] ^= 1;
        assert!(!verify_qm31_multiproof4(
            "fri:layer:0",
            &rows,
            &changed_proof,
            16,
            tree.root()
        ));
        assert!(!verify_qm31_multiproof4(
            "fri:layer:1",
            &rows,
            &proof,
            16,
            tree.root()
        ));
    }

    #[test]
    fn successor_transcript_matches_typescript_known_answer() {
        let mut transcript = SuccessorTranscript::new(b"transcript-kat");
        transcript.absorb("statement", &[1, 2, 3, 4]);
        assert_eq!(
            transcript.challenge_qm31("fri-alpha:0"),
            [641_955_534, 1_156_760_623, 378_207_287, 2_059_957_541]
        );
        transcript.absorb("fri-root:1", &[0xa5; 32]);
        assert_eq!(
            transcript.challenge_qm31("fri-alpha:1"),
            [286_744_312, 1_230_511_567, 1_287_274_865, 1_635_578_672]
        );
        assert_eq!(transcript.grind_for_queries(8, 512, 12), 18);
        assert_eq!(
            transcript.query_indices(512, 12),
            vec![86, 267, 415, 124, 170, 180, 10, 65, 100, 311, 491, 404]
        );
        assert_eq!(
            hex::encode(transcript.digest()),
            "f47eae2692e04be72e91eb15d33f966dd849323106cd03ff083b2e5c732d3f34"
        );
    }

    #[test]
    fn vertical_transcript_matches_typescript_known_answer() {
        let mut transcript = VerticalTranscript::new(b"vertical transcript KAT");
        transcript.absorb("root", &[7; 32]);
        assert_eq!(
            transcript.challenge_qm31("alpha"),
            [1_556_270_023, 1_530_621_168, 1_662_953_229, 976_546_177]
        );
        assert_eq!(transcript.grind(8), 477);
        let queries = transcript.query_indices(1 << 24, 28);
        assert_eq!(
            queries
                .iter()
                .map(|query| query >> 1)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            28
        );
    }

    #[test]
    fn successor_domain_matches_typescript_known_answer() {
        let circle = CanonicCoset::new(6).circle_domain();
        let p0 = circle.at(bit_reverse_index(0, 6));
        let p13 = circle.at(bit_reverse_index(13, 6));
        assert_eq!((p0.x.0, p0.y.0), (838_195_206, 1_774_253_895));
        assert_eq!((p13.x.0, p13.y.0), (262_191_051, 1_739_004_854));
        let line = LineDomain::new(Coset::half_odds(5));
        assert_eq!(line.at(bit_reverse_index(0, 5)).0, 838_195_206);
        assert_eq!(line.at(bit_reverse_index(13, 5)).0, 350_742_286);
        assert_eq!(
            stwo::core::utils::offset_bit_reversed_circle_domain_index(12345, 13, 18, -7),
            5177
        );
    }

    #[test]
    fn qm31_quotient_division_and_independent_fri_mask_are_exact() {
        let degree_rows = 64;
        let log_blowup = 3;
        let quotient_seed: Vec<Qm31Value> = (0..degree_rows)
            .map(|row| std::array::from_fn(|coordinate| (row * 31 + coordinate * 101 + 7) as u32))
            .collect();
        let quotient_lde = circle_lde_qm31(&quotient_seed, log_blowup);
        let zerofier = trace_zerofier_values(quotient_lde.len().ilog2(), 5);
        let composition_lde: Vec<Qm31Value> = quotient_lde
            .iter()
            .zip(zerofier)
            .map(|(value, z)| {
                std::array::from_fn(|coordinate| mul_m(value[coordinate] as u64, z as u64) as u32)
            })
            .collect();
        assert_eq!(
            divide_composition_by_trace_zerofier(&composition_lde, 5),
            quotient_lde
        );
        let mut quotient_bit_reversed = quotient_lde.clone();
        let mut composition_bit_reversed = composition_lde.clone();
        stwo::core::utils::bit_reverse(&mut quotient_bit_reversed);
        stwo::core::utils::bit_reverse(&mut composition_bit_reversed);
        assert_eq!(
            divide_composition_by_trace_zerofier_bit_reversed(&composition_bit_reversed, 5),
            quotient_bit_reversed
        );
        assert!(qm31_circle_degree_bound_bit_reversed(&quotient_bit_reversed) <= degree_rows);

        let mask_a = fresh_qm31_lde(degree_rows, log_blowup);
        let mask_b = fresh_qm31_lde(degree_rows, log_blowup);
        assert_ne!(mask_a, mask_b);
        assert_ne!(
            qm31_oracle_root("fri-mask", &mask_a),
            qm31_oracle_root("fri-mask", &mask_b)
        );
    }

    #[test]
    fn successor_fri_uses_pinned_stwo_folds_and_rejects_high_degree_data() {
        let seed: Vec<Qm31Value> = (0..64)
            .map(|row| std::array::from_fn(|coordinate| (row * 19 + coordinate * 73 + 5) as u32))
            .collect();
        let codeword = circle_lde_qm31(&seed, 3);
        let alphas: Vec<Qm31Value> = (0..4)
            .map(|round| {
                std::array::from_fn(|coordinate| (round * 101 + coordinate * 29 + 11) as u32)
            })
            .collect();
        let folded = successor_fri_fold_layers(&codeword, &alphas, 3, 2).unwrap();
        assert_eq!(
            folded.layers.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![512, 256, 128, 64]
        );
        assert_eq!(folded.final_coefficients.len(), 4);

        let mut invalid = codeword;
        invalid[137][2] ^= 1;
        assert_eq!(
            successor_fri_fold_layers(&invalid, &alphas, 3, 2),
            Err("FRI final degree")
        );
    }

    #[test]
    fn successor_fri_one_transcript_multiproof_rejects_all_mutation_classes() {
        let seed: Vec<Qm31Value> = (0..64)
            .map(|row| std::array::from_fn(|coordinate| (row * 23 + coordinate * 61 + 7) as u32))
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
        let mut prover_transcript = SuccessorTranscript::new(b"successor-fri-test");
        prover_transcript.absorb("statement", b"fixed-public-statement");
        let proof = prove_successor_fri(&codeword, &mut prover_transcript, config).unwrap();
        assert_eq!(proof.layers.len(), 4);
        let encoded = encode_successor_fri_proof(&proof);
        assert_eq!(decode_successor_fri_proof(&encoded).unwrap(), proof);
        assert!(decode_successor_fri_proof(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_successor_fri_proof(&trailing).is_err());
        let verify = |candidate: &SuccessorFriProof| {
            let mut transcript = SuccessorTranscript::new(b"successor-fri-test");
            transcript.absorb("statement", b"fixed-public-statement");
            verify_successor_fri(candidate, 9, &mut transcript, config)
        };
        assert_eq!(verify(&proof), Ok(()));

        let mut changed_value = proof.clone();
        changed_value.layers[0].values[0][0] ^= 1;
        assert!(verify(&changed_value).is_err());
        let mut changed_path = proof.clone();
        changed_path.layers[0].merkle.siblings[0][0] ^= 1;
        assert!(verify(&changed_path).is_err());
        let mut changed_root = proof.clone();
        changed_root.layers[1].root[0] ^= 1;
        assert!(verify(&changed_root).is_err());
        let mut changed_final = proof.clone();
        changed_final.final_coefficients[0][0] ^= 1;
        assert!(verify(&changed_final).is_err());
        let mut changed_grind = proof.clone();
        changed_grind.grind_nonce ^= 1;
        assert!(verify(&changed_grind).is_err());

        let mut non_field = proof.clone();
        non_field.layers[0].values[0][0] = M31 as u32;
        assert_eq!(verify(&non_field), Err("FRI field"));
    }

    #[test]
    fn successor_sealed_proof_has_one_strict_canonical_codec() {
        let seed: Vec<Qm31Value> = (0..64)
            .map(|row| std::array::from_fn(|coordinate| (row * 23 + coordinate * 61 + 7) as u32))
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
        let mut transcript = SuccessorTranscript::new(b"sealed-proof-codec");
        let fri = prove_successor_fri(&codeword, &mut transcript, config).unwrap();
        let opening = SuccessorMatrixOpening {
            root: [0x31; 32],
            row_width: 8,
            indices: vec![3, 17],
            rows: vec![
                [7u32.to_le_bytes(), 11u32.to_le_bytes()].concat(),
                [13u32.to_le_bytes(), 19u32.to_le_bytes()].concat(),
            ],
            siblings: vec![[0x42; 32], [0x53; 32]],
        };
        let proof = SuccessorSealedProof {
            profile: 2,
            air_program_hash: [0x19; 32],
            transcript_initial: b"sealed-proof-codec".to_vec(),
            preprocessed: opening.clone(),
            sha: opening.clone(),
            sha_aux: opening.clone(),
            bus: opening.clone(),
            quotient: opening.clone(),
            fri_mask: opening,
            constraint_alpha: [29, 31, 37, 41],
            constraint_transcript_digest: [0x23; 32],
            constraint_coefficient_seed: [0x27; 32],
            partial_challenges: [[9u32; POOL_AIR_HORNER_LANES]; 8],
            compression_challenges: [[1, 2, 3, 4]; POOL_AIR_HORNER_LANES],
            composition_partials: vec![
                [[1u32; POOL_AIR_HORNER_LANES]; 8],
                [[5u32; POOL_AIR_HORNER_LANES]; 8],
            ],
            batch_beta: [43, 47, 53, 59],
            fri_transcript_digest: [0x61; 32],
            fri_alphas: vec![[67, 71, 73, 79]; fri.layers.len()],
            query_digest: [0x83; 32],
            queries: (0..SuccessorFriConfig::PRODUCTION.queries).collect(),
            fri,
        };
        let encoded = encode_successor_sealed_proof(&proof);
        assert_eq!(decode_successor_sealed_proof(&encoded).unwrap(), proof);
        assert!(decode_successor_sealed_proof(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_successor_sealed_proof(&trailing).is_err());
    }
}
