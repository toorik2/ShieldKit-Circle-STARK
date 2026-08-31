use rayon::prelude::*;
use std::fs::{File, create_dir};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::cpu::{CpuCircleEvaluation, CpuCirclePoly};
use stwo::prover::poly::NaturalOrder;

use crate::{
    M31, Qm31Value, SuccessorMatrixOpening, V17MerkleDescriptor, V17Qm31CirclePoint, fresh_m31,
    logical_coset_values_to_circle_order, qm31_to_secure, raw_leaf, secure_to_qm31,
    v17_merkle_parent, v17_merkle_tree_key,
};

const POLYNOMIAL_SIDECAR_MAGIC: &[u8; 4] = b"SKPS";
const POLYNOMIAL_SIDECAR_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskPolynomialSidecarKind {
    /** One exact M31 Circle polynomial. */
    Exact,
    /** The single masked polynomial `w + Z_H r`; bare `w` and `r` are not persisted. */
    SealedRelation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskPolynomialSidecarInfo {
    pub kind: DiskPolynomialSidecarKind,
    pub polynomial_log_size: u32,
    pub sealed_relation_log_size: Option<u32>,
}

struct DiskPolynomialSidecar {
    kind: DiskPolynomialSidecarKind,
    relation_log_size: u32,
    /** Exact committed polynomial; sealed sidecars never persist bare w or r. */
    polynomial: CpuCirclePoly,
}

struct ExtendedDiskColumn {
    bit_reversed_lde: Vec<u32>,
    sidecar: DiskPolynomialSidecar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskColumnExtension {
    /** Secret `w + Z_H r`; expansion is measured from the sealed degree bucket. */
    SealedRelation { log_blowup: u32 },
    /** Deterministic public relation polynomial evaluated at `eval_log`. */
    PublicRelation { eval_log: u32 },
    /** Already-uniform private polynomial evaluated at `eval_log`. */
    RandomPolynomial { eval_log: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskMatrixCommitment {
    pub label: String,
    pub directory: PathBuf,
    pub row_count: usize,
    pub column_count: usize,
    pub root: [u8; 32],
    pub layer_count: usize,
}

pub struct DiskMatrixColumnReader {
    readers: Vec<BufReader<File>>,
    row_count: usize,
    cursor: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskQm31Evaluation {
    pub directory: PathBuf,
    pub row_count: usize,
}

pub struct DiskQm31Writer {
    directory: PathBuf,
    row_count: usize,
    written: usize,
    writers: [BufWriter<File>; 4],
}

fn io_error(context: &str, error: std::io::Error) -> String {
    format!("{context}: {error}")
}

fn column_path(directory: &Path, column: usize) -> PathBuf {
    directory.join(format!("column-{column:04}.bin"))
}

fn polynomial_sidecar_path(directory: &Path, column: usize) -> PathBuf {
    directory.join(format!("polynomial-{column:04}.bin"))
}

fn layer_path(directory: &Path, layer: usize) -> PathBuf {
    directory.join(format!("layer-{layer:02}.bin"))
}

fn write_u32_column(path: &Path, values: &[u32]) -> Result<(), String> {
    let file = File::create(path).map_err(|error| io_error("create disk oracle column", error))?;
    let mut writer = BufWriter::new(file);
    const VALUES_PER_CHUNK: usize = 1 << 16;
    for chunk in values.chunks(VALUES_PER_CHUNK) {
        let mut bytes = Vec::with_capacity(chunk.len() * 4);
        for value in chunk {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        writer
            .write_all(&bytes)
            .map_err(|error| io_error("write disk oracle column", error))?;
    }
    writer
        .flush()
        .map_err(|error| io_error("flush disk oracle column", error))
}

fn interpolate_logical_relation(values: &[u32]) -> CpuCirclePoly {
    let log_size = values.len().ilog2();
    let natural: CpuCircleEvaluation<BaseField, NaturalOrder> = CpuCircleEvaluation::new(
        CanonicCoset::new(log_size).circle_domain(),
        logical_coset_values_to_circle_order(values),
    );
    natural.bit_reverse().interpolate()
}

fn evaluate_polynomial_natural(poly: &CpuCirclePoly, eval_log: u32) -> Vec<BaseField> {
    poly.evaluate(CanonicCoset::new(eval_log).circle_domain())
        .bit_reverse()
        .values
}

fn extend_column(values: &[u32], extension: DiskColumnExtension) -> ExtendedDiskColumn {
    let witness = interpolate_logical_relation(values);
    let relation_log_size = values.len().ilog2();
    let (mut lde, sidecar): (Vec<u32>, DiskPolynomialSidecar) = match extension {
        DiskColumnExtension::SealedRelation { log_blowup } => {
            let eval_log = relation_log_size + log_blowup + 1;
            let randomizer =
                CpuCirclePoly::new((0..values.len()).map(|_| fresh_m31()).collect::<Vec<_>>());
            let sealed_log = relation_log_size + 1;
            let witness_seal_domain = evaluate_polynomial_natural(&witness, sealed_log);
            let randomizer_seal_domain = evaluate_polynomial_natural(&randomizer, sealed_log);
            let trace_coset = CanonicCoset::new(relation_log_size).coset;
            let sealed_domain = CanonicCoset::new(sealed_log).circle_domain();
            let sealed_values = sealed_domain
                .iter()
                .zip(witness_seal_domain)
                .zip(randomizer_seal_domain)
                .map(|((point, witness_value), randomizer_value)| {
                    (witness_value + coset_vanishing(trace_coset, point) * randomizer_value).0
                })
                .collect::<Vec<_>>();
            let sealed: CpuCircleEvaluation<BaseField, NaturalOrder> = CpuCircleEvaluation::new(
                sealed_domain,
                sealed_values
                    .into_iter()
                    .map(BaseField::from_u32_unchecked)
                    .collect(),
            );
            let sealed = sealed.bit_reverse().interpolate();
            let lde = evaluate_polynomial_natural(&sealed, eval_log)
                .into_iter()
                .map(|value| value.0)
                .collect();
            (
                lde,
                DiskPolynomialSidecar {
                    kind: DiskPolynomialSidecarKind::SealedRelation,
                    relation_log_size,
                    polynomial: sealed,
                },
            )
        }
        DiskColumnExtension::PublicRelation { eval_log }
        | DiskColumnExtension::RandomPolynomial { eval_log } => (
            evaluate_polynomial_natural(&witness, eval_log)
                .into_iter()
                .map(|value| value.0)
                .collect(),
            DiskPolynomialSidecar {
                kind: DiskPolynomialSidecarKind::Exact,
                relation_log_size,
                polynomial: witness,
            },
        ),
    };
    stwo::core::utils::bit_reverse(&mut lde);
    ExtendedDiskColumn {
        bit_reversed_lde: lde,
        sidecar,
    }
}

fn write_polynomial_coefficients(
    writer: &mut BufWriter<File>,
    coefficients: &[BaseField],
) -> Result<(), String> {
    const VALUES_PER_CHUNK: usize = 1 << 16;
    for chunk in coefficients.chunks(VALUES_PER_CHUNK) {
        let mut bytes = Vec::with_capacity(chunk.len() * 4);
        for value in chunk {
            bytes.extend_from_slice(&value.0.to_le_bytes());
        }
        writer
            .write_all(&bytes)
            .map_err(|error| io_error("write disk polynomial sidecar coefficients", error))?;
    }
    Ok(())
}

fn write_polynomial_sidecar(path: &Path, sidecar: &DiskPolynomialSidecar) -> Result<(), String> {
    let polynomial_count = sidecar.polynomial.coeffs.len();
    let expected_log = sidecar.relation_log_size
        + u32::from(sidecar.kind == DiskPolynomialSidecarKind::SealedRelation);
    if polynomial_count == 0
        || !polynomial_count.is_power_of_two()
        || polynomial_count.ilog2() != expected_log
        || polynomial_count > u32::MAX as usize
    {
        return Err("disk polynomial sidecar shape".into());
    }
    let file =
        File::create(path).map_err(|error| io_error("create disk polynomial sidecar", error))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(POLYNOMIAL_SIDECAR_MAGIC)
        .and_then(|_| writer.write_all(&[POLYNOMIAL_SIDECAR_VERSION]))
        .and_then(|_| {
            writer.write_all(&[match sidecar.kind {
                DiskPolynomialSidecarKind::Exact => 0,
                DiskPolynomialSidecarKind::SealedRelation => 1,
            }])
        })
        .and_then(|_| writer.write_all(&[0, 0]))
        .and_then(|_| writer.write_all(&sidecar.relation_log_size.to_le_bytes()))
        .and_then(|_| writer.write_all(&(polynomial_count as u32).to_le_bytes()))
        .and_then(|_| writer.write_all(&0u32.to_le_bytes()))
        .map_err(|error| io_error("write disk polynomial sidecar header", error))?;
    write_polynomial_coefficients(&mut writer, &sidecar.polynomial.coeffs)?;
    writer
        .flush()
        .map_err(|error| io_error("flush disk polynomial sidecar", error))
}

fn read_u32_le(reader: &mut BufReader<File>, context: &str) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| io_error(context, error))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_polynomial_coefficients(
    reader: &mut BufReader<File>,
    count: usize,
) -> Result<Vec<BaseField>, String> {
    let mut bytes = vec![0u8; count.checked_mul(4).ok_or("disk polynomial sidecar size")?];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| io_error("read disk polynomial sidecar coefficients", error))?;
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let value = u32::from_le_bytes(chunk.try_into().unwrap());
            if value as u64 >= M31 {
                Err("disk polynomial sidecar field element".into())
            } else {
                Ok(BaseField::from_u32_unchecked(value))
            }
        })
        .collect()
}

fn read_polynomial_sidecar(path: &Path) -> Result<DiskPolynomialSidecar, String> {
    let file = File::open(path).map_err(|error| io_error("open disk polynomial sidecar", error))?;
    let file_len = file
        .metadata()
        .map_err(|error| io_error("stat disk polynomial sidecar", error))?
        .len();
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 4];
    let mut version = [0u8; 1];
    let mut kind = [0u8; 1];
    let mut reserved = [0u8; 2];
    reader
        .read_exact(&mut magic)
        .and_then(|_| reader.read_exact(&mut version))
        .and_then(|_| reader.read_exact(&mut kind))
        .and_then(|_| reader.read_exact(&mut reserved))
        .map_err(|error| io_error("read disk polynomial sidecar header", error))?;
    if &magic != POLYNOMIAL_SIDECAR_MAGIC
        || version[0] != POLYNOMIAL_SIDECAR_VERSION
        || reserved != [0, 0]
    {
        return Err("disk polynomial sidecar codec".into());
    }
    let kind = match kind[0] {
        0 => DiskPolynomialSidecarKind::Exact,
        1 => DiskPolynomialSidecarKind::SealedRelation,
        _ => return Err("disk polynomial sidecar kind".into()),
    };
    let relation_log_size = read_u32_le(&mut reader, "read disk polynomial relation log")?;
    let polynomial_count =
        read_u32_le(&mut reader, "read disk polynomial coefficient count")? as usize;
    let reserved_count = read_u32_le(&mut reader, "read disk polynomial reserved count")?;
    let expected_log =
        relation_log_size + u32::from(kind == DiskPolynomialSidecarKind::SealedRelation);
    if polynomial_count == 0
        || !polynomial_count.is_power_of_two()
        || polynomial_count.ilog2() != expected_log
        || reserved_count != 0
        || file_len != 20 + 4 * polynomial_count as u64
    {
        return Err("disk polynomial sidecar geometry".into());
    }
    let polynomial =
        CpuCirclePoly::new(read_polynomial_coefficients(&mut reader, polynomial_count)?);
    Ok(DiskPolynomialSidecar {
        kind,
        relation_log_size,
        polynomial,
    })
}

fn build_leaf_layer(
    descriptor: &V17MerkleDescriptor,
    directory: &Path,
    column_count: usize,
) -> Result<(), String> {
    const ROW_CHUNK: usize = 1 << 14;
    let row_count = descriptor.row_count();
    if descriptor.row_width != column_count * 4 {
        return Err("disk oracle v17 leaf descriptor".into());
    }
    let tree_key = v17_merkle_tree_key(descriptor);
    let mut readers = (0..column_count)
        .map(|column| {
            File::open(column_path(directory, column))
                .map(BufReader::new)
                .map_err(|error| io_error("open disk oracle column", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_file = File::create(layer_path(directory, 0))
        .map_err(|error| io_error("create disk oracle leaf layer", error))?;
    let mut leaf_writer = BufWriter::new(leaf_file);
    for start in (0..row_count).step_by(ROW_CHUNK) {
        let rows = (row_count - start).min(ROW_CHUNK);
        let mut row_bytes = vec![0u8; rows * column_count * 4];
        let mut column_bytes = vec![0u8; rows * 4];
        for (column, reader) in readers.iter_mut().enumerate() {
            reader
                .read_exact(&mut column_bytes)
                .map_err(|error| io_error("read disk oracle column", error))?;
            for row in 0..rows {
                let source = row * 4;
                let target = (row * column_count + column) * 4;
                row_bytes[target..target + 4].copy_from_slice(&column_bytes[source..source + 4]);
            }
        }
        let hashes: Vec<[u8; 32]> = row_bytes
            .par_chunks_exact(column_count * 4)
            .enumerate()
            .map(|(offset, raw)| raw_leaf(&tree_key, start + offset, raw))
            .collect();
        for hash in hashes {
            leaf_writer
                .write_all(&hash)
                .map_err(|error| io_error("write disk oracle leaf", error))?;
        }
    }
    leaf_writer
        .flush()
        .map_err(|error| io_error("flush disk oracle leaf layer", error))
}

fn build_parent_layers(
    descriptor: &V17MerkleDescriptor,
    directory: &Path,
) -> Result<[u8; 32], String> {
    let row_count = descriptor.row_count();
    const NODE_CHUNK: usize = 1 << 16;
    let tree_key = v17_merkle_tree_key(descriptor);
    let mut nodes = row_count;
    let mut level = 0usize;
    for level_spec in descriptor.levels() {
        let source = File::open(layer_path(directory, level))
            .map_err(|error| io_error("open disk oracle layer", error))?;
        let mut reader = BufReader::new(source);
        let target = File::create(layer_path(directory, level + 1))
            .map_err(|error| io_error("create disk oracle parent layer", error))?;
        let mut writer = BufWriter::new(target);
        let parents = nodes / level_spec.arity;
        for start in (0..parents).step_by(NODE_CHUNK) {
            let count = (parents - start).min(NODE_CHUNK);
            let mut bytes = vec![0u8; count * level_spec.arity * 32];
            reader
                .read_exact(&mut bytes)
                .map_err(|error| io_error("read disk oracle layer", error))?;
            let hashes: Vec<[u8; 32]> = bytes
                .par_chunks_exact(level_spec.arity * 32)
                .map(|group| {
                    let children = (0..level_spec.arity)
                        .map(|child| group[child * 32..(child + 1) * 32].try_into().unwrap())
                        .collect::<Vec<[u8; 32]>>();
                    v17_merkle_parent(&tree_key, level_spec, &children).unwrap()
                })
                .collect();
            for hash in hashes {
                writer
                    .write_all(&hash)
                    .map_err(|error| io_error("write disk oracle parent", error))?;
            }
        }
        writer
            .flush()
            .map_err(|error| io_error("flush disk oracle parent layer", error))?;
        nodes = parents;
        level += 1;
    }
    if nodes != 1 {
        return Err("disk oracle v17 Merkle root".into());
    }
    let mut root = [0u8; 32];
    File::open(layer_path(directory, level))
        .and_then(|mut file| file.read_exact(&mut root))
        .map_err(|error| io_error("read disk oracle root", error))?;
    Ok(root)
}

/**
 * Extend each relation column separately, persist it, then build the canonical
 * row Merkle tree in bounded memory. `directory` must not already exist.
 */
pub fn build_disk_matrix_commitment(
    label: &str,
    relation_columns: &[Vec<u32>],
    extension: DiskColumnExtension,
    directory: &Path,
) -> Result<DiskMatrixCommitment, String> {
    if label.is_empty() || relation_columns.is_empty() {
        return Err("disk oracle shape".into());
    }
    let relation_rows = relation_columns[0].len();
    if relation_rows < 2
        || !relation_rows.is_power_of_two()
        || relation_columns
            .iter()
            .any(|column| column.len() != relation_rows)
        || relation_columns
            .iter()
            .flatten()
            .any(|value| *value as u64 >= M31)
    {
        return Err("disk oracle relation columns".into());
    }
    create_dir(directory).map_err(|error| io_error("create disk oracle directory", error))?;
    let mut row_count = None;
    for (column, values) in relation_columns.iter().enumerate() {
        let extended = extend_column(values, extension);
        if let Some(expected) = row_count {
            if extended.bit_reversed_lde.len() != expected {
                return Err("disk oracle LDE rows".into());
            }
        } else {
            row_count = Some(extended.bit_reversed_lde.len());
        }
        write_u32_column(&column_path(directory, column), &extended.bit_reversed_lde)?;
        write_polynomial_sidecar(
            &polynomial_sidecar_path(directory, column),
            &extended.sidecar,
        )?;
    }
    let row_count = row_count.unwrap();
    let descriptor = V17MerkleDescriptor::binary(label, row_count, relation_columns.len() * 4)?;
    build_leaf_layer(&descriptor, directory, relation_columns.len())?;
    let root = build_parent_layers(&descriptor, directory)?;
    Ok(DiskMatrixCommitment {
        label: label.to_string(),
        directory: directory.to_path_buf(),
        row_count,
        column_count: relation_columns.len(),
        root,
        layer_count: descriptor.levels().len() + 1,
    })
}

/**
 * Commit existing column oracles as one wider row matrix. Columns are linked,
 * not copied or re-extended; only the single canonical tree is new. Source
 * roots are prover-local artifacts and never enter the transcript.
 */
pub fn combine_disk_matrix_commitments(
    label: &str,
    sources: &[&DiskMatrixCommitment],
    directory: &Path,
) -> Result<DiskMatrixCommitment, String> {
    if label.is_empty() || sources.is_empty() || directory.exists() {
        return Err("combined disk oracle shape".into());
    }
    let row_count = sources[0].row_count;
    if row_count < 2
        || !row_count.is_power_of_two()
        || sources
            .iter()
            .any(|source| source.row_count != row_count || source.column_count == 0)
    {
        return Err("combined disk oracle geometry".into());
    }
    create_dir(directory).map_err(|error| io_error("create combined disk oracle", error))?;
    let mut target_column = 0usize;
    for source in sources {
        for source_column in 0..source.column_count {
            std::fs::hard_link(
                column_path(&source.directory, source_column),
                column_path(directory, target_column),
            )
            .map_err(|error| io_error("link combined disk oracle column", error))?;
            let source_sidecar = polynomial_sidecar_path(&source.directory, source_column);
            if source_sidecar.exists() {
                std::fs::hard_link(
                    source_sidecar,
                    polynomial_sidecar_path(directory, target_column),
                )
                .map_err(|error| io_error("link combined disk polynomial sidecar", error))?;
            }
            target_column += 1;
        }
    }
    let descriptor = V17MerkleDescriptor::binary(label, row_count, target_column * 4)?;
    build_leaf_layer(&descriptor, directory, target_column)?;
    let root = build_parent_layers(&descriptor, directory)?;
    Ok(DiskMatrixCommitment {
        label: label.to_string(),
        directory: directory.to_path_buf(),
        row_count,
        column_count: target_column,
        root,
        layer_count: descriptor.levels().len() + 1,
    })
}

/** Commit an existing QM31 evaluation without copying or re-extending it. */
pub fn commit_disk_qm31_evaluation(
    label: &str,
    evaluation: &DiskQm31Evaluation,
    directory: &Path,
) -> Result<DiskMatrixCommitment, String> {
    if label.is_empty()
        || directory.exists()
        || evaluation.row_count < 2
        || !evaluation.row_count.is_power_of_two()
    {
        return Err("disk QM31 commitment geometry".into());
    }
    create_dir(directory).map_err(|error| io_error("create disk QM31 commitment", error))?;
    for coordinate in 0..4 {
        std::fs::hard_link(
            column_path(&evaluation.directory, coordinate),
            column_path(directory, coordinate),
        )
        .map_err(|error| io_error("link disk QM31 commitment column", error))?;
    }
    let descriptor = V17MerkleDescriptor::binary(label, evaluation.row_count, 16)?;
    build_leaf_layer(&descriptor, directory, 4)?;
    let root = build_parent_layers(&descriptor, directory)?;
    Ok(DiskMatrixCommitment {
        label: label.to_string(),
        directory: directory.to_path_buf(),
        row_count: evaluation.row_count,
        column_count: 4,
        root,
        layer_count: descriptor.levels().len() + 1,
    })
}

fn read_at(path: &Path, offset: u64, bytes: &mut [u8], context: &str) -> Result<(), String> {
    let mut file = File::open(path).map_err(|error| io_error(context, error))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| io_error(context, error))?;
    file.read_exact(bytes)
        .map_err(|error| io_error(context, error))
}

fn secure_circle_point(point: V17Qm31CirclePoint) -> Result<CirclePoint<SecureField>, String> {
    let point = CirclePoint {
        x: qm31_to_secure(point.x),
        y: qm31_to_secure(point.y),
    };
    if point.x * point.x + point.y * point.y != SecureField::from(1u32) {
        return Err("disk polynomial evaluation point is not on the circle".into());
    }
    Ok(point)
}

fn evaluate_polynomial_sidecar_secure(
    path: &Path,
    point: CirclePoint<SecureField>,
) -> Result<SecureField, String> {
    let sidecar = read_polynomial_sidecar(path)?;
    Ok(sidecar.polynomial.eval_at_point(point))
}

impl DiskMatrixCommitment {
    pub fn polynomial_sidecar_info(
        &self,
        column: usize,
    ) -> Result<DiskPolynomialSidecarInfo, String> {
        if column >= self.column_count {
            return Err("disk polynomial sidecar column index".into());
        }
        let sidecar = read_polynomial_sidecar(&polynomial_sidecar_path(&self.directory, column))?;
        Ok(DiskPolynomialSidecarInfo {
            kind: sidecar.kind,
            polynomial_log_size: sidecar.polynomial.log_size(),
            sealed_relation_log_size: (sidecar.kind == DiskPolynomialSidecarKind::SealedRelation)
                .then_some(sidecar.relation_log_size),
        })
    }

    /** Evaluate one committed M31 column at an arbitrary QM31 Circle point. */
    pub fn evaluate_column_at_qm31(
        &self,
        column: usize,
        point: V17Qm31CirclePoint,
    ) -> Result<Qm31Value, String> {
        if column >= self.column_count {
            return Err("disk polynomial evaluation column index".into());
        }
        let point = secure_circle_point(point)?;
        Ok(secure_to_qm31(evaluate_polynomial_sidecar_secure(
            &polynomial_sidecar_path(&self.directory, column),
            point,
        )?))
    }

    /** Evaluate selected columns without materializing or interpolating their LDEs. */
    pub fn evaluate_columns_at_qm31(
        &self,
        columns: &[usize],
        point: V17Qm31CirclePoint,
    ) -> Result<Vec<Qm31Value>, String> {
        if columns.is_empty()
            || columns.iter().any(|column| *column >= self.column_count)
            || columns.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("disk polynomial evaluation column schedule".into());
        }
        let point = secure_circle_point(point)?;
        columns
            .iter()
            .map(|column| {
                evaluate_polynomial_sidecar_secure(
                    &polynomial_sidecar_path(&self.directory, *column),
                    point,
                )
                .map(secure_to_qm31)
            })
            .collect()
    }

    pub fn evaluate_all_columns_at_qm31(
        &self,
        point: V17Qm31CirclePoint,
    ) -> Result<Vec<Qm31Value>, String> {
        let point = secure_circle_point(point)?;
        (0..self.column_count)
            .into_par_iter()
            .map(|column| {
                evaluate_polynomial_sidecar_secure(
                    &polynomial_sidecar_path(&self.directory, column),
                    point,
                )
                .map(secure_to_qm31)
            })
            .collect()
    }

    pub fn column_reader(&self) -> Result<DiskMatrixColumnReader, String> {
        let readers = (0..self.column_count)
            .map(|column| {
                File::open(column_path(&self.directory, column))
                    .map(BufReader::new)
                    .map_err(|error| io_error("open disk oracle column reader", error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DiskMatrixColumnReader {
            readers,
            row_count: self.row_count,
            cursor: 0,
        })
    }

    pub fn row_values(&self, index: usize) -> Result<Vec<u32>, String> {
        if index >= self.row_count {
            return Err("disk oracle row index".into());
        }
        let mut row = Vec::with_capacity(self.column_count);
        for column in 0..self.column_count {
            let mut value = [0u8; 4];
            read_at(
                &column_path(&self.directory, column),
                (index as u64) * 4,
                &mut value,
                "read disk oracle row",
            )?;
            let value = u32::from_le_bytes(value);
            if value as u64 >= M31 {
                return Err("disk oracle row field element".into());
            }
            row.push(value);
        }
        Ok(row)
    }

    pub fn column_values(&self, column: usize) -> Result<Vec<u32>, String> {
        if column >= self.column_count {
            return Err("disk oracle column index".into());
        }
        let mut bytes = vec![0u8; self.row_count * 4];
        File::open(column_path(&self.directory, column))
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|error| io_error("read disk oracle column", error))?;
        let values = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        if values.iter().any(|value| *value as u64 >= M31) {
            return Err("disk oracle column field element".into());
        }
        Ok(values)
    }

    pub fn opening(&self, indices: &[usize]) -> Result<SuccessorMatrixOpening, String> {
        if indices.is_empty()
            || indices.iter().any(|index| *index >= self.row_count)
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("disk oracle opening indices".into());
        }
        let mut rows = Vec::with_capacity(indices.len());
        for index in indices {
            let row = self
                .row_values(*index)?
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            rows.push(row);
        }
        let descriptor =
            V17MerkleDescriptor::binary(&self.label, self.row_count, self.column_count * 4)?;
        let mut frontier = indices.to_vec();
        let mut siblings = Vec::new();
        for (level, level_spec) in descriptor.levels().into_iter().enumerate() {
            let mut parents = frontier
                .iter()
                .map(|index| index / level_spec.arity)
                .collect::<Vec<_>>();
            parents.dedup();
            for parent in &parents {
                for child in 0..level_spec.arity {
                    let sibling = parent * level_spec.arity + child;
                    if frontier.binary_search(&sibling).is_ok() {
                        continue;
                    }
                    let mut hash = [0u8; 32];
                    read_at(
                        &layer_path(&self.directory, level),
                        (sibling as u64) * 32,
                        &mut hash,
                        "read disk oracle sibling",
                    )?;
                    siblings.push(hash);
                }
            }
            frontier = parents;
        }
        if self.layer_count != descriptor.levels().len() + 1 || frontier != [0] {
            return Err("disk oracle v17 opening root schedule".into());
        }
        Ok(SuccessorMatrixOpening {
            root: self.root,
            row_width: self.column_count * 4,
            indices: indices.to_vec(),
            rows,
            siblings,
        })
    }
}

impl DiskMatrixColumnReader {
    /** Read the next rows from every column, preserving column-major shape. */
    pub fn read_next(&mut self, count: usize) -> Result<Vec<Vec<u32>>, String> {
        if count == 0
            || self
                .cursor
                .checked_add(count)
                .is_none_or(|end| end > self.row_count)
        {
            return Err("disk oracle column reader range".into());
        }
        let mut columns = Vec::with_capacity(self.readers.len());
        for reader in &mut self.readers {
            let mut bytes = vec![0u8; count * 4];
            reader
                .read_exact(&mut bytes)
                .map_err(|error| io_error("read disk oracle column chunk", error))?;
            let values = bytes
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>();
            if values.iter().any(|value| *value as u64 >= M31) {
                return Err("disk oracle column chunk field element".into());
            }
            columns.push(values);
        }
        self.cursor += count;
        Ok(columns)
    }

    pub fn remaining(&self) -> usize {
        self.row_count - self.cursor
    }
}

impl DiskQm31Writer {
    pub fn create(directory: &Path, row_count: usize) -> Result<Self, String> {
        if row_count < 2 || !row_count.is_power_of_two() || directory.exists() {
            return Err("disk QM31 writer geometry".into());
        }
        create_dir(directory).map_err(|error| io_error("create disk QM31 evaluation", error))?;
        let mut writer_values = Vec::with_capacity(4);
        for coordinate in 0..4 {
            writer_values.push(BufWriter::new(
                File::create(column_path(directory, coordinate))
                    .map_err(|error| io_error("create disk QM31 column", error))?,
            ));
        }
        let writers: [BufWriter<File>; 4] = writer_values.try_into().ok().unwrap();
        Ok(Self {
            directory: directory.to_path_buf(),
            row_count,
            written: 0,
            writers,
        })
    }

    pub fn write_chunk(&mut self, values: &[Qm31Value]) -> Result<(), String> {
        if values.is_empty()
            || self
                .written
                .checked_add(values.len())
                .is_none_or(|end| end > self.row_count)
            || values.iter().flatten().any(|value| *value as u64 >= M31)
        {
            return Err("disk QM31 writer chunk".into());
        }
        for coordinate in 0..4 {
            let mut bytes = Vec::with_capacity(values.len() * 4);
            for value in values {
                bytes.extend_from_slice(&value[coordinate].to_le_bytes());
            }
            self.writers[coordinate]
                .write_all(&bytes)
                .map_err(|error| io_error("write disk QM31 column", error))?;
        }
        self.written += values.len();
        Ok(())
    }

    pub fn finish(mut self) -> Result<DiskQm31Evaluation, String> {
        if self.written != self.row_count {
            return Err("disk QM31 writer incomplete".into());
        }
        for writer in &mut self.writers {
            writer
                .flush()
                .map_err(|error| io_error("flush disk QM31 column", error))?;
        }
        Ok(DiskQm31Evaluation {
            directory: self.directory,
            row_count: self.row_count,
        })
    }
}

impl DiskQm31Evaluation {
    pub fn values(&self) -> Result<Vec<Qm31Value>, String> {
        let mut columns = Vec::with_capacity(4);
        for coordinate in 0..4 {
            let mut bytes = vec![0u8; self.row_count * 4];
            File::open(column_path(&self.directory, coordinate))
                .and_then(|mut file| file.read_exact(&mut bytes))
                .map_err(|error| io_error("read disk QM31 evaluation", error))?;
            columns.push(
                bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                    .collect::<Vec<_>>(),
            );
        }
        if columns.iter().flatten().any(|value| *value as u64 >= M31) {
            return Err("disk QM31 evaluation field element".into());
        }
        Ok((0..self.row_count)
            .map(|row| std::array::from_fn(|coordinate| columns[coordinate][row]))
            .collect())
    }
}
