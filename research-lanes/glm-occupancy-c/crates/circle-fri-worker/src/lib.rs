//! Bench Circle FRI over M31. Matches the TypeScript plugin wire format.
//! sound: false (n=32, 8 queries). Hash-based = PQ family.

use sha2::{Digest, Sha256};

pub const M31: u64 = 2_147_483_647;
pub const FRI_LOG_N: usize = 5;
pub const FRI_N: usize = 32;
pub const FRI_QUERIES: usize = 8;
pub const FRI_VERSION: u8 = 1;
pub const CIRCLE_GEN: Point = Point {
    x: 2,
    y: 1_268_011_823,
};

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
}
