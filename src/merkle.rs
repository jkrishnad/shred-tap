//! Climbs a shred's Merkle proof up to the root of its FEC set.
//!
//! The leader hashes every shred of a set into a leaf, joins the leaves in pairs level by level
//! until one hash is left, the root, and signs only that root.
//! Each shred carries its proof, the sibling hash at every level on the way up,
//! so one shred alone is enough to climb back to the root.
//!
//! The functions below run in this order.
//! 1. shred_root cuts a shred into the bytes it commits to and its proof.
//! 2. leaf hashes those bytes, from just after the signature to just before the proof.
//! 3. root_from_proof does the climb. The shard index says at each level whether the shred is
//!    the left child (even) or the right child (odd), then it is halved for the next level up.
//! 4. join hashes two children into their parent, entry and sha256 are its helpers.
//!
//! The prefixes and the 20 byte cut follow Agave merkle_tree.rs and merkle.rs.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::shred::{Shred, layout};
use crate::wire;

/// Leaves and parents hash with different prefixes, so a parent can never pass as a leaf.
const LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

/// Parents join only the first 20 bytes of each child, which is why proof entries are 20 bytes.
pub const PROOF_ENTRY_SIZE: usize = 20;

/// A SHA-256 hash, a leaf, a parent or a root.
pub type Hash = [u8; 32];

/// The root of the FEC set this shred claims to belong to, from the shred alone.
pub fn shred_root(shred: &Shred) -> Result<Hash> {
    let parts = layout(shred.variant)?;
    // the signature signs the root and the proof can't cover itself, so both are left out
    let covered = wire::SIGNATURE.end..parts.proof.start;
    let too_short = || Error::TooShort {
        expected: parts.proof.end,
        actual: shred.bytes.len(),
    };
    let covered = shred.bytes.get(covered).ok_or_else(too_short)?;
    let proof = shred.bytes.get(parts.proof.clone()).ok_or_else(too_short)?;
    root_from_proof(shred.shard_index, leaf(covered), proof)
}

/// The leaf of a shred from the bytes it commits to.
pub fn leaf(covered: &[u8]) -> Hash {
    sha256(&[LEAF_PREFIX, covered])
}

/// The root reached by climbing from a leaf at shard_index with its proof.
/// The proof must be whole 20 byte entries and exactly long enough to bring the index to 0.
pub fn root_from_proof(shard_index: usize, leaf: Hash, proof: &[u8]) -> Result<Hash> {
    let (entries, rest) = proof.as_chunks::<PROOF_ENTRY_SIZE>();
    if !rest.is_empty() {
        return Err(Error::InvalidMerkleProof { shard_index });
    }

    let mut node = leaf;
    let mut index = shard_index;
    for sibling in entries {
        let me = entry(&node);
        // even means we are the left child, odd the right one
        node = if index.is_multiple_of(2) {
            join(&me, sibling)
        } else {
            join(sibling, &me)
        };
        index >>= 1;
    }

    // a proof too short for the index never reaches the top
    if index != 0 {
        return Err(Error::InvalidMerkleProof { shard_index });
    }
    Ok(node)
}

/// The parent of two sibling nodes, left first.
pub fn join(left: &[u8; PROOF_ENTRY_SIZE], right: &[u8; PROOF_ENTRY_SIZE]) -> Hash {
    sha256(&[NODE_PREFIX, left, right])
}

/// The first 20 bytes of a node, the part a parent joins.
fn entry(node: &Hash) -> [u8; PROOF_ENTRY_SIZE] {
    let mut out = [0u8; PROOF_ENTRY_SIZE];
    out.copy_from_slice(&node[..PROOF_ENTRY_SIZE]);
    out
}

/// SHA-256 over several byte strings, as if they were one.
fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // One complete real FEC set, slot 449661784 set 96, 32 data then 32 coding shreds in shard order.
    const SET: &[u8] = include_bytes!("../tests/fixtures/real-fec-set.bin");
    // Every data shred of slot 449661788 in index order, 4 FEC sets, the last one resigned.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");

    fn set_shred(shard_index: usize) -> Shred {
        let bytes = if shard_index < 32 {
            &SET[shard_index * 1203..(shard_index + 1) * 1203]
        } else {
            let start = 32 * 1203 + (shard_index - 32) * 1228;
            &SET[start..start + 1228]
        };
        Shred::parse(bytes, 0).unwrap()
    }

    fn slot_shred(index: usize) -> Shred {
        Shred::parse(&SLOT[index * 1203..(index + 1) * 1203], 0).unwrap()
    }

    #[test]
    fn test_worked_example_four_leaves() {
        // the four shred tree from the explanation, the proof of shred 2 is [L3, P0]
        let l: Vec<Hash> = (0..4)
            .map(|i| leaf(format!("shred{i}").as_bytes()))
            .collect();
        let p0 = join(&entry(&l[0]), &entry(&l[1]));
        let p1 = join(&entry(&l[2]), &entry(&l[3]));
        let root = join(&entry(&p0), &entry(&p1));

        let proof = [entry(&l[3]), entry(&p0)].concat();
        assert_eq!(root_from_proof(2, l[2], &proof).unwrap(), root);
        // the same proof with the wrong index climbs to a different root
        assert_ne!(root_from_proof(3, l[2], &proof).unwrap(), root);
    }

    #[test]
    fn test_every_shred_of_a_set_climbs_to_one_root() {
        let root = shred_root(&set_shred(0)).unwrap();
        for i in 0..64 {
            assert_eq!(shred_root(&set_shred(i)).unwrap(), root, "shard {i}");
        }
    }

    #[test]
    fn test_root_matches_the_next_sets_chained_root() {
        // each set stores the root of the set before it, written by the leader
        for set in 0..3 {
            let root = shred_root(&slot_shred(set * 32)).unwrap();
            let next = slot_shred((set + 1) * 32);
            let chained = &next.bytes[layout(next.variant).unwrap().chained_merkle_root];
            assert_eq!(chained, root, "set {}", set * 32);
        }
    }

    #[test]
    fn test_resigned_shreds_climb_too() {
        // the retransmitter signature sits after the proof, outside what the leaf covers
        let first = slot_shred(96);
        assert!(first.variant.resigned);
        let root = shred_root(&first).unwrap();
        for i in 96..128 {
            assert_eq!(shred_root(&slot_shred(i)).unwrap(), root, "index {i}");
        }
    }

    #[test]
    fn test_changed_byte_breaks_the_climb() {
        let root = shred_root(&set_shred(5)).unwrap();
        let parts = layout(set_shred(5).variant).unwrap();
        // one byte in the shard, the chained root and the proof
        for at in [100, parts.chained_merkle_root.start, parts.proof.start + 3] {
            let mut shred = set_shred(5);
            shred.bytes[at] ^= 1;
            assert_ne!(shred_root(&shred).unwrap(), root, "byte {at}");
        }
    }

    #[test]
    fn test_signature_is_not_covered() {
        // the signature signs the root, so it can't be part of it
        let root = shred_root(&set_shred(5)).unwrap();
        let mut shred = set_shred(5);
        shred.bytes[0] ^= 1;
        assert_eq!(shred_root(&shred).unwrap(), root);
    }

    #[test]
    fn test_wrong_shard_index_breaks_the_climb() {
        let root = shred_root(&set_shred(5)).unwrap();
        let mut shred = set_shred(5);
        shred.shard_index = 4;
        assert_ne!(shred_root(&shred).unwrap(), root);
    }

    #[test]
    fn test_bad_proofs() {
        let l = leaf(b"x");
        // not whole entries
        assert!(matches!(
            root_from_proof(0, l, &[0u8; 30]),
            Err(Error::InvalidMerkleProof { shard_index: 0 })
        ));
        // 6 entries only reach the top from shard indexes below 64
        assert!(root_from_proof(63, l, &[0u8; 120]).is_ok());
        assert!(root_from_proof(64, l, &[0u8; 120]).is_err());
        // no proof means the leaf is the root, for index 0 only
        assert_eq!(root_from_proof(0, l, &[]).unwrap(), l);
        assert!(root_from_proof(1, l, &[]).is_err());
    }

    #[test]
    fn test_cut_shred() {
        let mut shred = set_shred(5);
        shred.bytes.truncate(1100);
        assert!(matches!(shred_root(&shred), Err(Error::TooShort { .. })));
    }
}
