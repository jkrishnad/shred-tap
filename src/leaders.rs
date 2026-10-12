//! Who led each slot, and whether a shred really comes from that leader.
//!
//! The leader signs the Merkle root of every FEC set it makes, once, and every shred of
//! the set carries that signature in its first 64 bytes. Checking it against the slot
//! leader's public key proves the whole set came from the leader, as Agave's sigverify does.
//! The schedule is read from the text that solana leader-schedule prints,
//! one slot and one base58 public key per line. Any other line is skipped.

use std::collections::HashMap;
use std::io::BufRead;
use std::str::FromStr;

use solana_address::Address;
use solana_signature::Signature;

use crate::error::Result;
use crate::merkle::Hash;
use crate::shred::Shred;
use crate::wire;

/// An Ed25519 public key.
pub type Pubkey = [u8; 32];

/// The leader of every slot the schedule covers.
#[derive(Debug, Default, Clone)]
pub struct LeaderSchedule {
    leaders: HashMap<u64, Pubkey>,
}

impl LeaderSchedule {
    /// Reads a schedule, adding to the slots already known, so several epochs can be loaded.
    pub fn read(&mut self, reader: impl BufRead) -> Result<()> {
        for line in reader.lines() {
            let line = line?;
            let mut words = line.split_whitespace();
            let (Some(slot), Some(key), None) = (words.next(), words.next(), words.next()) else {
                continue;
            };
            let (Ok(slot), Ok(key)) = (slot.parse::<u64>(), Address::from_str(key)) else {
                continue;
            };
            self.leaders.insert(slot, key.to_bytes());
        }
        Ok(())
    }

    /// The leader of a slot, None if the schedule doesn't cover it.
    pub fn leader(&self, slot: u64) -> Option<&Pubkey> {
        self.leaders.get(&slot)
    }

    /// How many slots the schedule covers.
    pub fn len(&self) -> usize {
        self.leaders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaders.is_empty()
    }
}

/// True if the shred's signature is the leader's signature over this Merkle root.
pub fn signed_by(shred: &Shred, root: &Hash, leader: &Pubkey) -> bool {
    let Some(bytes) = shred.bytes.get(wire::SIGNATURE) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(bytes) else {
        return false;
    };
    signature.verify(leader, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::shred_root;

    // From solana leader-schedule for testnet epoch 1053, the slots around the 10 second capture.
    const LEADERS: &str = include_str!("../tests/fixtures/real-leaders.txt");
    // Every data shred of slot 449661788 in index order.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");

    fn schedule() -> LeaderSchedule {
        let mut schedule = LeaderSchedule::default();
        schedule.read(LEADERS.as_bytes()).unwrap();
        schedule
    }

    #[test]
    fn test_read_schedule() {
        let mut s = schedule();
        assert_eq!(s.len(), 57);
        let leader = Address::from_str("F1jcLYJ1s8k4oYVy51J2RvYGh4sB1kWsUB2NaDrg6ejL").unwrap();
        assert_eq!(s.leader(449_661_788), Some(&leader.to_bytes()));
        assert_eq!(s.leader(1), None);
        // headers, blank lines and junk are skipped, a second file adds to the first
        s.read(
            "Leader schedule\n\n  12  notakey\n  5  F1jcLYJ1s8k4oYVy51J2RvYGh4sB1kWsUB2NaDrg6ejL\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(s.len(), 58);
    }

    #[test]
    fn test_real_shred_signed_by_its_leader() {
        let shred = Shred::parse(&SLOT[..1203], 0).unwrap();
        let root = shred_root(&shred).unwrap();
        let s = schedule();
        assert!(signed_by(&shred, &root, s.leader(449_661_788).unwrap()));
        // not by the leader of the slot before, and not over another root
        assert!(!signed_by(&shred, &root, s.leader(449_661_784).unwrap()));
        assert!(!signed_by(
            &shred,
            &[0u8; 32],
            s.leader(449_661_788).unwrap()
        ));
    }
}
