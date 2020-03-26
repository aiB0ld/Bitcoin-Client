use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
use crate::crypto::merkle::MerkleTree;
use super::transaction::{Transaction, SignedTransaction};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
	pub parent: H256,
	pub nonce: u32,
	pub difficulty: H256,
	pub timestamp: u128,
	pub merkle_root: H256,
}

impl Hashable for Header {
    fn hash(&self) -> H256 {
        let m = bincode::serialize(&self).unwrap();
        ring::digest::digest(&ring::digest::SHA256, m.as_ref()).into()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
	pub data: Vec<SignedTransaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
	pub header: Header,
	pub content: Content,
}

impl Hashable for Block {
    fn hash(&self) -> H256 {
        self.header.hash()
    }
}

#[cfg(any(test, test_utilities))]
pub mod test {
    use super::*;
    use crate::crypto::hash::H256;

    pub fn generate_random_block(parent: &H256) -> Block {
    	use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce: u32 = rng.gen();
        let transactions = Vec::new();
        let timestamp: u128 = rng.gen_range(1581553864000, 1582553864000);
        let mut bytes32 = [255u8; 32];
        bytes32[0] = 0;
        bytes32[1] = 0;
        let difficulty: H256 = bytes32.into();
        let empty_tree = MerkleTree::new(&transactions);
        let merkle_root = empty_tree.root();
        let header = Header{ parent: *parent, nonce: nonce, difficulty: difficulty, timestamp: timestamp, merkle_root: merkle_root };
        let content = Content{ data: transactions };
        Block{ header: header, content: content }
    }
}
