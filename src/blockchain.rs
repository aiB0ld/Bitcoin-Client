use crate::block::{Block, Header, Content};
use crate::crypto::hash::{H256, Hashable};
use std::collections::HashMap;
use crate::crypto::merkle::MerkleTree;

pub struct Blockchain {
    pub blockmap: HashMap<H256, Block>,
    pub lengthmap: HashMap<H256, usize>,
    tip: H256,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let parent: H256 = [0u8; 32].into();
        let nonce = 0u32;
        let mut bytes32 = [0u8; 32];
        bytes32[2] = 1;
        bytes32[3] = 1;
        bytes32[4] = 1;
        let difficulty: H256 = bytes32.into();
        let timestamp = 0u128;
        let transactions = Vec::new();
        let empty_tree = MerkleTree::new(&transactions);
        let merkle_root = empty_tree.root();
        let header = Header{ parent: parent, nonce: nonce, difficulty: difficulty, timestamp: timestamp, merkle_root: merkle_root };
        let content = Content{ data: transactions };
        let genesis = Block{ header: header, content: content };
        let mut blockmap = HashMap::new();
        let mut lengthmap = HashMap::new();
        let genesis_hash: H256 = genesis.hash();
        blockmap.insert(genesis_hash, genesis);
        lengthmap.insert(genesis_hash, 0);
        let tip = genesis_hash;
        Blockchain { blockmap: blockmap, lengthmap: lengthmap, tip: tip }
    }

    /// Insert a block into blockchain
    pub fn insert(&mut self, block: &Block) {
        let prev = block.header.parent;
        let block_hash: H256 = block.hash();
        self.blockmap.insert(block_hash, block.clone());
        self.lengthmap.insert(block_hash, self.lengthmap[&prev] + 1);
        if self.lengthmap[&self.tip] < self.lengthmap[&block_hash] {
            self.tip = block_hash;
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        return self.tip;
    }

    /// Get the last block's hash of the longest chain
    // #[cfg(any(test, test_utilities))]
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        let mut trav = self.tip;
        let mut longest_chain = Vec::new();
        let target = [0u8; 32].into();
        while trav != target {
            longest_chain.push(trav);
            let cur_b = &self.blockmap[&trav];
            trav = cur_b.header.parent;
        }
        return longest_chain;
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::block::test::generate_random_block;
    use crate::crypto::hash::Hashable;

    #[test]
    fn insert_one() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());
    }
}
