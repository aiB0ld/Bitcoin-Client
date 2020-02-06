use super::hash::{Hashable, H256};
use ring::digest;

/// A Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    tree: Vec<H256>,
    leaf_num: usize,
}

fn findHeight(in_size: usize) -> u32 {
    let mut height = 0;
    let mut cur = 1;
    while in_size > cur {
        height += 1;
        cur *= 2;
    }
    return height;
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self where T: Hashable, {
        let mut input_len = data.len();
        let mut tree = Vec::new();
        for i in 0..input_len {
            let hash = data[i].hash();
            tree.push(hash);
        }
        if input_len % 2 == 1 && input_len != 1 {
            tree.push(tree[tree.len()-1]);
            input_len += 1;
        }
        let mut start = 0;
        let mut cur_len = input_len;
        while cur_len > 1 {
            let half = cur_len/2;
            for i in 0..half {
                let mut ctx = digest::Context::new(&digest::SHA256);
                ctx.update(tree[start+2*i].as_ref());
                ctx.update(tree[start+2*i+1].as_ref());
                tree.push(ctx.finish().into());
            }
            if data.len() % 2 == 1 {
                tree.push(tree[tree.len()-1]);
            }
            start += cur_len;
            cur_len /= 2;
            if cur_len % 2 == 1 && cur_len != 1 {
                cur_len += 1;
            }
        }
        MerkleTree { tree: tree, leaf_num: input_len }
    }

    pub fn root(&self) -> H256 {
        return self.tree[self.tree.len()-1];
    }

    /// Returns the Merkle Proof of data at index i
    pub fn proof(&self, index: usize) -> Vec<H256> {
        let mut proof = Vec::new();
        if index >= self.leaf_num {
            return proof;
        }
        let height = findHeight(self.leaf_num);
        let mut cur_index = index;
        let mut sequence = 0;
        for i in 0..height {
            // println!("{:?}", cur_index);
            let group = (cur_index - sequence)/2;
            if cur_index % 2 == 1 {
                proof.push(self.tree[cur_index-1]);
            }
            else {
                proof.push(self.tree[cur_index+1]);
            }
            if i == 0 {
                sequence += self.leaf_num;
            }
            else {
                sequence += 2usize.pow(height - i);
            }
            cur_index = sequence + group;
        }
        return proof;
    }
}

/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, leaf_size: usize) -> bool {
    let height = proof.len();
    let leaf_num = 2usize.pow(height as u32) - (2usize.pow(height as u32+1) - 1 - leaf_size);
    let mut cur_index = index;
    let mut sequence = 0;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut trace = datum.clone();
    for i in 0..height {
        let group = (cur_index - sequence)/2;
        if cur_index % 2 == 1 {
            ctx.update(proof[i].as_ref());
            ctx.update(trace.as_ref());
        }
        else {
            ctx.update(trace.as_ref());
            ctx.update(proof[i].as_ref());
        }
        if i == 0 {
            sequence += leaf_num;
        }
        else {
            sequence += 2usize.pow(height as u32 - i as u32);
        }
        cur_index = sequence + group;
        trace = ctx.clone().finish().into();
    }
    return trace == *root;
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::H256;
    use super::*;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                   vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(&merkle_tree.root(), &input_data[0].hash(), &proof, 0, input_data.len()));
    }
}
