extern crate rand;
use serde::{Serialize,Deserialize};
use ring::digest;
use ring::signature::{self, Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use crate::crypto::hash::{H160, H256, Hashable};
use std::convert::TryInto;
use std::collections::{HashSet, HashMap};

pub struct State {
    pub utxo: HashMap<(H256, u8), (u64, H160)>,
}

impl State {
    pub fn new() -> Self {
        use crate::crypto::key_pair;
        let mut utxo = HashMap::new();
        let bytes32 = [0u8; 32];
        let tx_hash: H256 = bytes32.into();
        let output_idx: u8 = 0;
        let value: u64 = 10000;
        let seed = [0u8; 32];
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let public_key = key.public_key();
        let pb_hash: H256 = digest::digest(&digest::SHA256, public_key.as_ref()).into();
        let recipient: H160 = pb_hash.to_addr().into();
        let init_key = (tx_hash, output_idx);
        let init_val = (value, recipient);
        utxo.insert(init_key, init_val);
        println!("ICO completed. {:?} coins are granted to {:?}", value, recipient);
        State { utxo: utxo }
    }

    pub fn update(&mut self, transaction: &SignedTransaction) {
        let tx = transaction.transaction.clone();
        let input = tx.input;
        let output = tx.output;
        for txin in input {
            let key = (txin.previous_output, txin.index);
            self.utxo.remove(&key);
        }
        let mut idx = 0;
        for txout in output {
            let tx_hash = transaction.hash();
            self.utxo.insert((tx_hash, idx), (txout.value, txout.recipient));
            idx += 1;
        }
    }
}

pub struct Mempool {
    pub txmap: HashMap<H256, SignedTransaction>,
}

impl Mempool {
    pub fn new() -> Self {
        let mut txmap = HashMap::new();
        Mempool { txmap: txmap }
    }

    pub fn insert(&mut self, transaction: &SignedTransaction) {
        let tx_hash: H256 = transaction.hash();
        self.txmap.insert(tx_hash, transaction.clone());
    }

    pub fn remove(&mut self, transaction: &SignedTransaction) {
        let tx_hash: H256 = transaction.hash();
        if self.txmap.contains_key(&tx_hash) {
            self.txmap.remove(&tx_hash);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Hashable for SignedTransaction {
    fn hash(&self) -> H256 {
        let m = bincode::serialize(&self).unwrap();
        digest::digest(&digest::SHA256, m.as_ref()).into()
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Hashable for Transaction {
    fn hash(&self) -> H256 {
        let m = bincode::serialize(&self).unwrap();
        digest::digest(&digest::SHA256, m.as_ref()).into()
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct TxIn {
    pub previous_output: H256,
    pub index: u8,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct TxOut {
    pub recipient: H160,
    pub value: u64,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let m = bincode::serialize(&t).unwrap();
    let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
    let sig = key.sign(txid.as_ref());
    return sig;
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let m = bincode::serialize(&t).unwrap();
    let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
    let public_key_ = signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref());
    let ret = public_key_.verify(txid.as_ref(), signature.as_ref()).is_ok();
    return ret;
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;

    pub fn generate_random_transaction() -> Transaction {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let key = key_pair::random();
        let public_key = key.public_key();
        let pb_hash: H256 = digest::digest(&digest::SHA256, public_key.as_ref()).into();
        let recipient: H160 = pb_hash.to_addr().into();
        let value: u64 = rng.gen();
        let tx_out = TxOut { recipient: recipient, value: value };

        let rand_num: u8 = rng.gen();
        let previous_output: H256 = [rand_num; 32].into();
        let index: u8 = rng.gen();
        let tx_in = TxIn { previous_output: previous_output, index: index };

        let inputs = vec![tx_in];
        let outputs = vec![tx_out];
        let tx = Transaction { input: inputs, output: outputs };
        return tx;
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}
