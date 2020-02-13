extern crate rand;
use serde::{Serialize,Deserialize};
use ring::digest;
use ring::signature::{self, Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use crate::crypto::hash::{H256, Hashable};

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
    pub previous_output: OutPoint,
    pub script_sig: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct OutPoint {
    pub txid: String,
    pub index: u8,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: String,
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
        const CHARSET: &[u8] = b"0123456789abcdef";
        const RIPEMD160_LEN: usize = 40;
        const SHA256_LEN: usize = 64;
        const SCRIPTSIG_LEN: usize = 144;
        let mut rng = rand::thread_rng();

        let txid: String = (0..SHA256_LEN)
            .map(|_| {
                let idx = rng.gen_range(0, CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        let index: u8 = rng.gen();
        let out_point = OutPoint { txid: txid, index: index };

        let pub_key: String = (0..RIPEMD160_LEN)
            .map(|_| {
                let idx = rng.gen_range(0, CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        let value: u64 = rng.gen();
        let tx_out = TxOut { value: value, script_pubkey: pub_key };

        let script_sig: String = (0..SCRIPTSIG_LEN)
            .map(|_| {
                let idx = rng.gen_range(0, CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        let tx_in = TxIn { previous_output: out_point, script_sig: script_sig };

        let inputs = vec![tx_in];
        let outputs = vec![tx_out];
        let tx = Transaction{ input: inputs, output: outputs };
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
