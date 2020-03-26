use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn};
use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::crypto::hash::{H256, Hashable};
use crate::transaction::{Transaction, SignedTransaction, Mempool};
use ring::digest;
use ring::signature::{self, Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};

use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    chain: Arc<Mutex<Blockchain>>,
    orphan_buffer: Arc<Mutex<HashMap<H256, Block>>>,
    mempool: Arc<Mutex<Mempool>>,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    chain: &Arc<Mutex<Blockchain>>,
    orphan_buffer: &Arc<Mutex<HashMap<H256, Block>>>,
    mempool: &Arc<Mutex<Mempool>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        chain: Arc::clone(chain),
        orphan_buffer: Arc::clone(orphan_buffer),
        mempool: Arc::clone(mempool),
    }
}

impl Context {
    pub fn start(self) {
        let num_worker = self.num_worker;
        for i in 0..num_worker {
            let mut cloned = self.clone();
            thread::spawn(move || {
                cloned.worker_loop();
                warn!("Worker thread {} exited", i);
            });
        }
    }

    fn worker_loop(&mut self) {
        let mut num_blocks = 0;
        let mut delay_sum = 0;
        loop {
            let msg = self.msg_chan.recv().unwrap();
            let (msg, peer) = msg;
            let msg: Message = bincode::deserialize(&msg).unwrap();
            match msg {
                Message::Ping(nonce) => {
                    debug!("Ping: {}", nonce);
                    peer.write(Message::Pong(nonce.to_string()));
                }
                Message::Pong(nonce) => {
                    debug!("Pong: {}", nonce);
                }
                Message::NewBlockHashes(blockhashes) => {
                    println!("Received NewBlockHashes");
                    let mut unknown = Vec::new();
                    let chain_un = self.chain.lock().unwrap();
                    for hash in blockhashes.clone() {
                        if !chain_un.blockmap.contains_key(&hash) {
                            unknown.push(hash);
                        }
                    }
                    peer.write(Message::GetBlocks(unknown));
                }
                Message::GetBlocks(blockhashes) => {
                    println!("Received GetBlocks");
                    let mut valid_blocks = Vec::new();
                    let chain_un = self.chain.lock().unwrap();
                    for hash in blockhashes {
                        if chain_un.blockmap.contains_key(&hash) {
                            let block = chain_un.blockmap[&hash].clone();
                            valid_blocks.push(block);
                        }
                    }
                    peer.write(Message::Blocks(valid_blocks));
                }
                Message::Blocks(blocks) => {
                    println!("Received Blocks");
                    let mut chain_un = self.chain.lock().unwrap();
                    let mut new_blocks = Vec::new();
                    for block in blocks {
                        num_blocks += 1;
                        delay_sum += SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() - block.header.timestamp;
                        println!("{:?} received by the worker. The sum of block delay is {:?} milliseconds.", num_blocks, delay_sum);
                        let mut hash: H256 = block.hash();
                        if !chain_un.blockmap.contains_key(&hash) {
                            let mut buffer = self.orphan_buffer.lock().unwrap();
                            if !chain_un.blockmap.contains_key(&block.header.parent) {
                                buffer.insert(block.header.parent, block);
                            } 
                            else if hash <= block.header.difficulty && block.header.difficulty == chain_un.blockmap[&block.header.parent].header.difficulty {
                                let transactions = block.clone().content.data;
                                let mut valid = true;
                                for transaction in &transactions {
                                    let tx = transaction.clone().transaction;
                                    let pk = transaction.clone().public_key;
                                    let sig = transaction.clone().signature;
                                    let m = bincode::serialize(&tx).unwrap();
                                    let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
                                    let public_key_ = signature::UnparsedPublicKey::new(&signature::ED25519, pk);
                                    let verify_res = public_key_.verify(txid.as_ref(), &sig).is_ok();
                                    if !verify_res {
                                        valid = false;
                                        break;
                                    }
                                }
                                if !valid {
                                    continue
                                }
                                let mut mempool_un = self.mempool.lock().unwrap();
                                for transaction in transactions {
                                    mempool_un.remove(&transaction);
                                }
                                chain_un.insert(&block);
                                new_blocks.push(hash);
                                self.server.broadcast(Message::NewBlockHashes(vec![hash]));
                                loop {
                                    if buffer.contains_key(&hash) {
                                        let orphan_block = buffer.remove(&hash).unwrap();
                                        let transactions = orphan_block.clone().content.data;
                                        for transaction in transactions {
                                            mempool_un.remove(&transaction);
                                        }
                                        chain_un.insert(&orphan_block);
                                        new_blocks.push(orphan_block.hash());
                                        self.server.broadcast(Message::NewBlockHashes(vec![orphan_block.hash()]));
                                        hash = orphan_block.hash();
                                    }
                                    else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Message::NewTransactionHashes(txhashes) => {
                    println!("Received NewTransactionHashes");
                    let mut unknown = Vec::new();
                    let mut mempool_un = self.mempool.lock().unwrap();
                    for hash in txhashes.clone() {
                        if !mempool_un.txset.contains(&hash) {
                            unknown.push(hash);
                        }
                    }
                    peer.write(Message::GetTransactions(unknown));
                }
                Message::GetTransactions(txhashes) => {
                    println!("Received GetTransactions");
                    let mut valid_txs = Vec::new();
                    let mut mempool_un = self.mempool.lock().unwrap();
                    for hash in txhashes {
                        if mempool_un.txmap.contains_key(&hash) {
                            let tx = mempool_un.txmap[&hash].clone();
                            valid_txs.push(tx);
                        }
                    }
                    peer.write(Message::Transactions(valid_txs));
                }
                Message::Transactions(transactions) => {
                    println!("Received Transactions");
                    let mut mempool_un = self.mempool.lock().unwrap();
                    for transaction in transactions {
                        let tx = transaction.clone().transaction;
                        let pk = transaction.clone().public_key;
                        let sig = transaction.clone().signature;
                        let m = bincode::serialize(&tx).unwrap();
                        let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
                        let public_key_ = signature::UnparsedPublicKey::new(&signature::ED25519, pk);
                        let verify_res = public_key_.verify(txid.as_ref(), &sig).is_ok();
                        let mut hash: H256 = transaction.hash();
                        if verify_res {
                            self.server.broadcast(Message::NewTransactionHashes(vec![hash]));
                            mempool_un.insert(&transaction);
                        }
                    }
                }
            }
        }
    }
}
