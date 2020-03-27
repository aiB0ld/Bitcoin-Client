use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn};
use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::crypto::hash::{H160, H256, Hashable};
use crate::transaction::{Transaction, SignedTransaction, Mempool, State};
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
    state: Arc<Mutex<State>>,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    chain: &Arc<Mutex<Blockchain>>,
    orphan_buffer: &Arc<Mutex<HashMap<H256, Block>>>,
    mempool: &Arc<Mutex<Mempool>>,
    state: &Arc<Mutex<State>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        chain: Arc::clone(chain),
        orphan_buffer: Arc::clone(orphan_buffer),
        mempool: Arc::clone(mempool),
        state: Arc::clone(state),
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
                                let mut state_un = self.state.lock().unwrap();
                                for transaction in &transactions {
                                    // Signature Check Step 1
                                    let tx = transaction.clone().transaction;
                                    let pk = transaction.clone().public_key;
                                    let sig = transaction.clone().signature;
                                    let m = bincode::serialize(&tx).unwrap();
                                    let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
                                    let public_key_ = signature::UnparsedPublicKey::new(&signature::ED25519, pk.clone());
                                    let mut verify_res = public_key_.verify(txid.as_ref(), &sig).is_ok();
                                    if verify_res {
                                        println!("pass signature check step 1");
                                    }
                                    else {
                                        println!("fail signature check step 1");
                                    }
                                    // Signature Check Step 2
                                    let input = tx.input;
                                    let mut input_amount = 0;
                                    for txin in input {
                                        let prev_out = txin.previous_output;
                                        let idx = txin.index;
                                        if state_un.utxo.contains_key(&(prev_out, idx)) {
                                            let val = state_un.utxo[&(prev_out, idx)];
                                            input_amount += val.0;
                                            let true_recipient = val.1;
                                            let pb_hash: H256 = digest::digest(&digest::SHA256, &pk).into();
                                            let recipient: H160 = pb_hash.to_addr().into();
                                            if recipient != true_recipient {
                                                println!("fail signature check step 2: inconsistent recipient");
                                                verify_res = false;
                                                break;
                                            }
                                        }
                                        else {
                                            println!("fail signature check step 2: not exist");
                                            verify_res = false;
                                            break;
                                        }
                                    }
                                    if verify_res {
                                        println!("pass signature check step 2");
                                    }
                                    // Spending Check
                                    let output = tx.output;
                                    let mut output_amount = 0;
                                    for txout in output {
                                        output_amount += txout.value;
                                    }
                                    if input_amount < output_amount {
                                        verify_res = false;
                                    }
                                    if verify_res {
                                        println!("pass spending check");
                                    }
                                    else {
                                        println!("fail spending check");
                                    }
                                    if !verify_res {
                                        valid = false;
                                        break;
                                    }
                                }
                                if !valid {
                                    println!("Invalid block received. Transaction is not signed properly!");
                                    continue
                                }
                                let mut mempool_un = self.mempool.lock().unwrap();
                                let mut state_un = self.state.lock().unwrap();
                                for transaction in transactions {
                                    mempool_un.remove(&transaction);
                                    state_un.update(&transaction);
                                    println!("{:?}", mempool_un.txmap.len());
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
                                            state_un.update(&transaction);
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
                    // println!("Received NewTransactionHashes");
                    let mut unknown = Vec::new();
                    let mut mempool_un = self.mempool.lock().unwrap();
                    for hash in txhashes.clone() {
                        if !mempool_un.txmap.contains_key(&hash) {
                            unknown.push(hash);
                        }
                    }
                    peer.write(Message::GetTransactions(unknown));
                }
                Message::GetTransactions(txhashes) => {
                    // println!("Received GetTransactions");
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
                    // println!("Received Transactions");
                    let mut mempool_un = self.mempool.lock().unwrap();
                    let mut state_un = self.state.lock().unwrap();
                    for transaction in transactions {
                        // Signature Check Step 1
                        let tx = transaction.clone().transaction;
                        let pk = transaction.clone().public_key;
                        let sig = transaction.clone().signature;
                        let m = bincode::serialize(&tx).unwrap();
                        let txid = digest::digest(&digest::SHA256, digest::digest(&digest::SHA256, m.as_ref()).as_ref());
                        let public_key_ = signature::UnparsedPublicKey::new(&signature::ED25519, pk.clone());
                        let mut verify_res = public_key_.verify(txid.as_ref(), &sig).is_ok();
                        if verify_res {
                            println!("pass signature check step 1");
                        }
                        else {
                            println!("fail signature check step 1");
                        }
                        // Signature Check Step 2
                        let input = tx.input;
                        let mut input_amount = 0;
                        for txin in input {
                            let prev_out = txin.previous_output;
                            let idx = txin.index;
                            if state_un.utxo.contains_key(&(prev_out, idx)) {
                                let val = state_un.utxo[&(prev_out, idx)];
                                input_amount += val.0;
                                let true_recipient = val.1;
                                let pb_hash: H256 = digest::digest(&digest::SHA256, &pk).into();
                                let recipient: H160 = pb_hash.to_addr().into();
                                if recipient != true_recipient {
                                    verify_res = false;
                                    println!("fail signature check step 2: inconsistent recipient");
                                    break;
                                }
                            }
                            else {
                                verify_res = false;
                                println!("fail signature check step 2: not exist");
                                break;
                            }
                        }
                        if verify_res {
                            println!("pass signature check step 2");
                        }
                        // Spending Check
                        let output = tx.output;
                        let mut output_amount = 0;
                        for txout in output {
                            output_amount += txout.value;
                        }
                        if input_amount < output_amount {
                            verify_res = false;
                        }
                        if verify_res {
                            println!("pass spending check");
                        }
                        else {
                            println!("fail spending check");
                        }

                        let mut hash: H256 = transaction.hash();
                        if verify_res {
                            self.server.broadcast(Message::NewTransactionHashes(vec![hash]));
                            mempool_un.insert(&transaction);
                            println!("{:?}", mempool_un.txmap.len());
                        }
                        else {
                            println!("Invalid transaction received! Not adding to the mempool.");
                        }
                    }
                }
            }
        }
    }
}
