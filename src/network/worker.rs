use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn};
use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::crypto::hash::{H256, Hashable};

use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// pub struct OrphanBuffer {
//     parent_map: HashMap<H256, Block>,
// }

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    chain: Arc<Mutex<Blockchain>>,
    orphan_buffer: Arc<Mutex<HashMap<H256, Block>>>,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    chain: &Arc<Mutex<Blockchain>>,
    orphan_buffer: &Arc<Mutex<HashMap<H256, Block>>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        chain: Arc::clone(chain),
        orphan_buffer: Arc::clone(orphan_buffer),
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
                            // self.server.broadcast(Message::NewBlockHashes(vec![hash]));
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
                        println!("{:?} received by the worker. The average block delay is {:?} milliseconds.", num_blocks, delay_sum/num_blocks);
                        let mut hash: H256 = block.hash();
                        if !chain_un.blockmap.contains_key(&hash) {
                            let mut buffer = self.orphan_buffer.lock().unwrap();
                            if !chain_un.blockmap.contains_key(&block.header.parent) {
                                buffer.insert(block.header.parent, block);
                            } 
                            else if hash <= block.header.difficulty && block.header.difficulty == chain_un.blockmap[&block.header.parent].header.difficulty {
                                chain_un.insert(&block);
                                new_blocks.push(hash);
                                self.server.broadcast(Message::NewBlockHashes(vec![hash]));
                                while true {
                                    if buffer.contains_key(&hash) {
                                        let orphan_block = buffer.remove(&hash).unwrap();
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
            }
        }
    }
}
