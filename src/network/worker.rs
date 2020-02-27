use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn};
use crate::blockchain::Blockchain;
use crate::crypto::hash::{H256, Hashable};

use std::thread;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    chain: Arc<Mutex<Blockchain>>,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    chain: &Arc<Mutex<Blockchain>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        chain: Arc::clone(chain),
    }
}

impl Context {
    pub fn start(self) {
        let num_worker = self.num_worker;
        for i in 0..num_worker {
            let cloned = self.clone();
            thread::spawn(move || {
                cloned.worker_loop();
                warn!("Worker thread {} exited", i);
            });
        }
    }

    fn worker_loop(&self) {
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
                    let mut chain_un = self.chain.lock().unwrap();
                    for hash in blockhashes.clone() {
                        if !chain_un.blockmap.contains_key(&hash) {
                            unknown.push(hash);
                            self.server.broadcast(Message::NewBlockHashes(vec![hash]));
                        }
                    }
                    peer.write(Message::GetBlocks(unknown));
                }
                Message::GetBlocks(blockhashes) => {
                    println!("Received GetBlocks");
                    let mut valid_blocks = Vec::new();
                    let mut chain_un = self.chain.lock().unwrap();
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
                    for block in blocks {
                        let hash: H256 = block.hash();
                        if !chain_un.blockmap.contains_key(&hash) {
                            chain_un.insert(&block);
                        }
                    }
                }
            }
        }
    }
}
