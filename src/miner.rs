use crate::network::server::Handle as ServerHandle;
use crate::blockchain::Blockchain;
use crate::crypto::merkle::MerkleTree;
use crate::block::{Block, Header, Content};
use crate::transaction::{Transaction, SignedTransaction, Mempool};

use log::{info, debug};

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;

use std::thread;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::hash::{H256, Hashable};
use crate::network::message::Message;

enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
}

enum OperatingState {
    Paused,
    Run(u64),
    ShutDown,
}

pub struct Context {
    /// Channel for receiving control signal
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    chain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<Mempool>>,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle, blockchain: &Arc<Mutex<Blockchain>>, mempool: &Arc<Mutex<Mempool>>,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        chain: Arc::clone(blockchain),
        mempool: Arc::clone(mempool),
    };

    let handle = Handle {
        control_chan: signal_chan_sender,
    };

    (ctx, handle)
}

impl Handle {
    pub fn exit(&self) {
        self.control_chan.send(ControlSignal::Exit).unwrap();
    }

    pub fn start(&self, lambda: u64) {
        self.control_chan
            .send(ControlSignal::Start(lambda))
            .unwrap();
    }

}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("miner".to_string())
            .spawn(move || {
                self.miner_loop();
            })
            .unwrap();
        info!("Miner initialized into paused mode");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Exit => {
                info!("Miner shutting down");
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Start(i) => {
                info!("Miner starting in continuous mode with lambda {}", i);
                self.operating_state = OperatingState::Run(i);
            }
        }
    }

    fn miner_loop(&mut self) {
        // main mining loop
        let mut num_blocks = 0;
        let mut cnt = 0;
        let mut total_size = 0;
        let start_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
        let block_limit = 2048;
        loop {
            // check and react to control signals
            match self.operating_state {
                OperatingState::Paused => {
                    let signal = self.control_chan.recv().unwrap();
                    self.handle_control_signal(signal);
                    continue;
                }
                OperatingState::ShutDown => {
                    return;
                }
                _ => match self.control_chan.try_recv() {
                    Ok(signal) => {
                        self.handle_control_signal(signal);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => panic!("Miner control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }

            // TODO: actual mining
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut chain_un = self.chain.lock().unwrap();
            let parent = chain_un.tip();
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
            let difficulty = chain_un.blockmap[&parent].header.difficulty;
            let mut transactions = Vec::new();
            let mut mempool_un = self.mempool.lock().unwrap();
            let mut block_size = 0;
            for key in mempool_un.txmap.keys() {
                let val = mempool_un.txmap[&key].clone();
                let m = bincode::serialize(&val).unwrap();
                if block_size + m.len() > block_limit {
                    break;
                }
                transactions.push(val);
                block_size += m.len();
            }
            let empty_tree = MerkleTree::new(&transactions);
            let merkle_root = empty_tree.root();
            let nonce = rng.gen();
            let header = Header{ parent: parent, nonce: nonce, difficulty: difficulty, timestamp: timestamp, merkle_root: merkle_root };
            let content = Content{ data: transactions };
            let cur_block = Block{ header: header, content: content };
            cnt += 1;
            if cnt % 100000 == 0 {
                println!("time: {:?}, tip: {:?}, blocksnum: {:?}", timestamp, chain_un.tip(), chain_un.blockmap.len());
            }

            if cur_block.hash() <= difficulty {
                for transaction in cur_block.clone().content.data {
                    mempool_un.remove(&transaction);
                }
                chain_un.insert(&cur_block);
                num_blocks += 1;
                total_size += bincode::serialize(&cur_block).unwrap().len();
                info!("{:?} blocks mined", num_blocks);
                let mut blockhashes = Vec::new();
                blockhashes.push(cur_block.hash());
                self.server.broadcast(Message::NewBlockHashes(blockhashes));
            }

            let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
            if cur_time - start_time > 300 {
                info!("{:?} blocks mined in {:?} seconds. The longest chain has {:?} blocks. The size of all blocks is {:?}.", num_blocks, 300, chain_un.all_blocks_in_longest_chain().len(), total_size);
                break;
            }

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let interval = time::Duration::from_micros(i as u64);
                    thread::sleep(interval);
                }
            }
        }
    }
}
