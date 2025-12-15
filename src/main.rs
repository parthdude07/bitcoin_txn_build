use sha2::{Sha256, Digest};
use secp256k1::{Message, Secp256k1};
mod varint; // Import the varint module we made above
mod varint;
mod keys;

use keys::{KeyPair, p2pkh_script};
#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: [u8; 32],      // The previous Transaction ID (hash)
    pub prev_index: u32,        // Which output of that Tx are we spending?
    pub script_sig: Vec<u8>,    // The unlocking script (Signature + Public Key)
    pub sequence: u32,          // Usually 0xffffffff
}

impl TxIn {
    pub fn new(prev_tx: [u8; 32], prev_index: u32, script_sig: Option<Vec<u8>>) -> Self {
        TxIn {
            prev_tx,
            prev_index,
            script_sig: script_sig.unwrap_or_default(),
            sequence: 0xffffffff,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // 1. Previous Tx ID (Must be Little-Endian)
        // Important: Block explorers show TxIDs reversed. 
        // We assume input `prev_tx` is already raw bytes (Internal Byte Order).
        buffer.extend_from_slice(&self.prev_tx); 
        
        // 2. Output Index (4 bytes, Little-Endian)
        buffer.extend_from_slice(&self.prev_index.to_le_bytes());
        
        // 3. Script Sig Length (VarInt)
        buffer.extend_from_slice(&varint::encode_varint(self.script_sig.len() as u64));
        
        // 4. Script Sig
        buffer.extend_from_slice(&self.script_sig);
        
        // 5. Sequence (4 bytes, Little-Endian)
        buffer.extend_from_slice(&self.sequence.to_le_bytes());
        
        buffer
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,            // Amount in Satoshis
    pub script_pubkey: Vec<u8>, // The locking script
}

impl TxOut {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // 1. Amount (8 bytes, Little-Endian)
        buffer.extend_from_slice(&self.amount.to_le_bytes());
        
        // 2. Script PubKey Length (VarInt)
        buffer.extend_from_slice(&varint::encode_varint(self.script_pubkey.len() as u64));
        
        // 3. Script PubKey
        buffer.extend_from_slice(&self.script_pubkey);
        
        buffer
    }
}

#[derive(Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // 1. Version (4 bytes, Little-Endian)
        buffer.extend_from_slice(&self.version.to_le_bytes());
        
        // 2. Input Count (VarInt)
        buffer.extend_from_slice(&varint::encode_varint(self.inputs.len() as u64));
        
        // 3. Serialize all Inputs
        for tx_in in &self.inputs {
            buffer.extend(tx_in.serialize());
        }
        
        // 4. Output Count (VarInt)
        buffer.extend_from_slice(&varint::encode_varint(self.outputs.len() as u64));
        
        // 5. Serialize all Outputs
        for tx_out in &self.outputs {
            buffer.extend(tx_out.serialize());
        }
        
        // 6. Locktime (4 bytes, Little-Endian)
        buffer.extend_from_slice(&self.locktime.to_le_bytes());
        
        buffer
    }
    
    // Hash256: Double SHA-256
    pub fn hash(&self) -> Vec<u8> {
        let serialized = self.serialize();
        let hash1 = Sha256::digest(&serialized);
        let hash2 = Sha256::digest(&hash1);
        hash2.to_vec()
    }


    ///////
    pub fn get_sig_hash(&self, input_index: usize, prev_script_pubkey: &[u8]) -> Vec<u8> {
        // Create a clone to modify safely
        let mut tx_clone = self.clone();

        // Rule: Clear all input scripts
        for tx_in in &mut tx_clone.inputs {
            tx_in.script_sig = vec![];
        }

        // Rule: Replace the script of the input we are signing with the PREVIOUS script_pubkey
        tx_clone.inputs[input_index].script_sig = prev_script_pubkey.to_vec();

        // Serialize the modified transaction
        let mut serialized = tx_clone.serialize();

        // Rule: Append SIGHASH_ALL (0x01) as 4 bytes Little-Endian
        let sighash_type = 1u32;
        serialized.extend_from_slice(&sighash_type.to_le_bytes());

        // Double SHA256 gives us the 32-byte hash to sign
        let hash1 = Sha256::digest(&serialized);
        let hash2 = Sha256::digest(&hash1);
        hash2.to_vec()
    }

    // 2. Sign a specific input
    pub fn sign_input(&mut self, input_index: usize, key_pair: &keys::KeyPair, prev_tx_out: &TxOut) {
        // Get the hash we need to sign (Pre-Image)
        let sig_hash = self.get_sig_hash(input_index, &prev_tx_out.script_pubkey);
        
        // Prepare the ECDSA signer
        let secp = Secp256k1::new();
        let message = Message::from_slice(&sig_hash).expect("32 bytes");
        
        // Sign the hash
        let signature = secp.sign_ecdsa(&message, &key_pair.secret);
        
        // Serialize signature to DER format
        let mut der_signature = signature.serialize_der().to_vec();
        
        // Rule: Append the SIGHASH_ALL byte (0x01) to the DER signature
        der_signature.push(0x01); 

        // Generate the ScriptSig: <Signature> <PublicKey>
        // In Bitcoin Script assembly: PUSH(Sig) PUSH(PubKey)
        let mut script_sig = Vec::new();
        
        // Push Signature
        script_sig.push(der_signature.len() as u8); // Length
        script_sig.extend(der_signature);
        
        // Push Public Key
        let pub_key_bytes = key_pair.public.serialize(); // Compressed 33 bytes
        script_sig.push(pub_key_bytes.len() as u8); // Length
        script_sig.extend_from_slice(&pub_key_bytes);

        // Place the completed script into the transaction
        self.inputs[input_index].script_sig = script_sig;
    }
    
    // Helper to print hex for broadcasting
    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }
}



fn main() {
    // 1. Your Identity (Testnet WIF)
    // REPLACE THIS with a real Testnet WIF you generated (e.g., from an Electrum testnet wallet)
    // If you don't have one, the code will fail at `from_wif`
    let wif = "cMcrSu7X5gfr75s2y51Z7_REPLACE_WITH_REAL_WIF_FOR_TESTING"; 
    
    let key_pair = match keys::KeyPair::from_wif(wif) {
        Ok(k) => k,
        Err(e) => {
            println!("Error parsing WIF: {}. Using dummy data for compilation check.", e);
            return;
        }
    };

    println!("Key loaded successfully!");

    // 2. The UTXO we are spending (The Input)
    // We need the ScriptPubKey of the money we own so we can sign against it.
    // Since we own it, the script is just P2PKH of OUR public key.
    let prev_script = keys::p2pkh_script(&key_pair.public);
    
    let input_txid_hex = "0000000000000000000000000000000000000000000000000000000000000000"; // Dummy
    let input_txid_bytes = hex::decode(input_txid_hex).unwrap();
    let mut input_txid_arr = [0u8; 32];
    input_txid_arr.copy_from_slice(&input_txid_bytes);

    // Create the Input Object
    let tx_in = TxIn::new(input_txid_arr, 0, None);

    // Create a mock of the Previous Output (needed for signing logic)
    let prev_tx_out = TxOut {
        amount: 100000, // 0.001 BTC
        script_pubkey: prev_script,
    };

    // 3. The Destination (The Output)
    // Let's send money back to ourselves for simplicity, or generate a random destination
    let destination_script = keys::p2pkh_script(&key_pair.public); 
    
    let tx_out = TxOut {
        amount: 90000, // Spending 90k, leaving 10k as fee
        script_pubkey: destination_script,
    };

    // 4. Build Transaction
    let mut tx = Transaction {
        version: 1,
        inputs: vec![tx_in],
        outputs: vec![tx_out],
        locktime: 0,
    };

    // 5. Sign!
    // We sign Input 0, using our KeyPair and the details of the UTXO
    tx.sign_input(0, &key_pair, &prev_tx_out);

    // 6. Print the Result
    println!("\n=== RAW SIGNED TRANSACTION ===");
    println!("{}", tx.to_hex());
    println!("==============================\n");
    println!("Broadcast this hex at: https://blockstream.info/testnet/tx/push");
}