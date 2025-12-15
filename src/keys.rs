use bs58;
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use ripemd::{Ripemd160};

// Helper: Double SHA256 (Hash256)
fn hash256(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    hash2.to_vec()
}

// Helper: Hash160 (RIPEMD160(SHA256(data))) - Used for Addresses
pub fn hash160(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Ripemd160::digest(&hash1);
    hash2.to_vec()
}

pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    // Decode WIF string to raw Private/Public key pair
    pub fn from_wif(wif: &str) -> Result<Self, String> {
        // 1. Decode Base58
        let decoded = bs58::decode(wif).into_vec().map_err(|e| e.to_string())?;
        
        // 2. Validate Checksum
        // The last 4 bytes are the checksum
        let (main_data, checksum) = decoded.split_at(decoded.len() - 4);
        let calculated_checksum = &hash256(main_data)[0..4];
        
        if checksum != calculated_checksum {
            return Err("Invalid WIF checksum".to_string());
        }

        // 3. Extract Key
        // First byte is version (0x80 mainnet, 0xef testnet)
        // If the byte after the key is 0x01, it is a "Compressed" key.
        let is_compressed = main_data.len() == 34 && main_data[33] == 0x01;
        
        let private_bytes = if is_compressed {
            &main_data[1..33] // Skip version byte, take 32 bytes
        } else {
            &main_data[1..33] // Uncompressed keys are simpler but rarer now
        };

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(private_bytes).map_err(|_| "Invalid Key")?;
        let public = PublicKey::from_secret_key(&secp, &secret);

        Ok(KeyPair { secret, public })
    }
    // Generate the P2PKH ScriptPubKey for a given Public Key
pub fn p2pkh_script(public_key: &PublicKey) -> Vec<u8> {
    let serialized_pubkey = public_key.serialize(); // Serializes to 33 bytes (compressed)
    let pubkey_hash = hash160(&serialized_pubkey); // 20 bytes
    
    let mut script = Vec::new();
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes (The length of the hash)
    script.extend(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    
    script
}
}