// Helper to encode integers into Bitcoin's VarInt format
pub fn encode_varint(i: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    
    if i < 0xfd {
        // Single byte
        buffer.push(i as u8);
    } else if i <= 0xffff {
        // 0xfd followed by 2 bytes (u16)
        buffer.push(0xfd);
        buffer.extend_from_slice(&(i as u16).to_le_bytes());
    } else if i <= 0xffffffff {
        // 0xfe followed by 4 bytes (u32)
        buffer.push(0xfe);
        buffer.extend_from_slice(&(i as u32).to_le_bytes());
    } else {
        // 0xff followed by 8 bytes (u64)
        buffer.push(0xff);
        buffer.extend_from_slice(&i.to_le_bytes());
    }
    
    buffer
}