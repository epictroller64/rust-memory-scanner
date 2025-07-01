use std::num::ParseIntError;

pub fn pattern_to_bytes(pattern: &str) -> Result<Vec<u8>, ParseIntError> {
    let mut bytes = Vec::new();
    let mut chars = pattern.chars().collect::<Vec<_>>();
    // Handle odd length by prefixing with 0
    if chars.len() % 2 != 0 {
        chars.insert(0, '0');
    }
    for chunk in chars.chunks(2) {
        let byte_str: String = chunk.iter().collect();
        let byte = u8::from_str_radix(&byte_str, 16)?;
        bytes.push(byte);
    }
    Ok(bytes)
}
