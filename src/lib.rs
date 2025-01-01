
use std::io::{Error as ioError, Read};
use std::error::Error;
use transaction::{Transaction, Input, Output, Amount, Txid};
mod transaction;
use sha2::{Sha256, Digest};

fn read_compact_size(transaction_bytes: &mut &[u8]) -> Result<u64, ioError> {
    let mut compact_size = [0; 1];
    transaction_bytes.read(&mut compact_size)?;

    match compact_size[0] {
        0..=252 => Ok(compact_size[0] as u64),
        253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read(&mut buffer)?;
            Ok(u16::from_le_bytes(buffer) as u64)
        },
        254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read(&mut buffer)?;
            Ok(u32::from_le_bytes(buffer) as u64)
        },
        255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read(&mut buffer)?;
            Ok(u64::from_le_bytes(buffer))
        }
    }
}

fn read_u32(bytes_slice: &mut &[u8]) -> Result<u32, ioError> {
    let mut buffer = [0; 4];
    bytes_slice.read(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

fn read_amount(bytes_slice: &mut &[u8]) -> Result<Amount, ioError> {
    let mut buffer = [0; 8];
    bytes_slice.read(&mut buffer)?;
    Ok(Amount::from_sat(u64::from_le_bytes(buffer)))
}

fn read_txid(bytes_slice: &mut &[u8]) -> Result<Txid, ioError> {
    let mut txid = [0; 32];
    bytes_slice.read(&mut txid)?;
    Ok(Txid::from_bytes(txid))
}

fn read_script(bytes_slice: &mut &[u8]) -> Result<String, ioError> {
    let script_size = read_compact_size(bytes_slice)? as usize;
    let mut script = vec![0_u8; script_size as usize];
    bytes_slice.read(&mut script)?;
    Ok(hex::encode(script))
}

fn hash_raw_transaction(raw_transaction: &[u8]) -> Txid {
    let mut hasher = Sha256::new();
    hasher.update(&raw_transaction);
    let hash1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&hash1);
    let hash2 = hasher.finalize();

    Txid::from_bytes(hash2.into())
}

pub fn decode(transaction_hex: String) -> Result<String, Box<dyn Error>> {
    let transaction_bytes = hex::decode(transaction_hex).map_err(|e| format!("Error decoding hex: {}", e))?;
    let mut bytes_slice = transaction_bytes.as_slice();
    let _version = read_u32(&mut bytes_slice)?;
    let input_count = read_compact_size(&mut bytes_slice)?;
    let mut inputs = vec![];
    for _ in 0..input_count {
        let txid = read_txid(&mut bytes_slice)?;
        let output_index = read_u32(&mut bytes_slice)?;
        let script_sig = read_script(&mut bytes_slice)?;
        let sequence = read_u32(&mut bytes_slice)?;

        inputs.push(Input {
            txid,
            output_index,
            script_sig,
            sequence
        });
    }

    let output_count = read_compact_size(&mut bytes_slice)?;
    let mut outputs = vec![];
    for _ in 0..output_count {
        let amount = read_amount(&mut bytes_slice)?;
        let script_pubkey = read_script(&mut bytes_slice)?;

        outputs.push(Output {
            amount,
            script_pubkey
        });
    }

    let lock_time = read_u32(&mut bytes_slice)?;
    let transaction_id = hash_raw_transaction(&transaction_bytes);

    let transaction = Transaction {
        transaction_id,
        version: _version,
        inputs,
        outputs,
        lock_time
    };
    Ok(serde_json::to_string_pretty(&transaction)?)
}



#[cfg(test)]

mod test {
    use super::read_compact_size;
    use super::Error;
    #[test]
    fn test_read_compact_size() -> Result<(), Box<dyn Error>> {
        let mut bytes_slice = [0x01].as_slice();
        assert_eq!(read_compact_size(&mut bytes_slice)?, 1);
        
        let mut bytes_slice = [0xfd, 0x02, 0x00].as_slice();
        assert_eq!(read_compact_size(&mut bytes_slice)?, 2);

        let mut bytes_slice = [0xfe, 0x03, 0x00, 0x00, 0x00].as_slice();
        assert_eq!(read_compact_size(&mut bytes_slice)?, 3);

        let mut bytes_slice = [0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice();
        assert_eq!(read_compact_size(&mut bytes_slice)?, 4);

        let hex = "fd204e";
        let decoded = hex::decode(hex)?;
        let mut bytes = decoded.as_slice();
        let count = read_compact_size(&mut bytes)?;
        let expected_count = 20_000_u64;
        assert_eq!(count, expected_count);

        Ok(())
    }
}