use std::fs::{File, metadata};
use std::io::Read;


pub enum ASN1Base {
    Sequence,
    Set
}

pub fn get_asn1_type(buf: &Vec<u8>) -> Result<ASN1Base, String> {
    match buf[0] {
        0x30 => return Ok(ASN1Base::Sequence),
        _ => return Err("Could not match to a known ASN type".to_string())
    }
}


pub fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

#[cfg(test)]
mod tests {
    use crate::{get_asn1_type, get_file_as_byte_vec};
    use std::matches;
    use crate::ASN1Base;
    #[test]
    fn read_file() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        assert_eq!(buf.len(), 1380);
    }
    #[test]
    fn file_is_asn1_sequence() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let asn1_type = get_asn1_type(buf).unwrap();
        assert!(matches!(asn1_type, ASN1Base::Sequence));
    }
}
