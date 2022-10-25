use std::fs::{File, metadata};
use std::io::Read;

pub struct ASN1FieldDescriptor {
    start_offset: usize,
    header_length: usize,
    payload_length: usize
}

pub enum ASN1Base {
    Sequence,
    Set
}

pub fn get_asn1_type(buf: &Vec<u8>) -> Result<ASN1Base, String> {
    match buf[0] {
        0x30 => return Ok(ASN1Base::Sequence),
        _ => return Err("Could not match to a known ASN1 type".to_string())
    }
}

pub fn get_field(buf: &Vec<u8>, start_offset: usize) -> Result<ASN1FieldDescriptor, String> {
    let lenbytes: usize;
    let len: usize = match buf[start_offset + 1] {
        0 ..=128 => {
            // println!("Short!");
            lenbytes = 1;
            buf[start_offset + 1] as usize
        },
        _ => {
            // println!("Long: {:?}", buf[offset + 1]);
            lenbytes = (buf[start_offset + 1] - 128) as usize;
            let mut len: usize = 0;
            for byte in 0..lenbytes {
                // println!("Byte: {:?}", buf[offset + byte + 2]);
                len += (buf[start_offset + byte + 2]) as usize;
                if byte < (lenbytes - 1) {
                    len = len << 8;
                }
            }
            len
        }
    };
    let header_length = lenbytes + 2;
    println!("Field Length: {:?}", buf.len());
    println!("Field Header Length: {:?}", header_length);
    if (len + header_length) > buf.len() {
        return Err("Length of field exceeded input buffer".to_string());
    }
    let payload = &buf[(header_length)..(len + header_length)].to_vec();
    println!("Field Payload Length: {:?}", payload.len());
    Ok(ASN1FieldDescriptor {
        start_offset: start_offset,
        header_length: header_length,
        payload_length: len
    })
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
        let asn1_type = get_asn1_type(&buf).unwrap();
        assert!(matches!(asn1_type, ASN1Base::Sequence));
    }
    use crate::get_field;
    #[test]
    fn get_outer_sequence_field() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf, 0).unwrap();
        assert_eq!(field.start_offset,0);
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,1376);
    }
    #[test]
    fn get_inner_sequence_field1() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf, 4).unwrap();
        assert_eq!(field.start_offset,4);
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,840);
    }
    #[test]
    fn get_inner_sequence_field2() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf, 848).unwrap();
        assert_eq!(field.start_offset,848);
        assert_eq!(field.header_length,3);
        assert_eq!(field.payload_length,13);
    }
    #[test]
    fn get_inner_sequence_field3() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf, 863).unwrap();
        assert_eq!(field.start_offset,863);
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,513);
    }
}
