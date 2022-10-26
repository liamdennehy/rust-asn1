use std::fs::{File, metadata};
use std::io::Read;

pub struct ASN1Field <'a> {
    tag: Tag,
    tag_class: TagClass,
    binary: &'a [u8],
    header_length: usize,
    payload_length: usize
}

pub enum Tag {
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    UTF8String,
    Sequence,
    Set,
    PrintableString,
    IA5String,
    UTCTime,
    GeneralizedTime,
    Unknown
}

pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private
}

pub enum ASN1Base {
    Sequence,
    Set,
    ASN1Unknown
}

pub struct Sequence <'a> {
    contents: &'a [u8]
}

pub fn get_asn1_type(buf: &[u8]) -> (Tag, TagClass) {
    let tag_byte: u8 = buf[0];
    let tag_bits: u8 = tag_byte << 2 >> 2;
    let tag_class_bits = tag_byte >> 6;
    let tag_class: TagClass;
    println!("{}",tag_class_bits);
    match tag_class_bits {
        0 => tag_class = TagClass::Universal,
        1 => tag_class = TagClass::Application,
        2 => tag_class = TagClass::ContextSpecific,
        3 => tag_class = TagClass::Private,
        _ => panic!("Not possible, bit shift broke"),
    }
    println!{"tag bits: {}",tag_bits};
    match tag_bits {
        0x03 => return (Tag::BitString, tag_class),
        0x30 => return (Tag::Sequence, tag_class),
        _ => return (Tag::Unknown, tag_class)
    }
}

pub fn get_field(buf: &[u8]) -> Result<ASN1Field, String> {
    let (tag, tag_class) = get_asn1_type(&buf);
    let lenbytes: usize;
    let len: usize = match buf[1] {
        0 ..=128 => {
            // println!("Short!");
            lenbytes = 1;
            buf[1] as usize
        },
        _ => {
            // println!("Long: {:?}", buf[offset + 1]);
            lenbytes = (buf[1] - 128) as usize;
            let mut len: usize = 0;
            for byte in 0..lenbytes {
                // println!("Byte: {:?}", buf[offset + byte + 2]);
                len += (buf[byte + 2]) as usize;
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
    Ok(ASN1Field {
        tag: tag,
        tag_class: tag_class,
        binary: &buf,
        header_length: header_length,
        payload_length: len
    })
}


pub fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    let result = buffer.clone();
    result
}

#[cfg(test)]
mod tests {
    use crate::{get_asn1_type, get_file_as_byte_vec};
    use std::matches;
    use crate::{Tag, TagClass};
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
        let (tag, tag_class) = get_asn1_type(&buf);
        assert!(matches!(tag, Tag::Sequence));
        assert!(matches!(tag_class, TagClass::Universal));
    }
    use crate::get_field;
    #[test]
    fn get_outer_sequence_field() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[0..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.binary[0],48);
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,1376);
    }
    #[test]
    fn get_inner_sequence_field1() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[4..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,840);
    }
    #[test]
    fn get_inner_sequence_field2() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[848..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,3);
        assert_eq!(field.payload_length,13);
    }
    #[test]
    fn get_inner_sequence_field3() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        // let field = get_field(&buf[863..buf.len()]).unwrap();
        // assert!(matches!(field.tag, Tag::BitString));
        // assert_eq!(field.header_length,4);
        // assert_eq!(field.payload_length,513);
    }
}
