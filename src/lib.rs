use std::fs::{File, metadata};
use std::io::Read;

pub struct ASN1Field <'a> {
    tag: Tag,
    tag_class: TagClass,
    binary: &'a [u8],
    header_length: u8,
    payload_length: u64,
    // members: Option<&'a [ASN1Field<'a>]>
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

pub fn get_asn1_type(buf: &[u8]) -> (Tag, TagClass, u8) {
    let tag_byte: u8 = buf[0];
    let tag_class_bits = tag_byte >> 6;
    if tag_class_bits > 0 {
        return (
            Tag::Unknown,
            match tag_class_bits {
                1 => TagClass::Application,
                2 => TagClass::ContextSpecific,
                3 => TagClass::Private,
                _ => panic!("This should not happen")
            },
            tag_byte
        )
    }
    let tag_is_constructed = (tag_byte & 32) == 32;
    let tag_bits: u8;
    if tag_is_constructed {
        println!("Constructed tag");
        tag_bits = (tag_byte - 32) << 2 >> 2;
    } else {
        tag_bits = tag_byte << 2 >> 2;
    }
    let tag_class: TagClass;
    println!("Tag Byte: {}",tag_byte);
    println!("Tag Class: {}",tag_class_bits);
    println!{"tag bits: {}",tag_bits};
    tag_class = TagClass::Universal;
    let tag: Tag;
    match tag_bits {
        0x03 => tag = Tag::BitString,
        0x10 => tag = Tag::Sequence,
        _ => panic!()
        // _ => return (Tag::Unknown, tag_class)
    }
    return (tag, tag_class, tag_byte)
}

pub fn get_field(buf: &[u8]) -> Result<ASN1Field, String> {
    let members: Option<&[ASN1Field]>;
    let (tag, tag_class, tag_byte) = get_asn1_type(&buf);
    let lenbytes: u8;
    let header_length: u8;
    println!("Length byte 1: {}", buf[1]);
    let payload_length: u64 = match buf[1] {
        0 ..=127 => {
            header_length = 2;
            println!("Short Length");
            lenbytes = 1;
            buf[1] as u64
        },
        128 ..=255 => {
            println!("Long Length");
            lenbytes = buf[1] - 128;
            header_length = lenbytes + 2;
            let mut payload_length: u64 = 0;
            for lenbyte in 0..lenbytes {
                // println!("Byte: {:?}", buf[offset + byte + 2]);
                payload_length += buf[(lenbyte as usize) + 2] as u64;
                if lenbyte < (lenbytes - 1) {
                    payload_length = payload_length << 8;
                }
            }
            payload_length
        }
    };
    println!("Buffer bytes left: {:?}", buf.len() - header_length as usize);
    println!("Field Header Length: {:?}", header_length);
    if (payload_length + header_length as u64) > buf.len() as u64 {
        return Err(format!("Length of field ({}) exceeded input buffer", payload_length));
    }
    let payload = &buf[(header_length as usize)..((payload_length + header_length as u64) as usize)];
    println!("Field Payload Length: {:?}", payload.len());
    let mut member: ASN1Field;
    let mut member_offset: usize = 0;
    match tag {
        Tag::Sequence => {
            println!("Found a Sequence!");
            println!();
            println!("Sequence offset: {}", member_offset);
            member = get_field(&payload).unwrap();
            member_offset += member.header_length as usize + member.payload_length as usize;
            member = get_field(&payload[member_offset..payload.len()]).unwrap();

            members = Some(&[member]);
        },
        Tag::Set => members = Some(&[]),
        _ => members = None
    }
    Ok(ASN1Field {
        tag: tag,
        tag_class: tag_class,
        binary: &buf,
        header_length: header_length,
        payload_length: payload_length,
        // members: members
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
    fn get_sequence_inner_field1() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[4..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,840);
    }
    #[test]
    fn get_sequence_inner_field2() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[848..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,3);
        assert_eq!(field.payload_length,13);
    }
    #[test]
    fn get_sequence_inner_field3() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf[863..buf.len()]).unwrap();
        assert!(matches!(field.tag, Tag::BitString));
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,513);
    }
}
