use std::fs::{File, metadata};
use std::io::Read;

pub struct ASN1Field <'a> {
    tag: Tag,
    tag_class: TagClass,
    buf: &'a Vec<u8>,
    start_offset: u64,
    header_length: u8,
    payload_length: u64,
    members: Vec<ASN1Field<'a>>
}

impl ASN1Field<'_> {
    pub fn get_payload_vec(&self) -> Vec<u8> {
        let payload_start: usize = self.start_offset as usize + self.header_length as usize;
        self.buf[payload_start..(payload_start + self.payload_length as usize)].to_vec()
    }

    pub fn get_members_vec(&self) -> &Vec<ASN1Field> {
        &self.members
    }

    pub fn get_type_name(&self) -> String{
        asn1_printable_type(&self.tag)
    }
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
        tag_bits = (tag_byte - 32) << 2 >> 2;
    } else {
        tag_bits = tag_byte << 2 >> 2;
    }
    let tag_class: TagClass;
    tag_class = TagClass::Universal;
    let tag: Tag;
    match tag_bits {
        0x02 => tag = Tag::Integer,
        0x03 => tag = Tag::BitString,
        0x04 => tag = Tag::OctetString,
        0x05 => tag = Tag::Null,
        0x06 => tag = Tag::ObjectIdentifier,
        0x0C => tag = Tag::UTF8String,
        0x10 => tag = Tag::Sequence,
        0x11 => tag = Tag::Set,
        0x13 => tag = Tag::PrintableString,
        0x16 => tag = Tag::IA5String,
        0x17 => tag = Tag::UTCTime,
        _ => panic!("Encountered an unrecognised ASN1 Tag: {}", tag_bits)
    }
    return (tag, tag_class, tag_byte)
}

pub fn asn1_printable_type(tag: &Tag) -> String {
    match tag {
        Tag::Integer => String::from("Integer"),
        Tag::BitString => String::from("BitString"),
        Tag::Null => String::from("Null"),
        Tag::ObjectIdentifier => String::from("ObjectIdentifier"),
        Tag::UTF8String => String::from("UTF8String"),
        Tag::PrintableString => String::from("PrintableString"),
        Tag::Sequence => String::from("Sequence"),
        Tag::UTCTime => String::from("UTCTime"),
        _ => String::from("Unknown")
    }
}

pub fn get_field(buf: &Vec<u8>, start_offset: u64) -> Result<ASN1Field, String> {
    println!("Getting a field from offset {}", start_offset);
    let (tag, tag_class, tag_byte) = get_asn1_type(&buf[(start_offset as usize)..buf.len()]);
    println!("Field Tag: {} ({})", asn1_printable_type(&tag), tag_byte);
    let lenbytes: u8;
    let header_length: u8;
    let payload_length: u64 = match buf[start_offset as usize + 1] {
        0 ..=127 => {
            header_length = 2;
            buf[start_offset as usize + 1] as u64
        },
        128 ..=255 => {
            lenbytes = buf[start_offset as usize + 1] - 128;
            header_length = lenbytes + 2;
            let mut payload_length: u64 = 0; // lenbytes are a variable-length integer of the payload length.
            let mut lenbytecount: u8 = 0; // How many bytes have we processed
            for lenbyte in 0..lenbytes {
                payload_length += buf[start_offset as usize + (lenbyte as usize) + 2] as u64;
                lenbytecount += 1;
                if lenbytecount < lenbytes {
                    payload_length = payload_length << 8;
                }
            }
            payload_length
        }
    };
    let payload_start = start_offset as usize + header_length as usize;
    match tag {
        Tag::PrintableString | Tag::UTF8String => println!(
            "Found a String: {}",
            std::str::from_utf8(
                &buf[payload_start..(payload_start + payload_length as usize)]
            ).unwrap()
        ),
        _ => ()
    }
    if (start_offset + payload_length + header_length as u64) > buf.len() as u64 {
        return Err(format!("Length of field ({}) exceeded input buffer", payload_length));
    }
    println!("Header Length: {}", header_length);
    println!("Payload Length: {}", payload_length);
    let members: Vec<ASN1Field> = match tag {
        Tag::Sequence | Tag::Set => {
            println!();
            println!("!! Found a collection at Start Offset: {}", start_offset);
            get_collection_members(buf,start_offset + header_length as u64, payload_length)
        },
        _ => Vec::new()
    };
    Ok(ASN1Field {
        tag: tag,
        tag_class: tag_class,
        buf: buf,
        header_length: header_length,
        payload_length: payload_length,
        start_offset: start_offset,
        members: members,
    })
}

fn get_collection_members(buf: &Vec<u8>, start_offset: u64, collection_length: u64) -> Vec<ASN1Field> {
    let mut member: ASN1Field;
    let mut members: Vec<ASN1Field> = Vec::new();
    let mut member_offset: u64 = 0;
    while (member_offset as u64) < collection_length {

        println!("Getting Sequence Member. start_offset: {}, member_offset: {}, collection_length: {}", start_offset, member_offset, collection_length);
        member = get_field(&buf, start_offset + member_offset).unwrap();
        println!("Found member: member_offest: {}, header length {} payload length {}", member_offset, member.header_length, member.payload_length);
        member_offset += member.header_length as u64 + member.payload_length as u64;
        members.push(member);
    }
    members
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
        let (tag, tag_class, tag_byte) = get_asn1_type(&buf);
        assert!(matches!(tag, Tag::Sequence));
        assert!(matches!(tag_class, TagClass::Universal));
    }
    use crate::get_field;
    #[test]
    fn get_outer_sequence_field() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf,0).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.binary[0],48);
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,1376);
    }
    #[test]
    fn get_sequence_inner_field1() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf,4).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,840);
    }
    #[test]
    fn get_sequence_inner_field2() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf,848).unwrap();
        assert!(matches!(field.tag, Tag::Sequence));
        assert_eq!(field.header_length,2);
        assert_eq!(field.payload_length,13);
    }
    #[test]
    fn get_sequence_inner_field3() {
        let test_cert = "1.crt".to_string();
        let buf = get_file_as_byte_vec(&test_cert);
        let field = get_field(&buf,863).unwrap();
        assert!(matches!(field.tag, Tag::BitString));
        assert_eq!(field.header_length,4);
        assert_eq!(field.payload_length,513);
    }
}
