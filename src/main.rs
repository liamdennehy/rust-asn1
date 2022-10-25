use rust_asn1::{get_asn1_type, get_file_as_byte_vec, ASN1Base};

fn main() {
    let buf = get_file_as_byte_vec(&"1.crt".to_string());
    let asn1_type = get_asn1_type(&buf).expect("No no");
    match asn1_type {
        ASN1Base::Sequence => open_sequence(&buf.clone(), 0),
        ASN1Base::Set => todo!()
    }
}

fn open_sequence(buf: &Vec<u8>, offset: usize) {
    println!("Sequence opened");
}
