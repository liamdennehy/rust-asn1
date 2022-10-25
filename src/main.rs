use rust_asn1::{get_asn1_type, get_file_as_byte_vec, ASN1Base};

fn main() {
    let buf = get_file_as_byte_vec(&"1.crt".to_string());
    let asn1_type = get_asn1_type(&buf).expect("No no");
    // match asn1_type {
    //     ASN1Base::Sequence => open_sequence(&buf.clone(), 0),
    //     ASN1Base::Set => todo!()
    // }
}

// fn open_sequence(buf: &Vec<u8>, offset: usize) {
//     let lenbytes: usize;
//     let len: usize = match buf[offset + 1] {
//         0 ..=128 => {
//             // println!("Short!");
//             lenbytes = 1;
//             buf[offset + 1] as usize
//         },
//         _ => {
//             // println!("Long: {:?}", buf[offset + 1]);
//             lenbytes = (buf[offset + 1] - 128) as usize;
//             let mut len: usize = 0;
//             for byte in 0..lenbytes {
//                 // println!("Byte: {:?}", buf[offset + byte + 2]);
//                 len += (buf[offset + byte + 2]) as usize;
//                 if byte < (lenbytes - 1) {
//                     len = len << 8;
//                 }
//             }
//             len
//         }
//     };
//     let header_length = lenbytes + 2;
//     println!("Sequence Length: {:?}", buf.len());
//     println!("Sequence Header: {:?}", header_length);
//     let sequence_payload = &buf[(header_length)..(len + header_length)];
//     println!("Sequence Payload Length: {:?}", sequence_payload.len());
// }
