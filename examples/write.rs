extern crate tar;

use std::collections::HashMap;

use std::fs::File;
use std::vec::Vec;
use tar::Builder;
use tar::EntryType;
use tar::Header;

fn create_pax_header(header: &Header, info: &HashMap<String, String>) -> Vec<u8> {
    let mut records: Vec<u8> = Vec::new();
    let mut buffer: Vec<u8> = Vec::new();
    for (k, v) in info.iter() {
        let l = k.len() + v.len() + 3;
        let mut n;
        let mut p = 0;
        loop {
            n = l + p.to_string().len();
            if n == p {
                break;
            }
            p = n;
        }
        records.append(&mut p.to_string().as_bytes().to_vec());
        records.append(&mut b" ".to_vec());
        records.append(&mut k.as_bytes().to_vec());
        records.append(&mut b"=".to_vec());
        records.append(&mut v.as_bytes().to_vec());
        records.append(&mut b"\n".to_vec());
    }

    let mut pax_header = Header::new_ustar();
    pax_header.set_path("././@PaxHeader").unwrap();
    pax_header.set_entry_type(EntryType::XHeader);
    pax_header.set_size(records.len().try_into().unwrap());
    pax_header.set_cksum();

    // Add padding
    let remainder = records.len() % 512;
    records.append(
        &mut std::iter::repeat("\0")
            .take(512 - remainder)
            .collect::<String>()
            .as_bytes()
            .to_vec(),
    );

    buffer.append(&mut pax_header.as_bytes().to_vec());
    buffer.append(&mut records);
    buffer.append(&mut header.as_bytes().to_vec());

    buffer
}

fn main() {
    let file = File::create("foo.tar").unwrap();
    let mut a = Builder::new(file);

    let data: &[u8] = "1234".as_bytes();
    let mut header = Header::new_ustar();
    header.set_path("README.md").unwrap();
    header.set_size(data.len().try_into().unwrap());
    header.set_cksum();

    let mut info: HashMap<String, String> = HashMap::new();
    info.insert("foo".to_string(), "bar".to_string());
    let mut pax_header = create_pax_header(&header, &info);

    a.append_raw_header(&mut pax_header, data).unwrap();

    let _ = a.finish();
}
