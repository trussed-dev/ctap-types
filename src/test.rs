use ciborium::Value;
use serde::Serialize;

fn parse_argument(additional_info: u8, value: &[u8]) -> (u64, usize) {
    match additional_info {
        0..24 => (additional_info.into(), 0),
        24 => (value[0].into(), 1),
        25 => {
            let (argument, _) = value.split_first_chunk().unwrap();
            (u16::from_be_bytes(*argument).into(), argument.len())
        }
        26 => {
            let (argument, _) = value.split_first_chunk().unwrap();
            (u32::from_be_bytes(*argument).into(), argument.len())
        }
        27 => {
            let (argument, _) = value.split_first_chunk().unwrap();
            (u64::from_be_bytes(*argument), argument.len())
        }
        28..=30 => panic!("reserved additional info: {additional_info}"),
        31 => panic!("indefinite length items are not allowed in canonical CBOR"),
        32.. => panic!("illegal additional info: {additional_info}"),
    }
}

fn parse_value<'a>(data: &'a [u8], path: &str) -> &'a [u8] {
    println!("Checking value {path}");

    assert!(data.len() > 0, "CBOR value must not be empty");
    let mut offset = 1;
    let major_type = (data[0] & 0b11100000) >> 5;
    let additional_info = data[0] & 0b00011111;
    let (argument, n) = parse_argument(additional_info, &data[offset..]);
    offset += n;

    // if the argument encodes an integer, it must be encoded as short as possible
    if major_type <= 5 {
        let expected = if let Ok(argument) = u8::try_from(argument) {
            if argument <= 23 {
                argument
            } else {
                24
            }
        } else if argument <= u16::MAX.into() {
            25
        } else if argument <= u32::MAX.into() {
            26
        } else {
            27
        };
        assert_eq!(
            additional_info, expected,
            "integer value {argument} must use additional info {expected}"
        );
    }

    let argument = usize::try_from(argument).unwrap();
    match major_type {
        0 | 1 | 7 => {
            // no additional restrictions, no additional data
        }
        2 => {
            // byte strings: no additional restrictions, but additional data
            offset += argument;
        }
        3 => {
            // text strings: must be valid UTF-8
            let s = &data[offset..][..argument];
            assert!(
                str::from_utf8(s).is_ok(),
                "text must be valid UTF-8: {}",
                String::from_utf8_lossy(s)
            );
            offset += argument;
        }
        4 => {
            // arrays: must have valid items
            for i in 0..argument {
                let item = parse_value(&data[offset..], &format!("{path}[{i}]"));
                offset += item.len();
            }
        }
        5 => {
            // maps: must have valid items and be sorted
            let mut last_key = None;
            for i in 0..argument {
                let key = parse_value(&data[offset..], &format!("{path}[{i}].key"));
                offset += key.len();

                let parsed_key: Value = ciborium::from_reader(key).unwrap();
                println!("{path}[{i}].key = {parsed_key:?}");

                let value = parse_value(&data[offset..], &format!("{path}[{i}].value"));
                offset += value.len();

                if let Some(last_key) = last_key {
                    assert!(
                        last_key < key,
                        "map keys must be in lexicographical order: keys[{}] = {}, keys[{i}] = {}",
                        i - 1,
                        hex::encode(last_key),
                        hex::encode(key)
                    );
                }
                last_key = Some(key);
            }
        }
        6 => {
            panic!("tags are not allowed in canonical CBOR");
        }
        8.. => panic!("illegal major type: {major_type}"),
    };

    &data[..offset]
}

pub fn assert_canonical_cbor<T: Serialize>(object: &T) {
    let mut buffer = [0; 1024];
    let serialized = cbor_smol::cbor_serialize(&object, &mut buffer).unwrap();
    let value = parse_value(&serialized, "root");
    assert_eq!(
        value.len(),
        serialized.len(),
        "CBOR data must not contain trailing bytes"
    );
}
