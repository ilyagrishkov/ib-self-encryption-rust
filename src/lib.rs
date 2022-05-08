use std::{
    env,
    fmt::{self},
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    string::String,
    sync::Arc,
};
use std::os::raw::c_char;
use std::path::Path;

use bytes::Bytes;
use crate::self_encryption::lib::{
    DataMap, decrypt_full_set, encrypt, EncryptedChunk, Error, Result, serialise, deserialise
};

use xor_name::XorName;

#[allow(unused_imports)]
use crate::rustgo::{allocate, deallocate, get_byte_vec, get_string, return_string};

mod rustgo;
mod self_encryption;

fn to_hex(ch: u8) -> String {
    fmt::format(format_args!("{:02x}", ch))
}

fn file_name(name: XorName) -> String {
    let mut string = String::new();
    for ch in name.0 {
        string.push_str(&to_hex(ch));
    }
    string
}

#[derive(Clone)]
struct DiskBasedStorage {
    pub(crate) storage_path: String,
}

impl DiskBasedStorage {
    fn calculate_path(&self, name: XorName) -> PathBuf {
        let mut path = PathBuf::from(self.storage_path.clone());
        path.push(file_name(name));
        path
    }

    fn get(&self, name: XorName) -> Result<Bytes, Error> {
        let path = self.calculate_path(name);
        let mut file = File::open(&path)?;
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data);
        Ok(Bytes::from(data))
    }

    fn put(&self, name: XorName, data: Bytes) -> Result<()> {
        let path = self.calculate_path(name);
        let mut file = File::create(&path)?;
        file.write_all(&data[..])
            .map(|_| {
                println!("Chunk written to {:?}", path);
            })
            .map_err(From::from)
    }
}

#[no_mangle]
pub extern fn self_encrypt(filepath_ptr: *mut c_char, identity_ptr: *mut c_char) -> () {
    let filepath = get_string(filepath_ptr);
    let identity = get_string(identity_ptr);

    let mut chunk_store_dir = env::current_dir().unwrap();
    chunk_store_dir.push("chunk_store/");
    let _ = fs::create_dir(chunk_store_dir.clone());
    let storage_path = chunk_store_dir.to_str().unwrap().to_owned();
    let storage = Arc::new(DiskBasedStorage { storage_path });

    let mut data_map_file = chunk_store_dir;
    data_map_file.push("data_map");

    if let Ok(mut file) = File::open(filepath.clone()) {
        let mut data = Vec::new();
        match file.read_to_end(&mut data) {
            Ok(_) => (),
            Err(error) => return println!("{}", error),
        }

        let (data_map, encrypted_chunks) = encrypt(Bytes::from(data), identity).unwrap();

        let result = encrypted_chunks
            .iter()
            .map(|c| (c, storage.clone()))
            .map(|(c, store)| store.put(XorName::from_content(&c.content), c.content.clone()))
            .collect::<Vec<_>>();

        assert!(result.iter().all(|r| r.is_ok()));

        match File::create(data_map_file.clone()) {
            Ok(mut file) => {
                let encoded = serialise(&data_map).unwrap();
                match file.write_all(&encoded[..]) {
                    Ok(_) => println!("Data map written to {:?}", data_map_file),
                    Err(error) => {
                        println!(
                            "Failed to write data map to {:?} - {:?}",
                            data_map_file, error
                        );
                    }
                }
            }
            Err(error) => {
                println!(
                    "Failed to create data map at {:?} - {:?}",
                    data_map_file, error
                );
            }
        }
    } else {
        println!("Failed to open {}", &filepath);
    }
}

#[no_mangle]
pub extern fn self_decrypt(destination: *mut c_char, identity_ptr: *mut c_char) -> () {
    let dst = get_string(destination);
    let identity = get_string(identity_ptr);
    let dst_file = Path::new(&dst).file_name().unwrap().to_str().unwrap();

    let mut chunk_store_dir = env::current_dir().unwrap();
    chunk_store_dir.push("chunk_store/");
    let _ = fs::create_dir(chunk_store_dir.clone());
    let storage_path = chunk_store_dir.to_str().unwrap().to_owned();
    let storage = Arc::new(DiskBasedStorage { storage_path });

    let mut data_map_file = chunk_store_dir;
    data_map_file.push("data_map");
    if let Ok(mut file) = File::open(data_map_file.to_str().unwrap()) {
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data).unwrap();
        match deserialise::<DataMap>(&data) {
            Ok(data_map) => {
                let (keys, encrypted_chunks) = data_map
                    .infos()
                    .iter()
                    .map(|key| {
                        Ok::<(_, _), Error>((
                            key.clone(),
                            EncryptedChunk {
                                index: key.index,
                                content: storage.get(key.dst_hash)?,
                            },
                        ))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flatten()
                    .fold((vec![], vec![]), |(mut keys, mut chunks), (key, chunk)| {
                        keys.push(key);
                        chunks.push(chunk);
                        (keys, chunks)
                    });
                let write_path = format!("{}{}", env::current_dir().unwrap().to_str().unwrap(), dst_file);
                if let Ok(mut file) = File::create(write_path.clone()) {
                    let content =
                        decrypt_full_set(&DataMap::new(keys), encrypted_chunks.as_ref(), identity)
                            .unwrap();
                    match file.write_all(&content[..]) {
                        Err(error) => println!("File write failed - {:?}", error),
                        Ok(_) => {
                            println!("File decrypted to {:?}", write_path)
                        }
                    };
                } else {
                    println!("Failed to create {}", (write_path));
                }
            }
            Err(_) => {
                println!("Failed to parse data map - possible corruption");
            }
        }
    } else {
        println!("Failed to open data map at {:?}", data_map_file);
    }
}
