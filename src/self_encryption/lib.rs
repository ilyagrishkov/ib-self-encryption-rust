// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A file **content** self_encryptor.
//!
//! This library provides convergent encryption on file-based data and produces a `DataMap` type and
//! several chunks of encrypted data. Each chunk is up to 1MB in size and has an index and a name. This name is the
//! SHA3-256 hash of the content, which allows the chunks to be self-validating.  If size and hash
//! checks are utilised, a high degree of certainty in the validity of the data can be expected.
//!
//! [Project GitHub page](https://github.com/maidsafe/self_encryption).
//!
//! # Examples
//!
//! A working implementation can be found
//! in the "examples" folder of this project.
//!
//! ```
//! use self_encryption::{encrypt, test_helpers::random_bytes};
//!
//! #[tokio::main]
//! async fn main() {
//!     let file_size = 10_000_000;
//!     let bytes = random_bytes(file_size);
//!
//!     if let Ok((_data_map, _encrypted_chunks)) = encrypt(bytes) {
//!         // .. then persist the `encrypted_chunks`.
//!         // Remember to keep `data_map` somewhere safe..!
//!     }
//! }
//! ```
//!
//! Storage of the `Vec<EncryptedChunk>` or `DataMap` is outwith the scope of this
//! library and must be implemented by the user.

// Doesn't allow casts on constants yet, remove when issue is fixed:
// https://github.com/rust-lang-nursery/rust-clippy/issues/2267
#![allow(clippy::cast_lossless, clippy::decimal_literal_representation)]

use crate::self_encryption::encryption::{Iv, Key, Pad, IV_SIZE, KEY_SIZE, PAD_SIZE};
pub use crate::self_encryption::{
    data_map::{ChunkInfo, DataMap},
    error::{Error, Result},
};
use bytes::Bytes;
use itertools::Itertools;
use xor_name::XorName;

// export these because they are used in our public API.
pub use bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
pub use xor_name;
use crate::self_encryption::{chunk, decrypt, encrypt};

/// The minimum size (before compression) of data to be self-encrypted, defined as 3kB.
pub const MIN_ENCRYPTABLE_BYTES: usize = 3 * MIN_CHUNK_SIZE;
/// The maximum size (before compression) of an individual chunk of the file, defined as 1MB.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;
/// The minimum size (before compression) of an individual chunk of the file, defined as 1kB.
pub const MIN_CHUNK_SIZE: usize = 1024;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: i32 = 6;

/// The actual encrypted content
/// of the chunk, and its key index.
#[derive(Clone)]
pub struct EncryptedChunk {
    /// Index number (zero-based)
    pub index: usize,
    /// The encrypted contents of the chunk.
    pub content: Bytes,
}

pub fn serialise<T: Serialize>(data: &T) -> Result<Vec<u8>, Error> {
    Ok(bincode::serialize(data)?)
}

pub fn deserialise<T>(data: &[u8]) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
{
    match bincode::deserialize(data) {
        Ok(data) => Ok(data),
        Err(_) => Err(Error::Deserialise),
    }
}

/// Encrypts a set of bytes and returns the encrypted data together with
/// the data map that is derived from the input data, and is used to later decrypt the encrypted data.
/// Returns an error if the size is too small for self-encryption.
/// Only files larger than 3072 bytes (3 * MIN_CHUNK_SIZE) can be self-encrypted.
/// Smaller files will have to be batched together for self-encryption to work.
pub fn encrypt(bytes: Bytes, identity: String) -> Result<(DataMap, Vec<EncryptedChunk>)> {
    if (MIN_ENCRYPTABLE_BYTES) > bytes.len() {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {}",
            MIN_ENCRYPTABLE_BYTES
        )));
    }
    let (num_chunks, batches) = chunk::batch_chunks(bytes);
    let (data_map, encrypted_chunks) = encrypt::encrypt(batches, identity);
    if num_chunks > encrypted_chunks.len() {
        return Err(Error::Encryption);
    }
    Ok((data_map, encrypted_chunks))
}

/// Decrypts what is expected to be the full set of chunks covered by the data map.
pub fn decrypt_full_set(data_map: &DataMap, chunks: &[EncryptedChunk], identity: String) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);
    let sorted_chunks = chunks
        .iter()
        .sorted_by_key(|c| c.index)
        .cloned() // should not be needed, something is wrong here, the docs for sorted_by_key says it will return owned items...!
        .collect_vec();
    decrypt::decrypt(src_hashes, sorted_chunks, identity)
}

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub(crate) fn xor(data: Bytes, &Pad(pad): &Pad) -> Bytes {
    let vec: Vec<_> = data
        .iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect();
    Bytes::from(vec)
}

fn extract_hashes(data_map: &DataMap) -> Vec<XorName> {
    data_map.infos().iter().map(|c| c.src_hash).collect()
}

pub(crate) fn get_pad_key_and_iv(chunk_index: usize, chunk_hashes: &[XorName]) -> (Pad, Key, Iv) {
    let (n_1, n_2) = match chunk_index {
        0 => (chunk_hashes.len() - 1, chunk_hashes.len() - 2),
        1 => (0, chunk_hashes.len() - 1),
        n => (n - 1, n - 2),
    };
    let src_hash = &chunk_hashes[chunk_index];
    let n_1_src_hash = &chunk_hashes[n_1];
    let n_2_src_hash = &chunk_hashes[n_2];

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .zip(src_hash.iter().chain(n_2_src_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().chain(iv.iter_mut()).zip(n_1_src_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

// Returns the number of chunks according to file size.
pub(crate) fn get_num_chunks(file_size: usize) -> usize {
    if file_size < (3 * MIN_CHUNK_SIZE) {
        return 0;
    }
    if file_size < (3 * MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE == 0 {
        file_size / MAX_CHUNK_SIZE
    } else {
        (file_size / MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            return file_size - (2 * (file_size / 3));
        }
    }
    let total_chunks = get_num_chunks(file_size);
    if chunk_index < total_chunks - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = file_size % MAX_CHUNK_SIZE;
    let penultimate = (total_chunks - 2) == chunk_index;
    if remainder == 0 {
        return MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        MAX_CHUNK_SIZE
    } else {
        remainder
    }
}

// Returns the [start, end) half-open byte range of a chunk.
pub(crate) fn get_start_end_positions(file_size: usize, chunk_index: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start = get_start_position(file_size, chunk_index);
    (start, start + get_chunk_size(file_size, chunk_index))
}

fn get_start_position(file_size: usize, chunk_index: usize) -> usize {
    let total_chunks = get_num_chunks(file_size);
    if total_chunks == 0 {
        return 0;
    }
    let last = (total_chunks - 1) == chunk_index;
    let first_chunk_size = get_chunk_size(file_size, 0);
    if last {
        first_chunk_size * (chunk_index - 1) + get_chunk_size(file_size, chunk_index - 1)
    } else {
        first_chunk_size * chunk_index
    }
}

