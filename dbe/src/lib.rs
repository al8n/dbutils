#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::convert::TryInto;

#[cfg(any(feature = "aes", feature = "aes-std"))]
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherError};
#[cfg(any(feature = "aes", feature = "aes-std"))]
use aes::{Aes128, Aes192, Aes256};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use bytes::Bytes;
use rand::RngCore;

/// The block size of the encryption algorithm.
pub const BLOCK_SIZE: usize = 16;

/// IV.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct IV {
  iv: [u8; BLOCK_SIZE],
}

impl IV {
  /// Creates a default IV.
  #[inline]
  pub const fn new() -> Self {
    Self {
      iv: [0; BLOCK_SIZE],
    }
  }

  /// Creates a random IV.
  #[inline]
  pub fn random() -> Self {
    Self { iv: random_iv() }
  }
}

impl core::ops::Deref for IV {
  type Target = [u8; BLOCK_SIZE];

  fn deref(&self) -> &Self::Target {
    &self.iv
  }
}

impl core::ops::DerefMut for IV {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.iv
  }
}

impl AsRef<[u8]> for IV {
  fn as_ref(&self) -> &[u8] {
    &self.iv
  }
}

impl AsMut<[u8]> for IV {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.iv
  }
}

impl prost::Message for IV {
  fn encode_raw<B>(&self, buf: &mut B)
  where
    B: bytes::BufMut,
    Self: Sized,
  {
    let high = u64::from_le_bytes(self.iv[..8].try_into().unwrap());
    let low = u64::from_le_bytes(self.iv[8..].try_into().unwrap());
    prost::encoding::uint64::encode(1u32, &high, buf);
    prost::encoding::uint64::encode(2u32, &low, buf);
  }

  fn merge_field<B>(
    &mut self,
    tag: u32,
    wire_type: prost::encoding::WireType,
    buf: &mut B,
    ctx: prost::encoding::DecodeContext,
  ) -> Result<(), prost::DecodeError>
  where
    B: bytes::Buf,
    Self: Sized,
  {
    const STRUCT_NAME: &str = "IV";

    match tag {
      1u32 => {
        let mut high = 0;
        ::prost::encoding::uint64::merge(wire_type, &mut high, buf, ctx)
          .map(|_| {
            self.iv[..8].copy_from_slice(&high.to_le_bytes());
          })
          .map_err(|mut error| {
            error.push(STRUCT_NAME, "high");
            error
          })
      }
      2u32 => {
        let mut low = 0;
        ::prost::encoding::uint64::merge(wire_type, &mut low, buf, ctx)
          .map(|_| {
            self.iv[8..].copy_from_slice(&low.to_le_bytes());
          })
          .map_err(|mut error| {
            error.push(STRUCT_NAME, "low");
            error
          })
      }
      _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
    }
  }

  fn encoded_len(&self) -> usize {
    let high = u64::from_le_bytes(self.iv[..8].try_into().unwrap());
    let low = u64::from_le_bytes(self.iv[8..].try_into().unwrap());
    (if high != 0u64 {
      ::prost::encoding::uint64::encoded_len(1u32, &high)
    } else {
      0
    }) + (if low != 0u64 {
      ::prost::encoding::uint64::encoded_len(2u32, &low)
    } else {
      0
    })
  }

  fn clear(&mut self) {
    self.iv = [0; BLOCK_SIZE];
  }
}

/// Encryption algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
#[repr(i32)]
pub enum EncryptionAlgorithm {
  /// None.
  None = 0,
  /// AES.
  #[cfg(any(feature = "aes", feature = "aes-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "aes", feature = "aes-std"))))]
  Aes = 1,
}

impl EncryptionAlgorithm {
  /// Returns the encryption algorithm is none.
  #[inline]
  pub const fn is_none(&self) -> bool {
    match self {
      #[cfg(any(feature = "aes", feature = "aes-std"))]
      EncryptionAlgorithm::Aes => false,
      _ => true,
    }
  }

  /// Returns the encryption algorithm is some.
  #[inline]
  pub const fn is_some(&self) -> bool {
    match self {
      #[cfg(any(feature = "aes", feature = "aes-std"))]
      EncryptionAlgorithm::Aes => true,
      _ => false,
    }
  }

  /// Returns the encryption algorithm IV length.
  #[inline]
  pub const fn iv_length(&self) -> usize {
    match self {
      #[cfg(any(feature = "aes", feature = "aes-std"))]
      EncryptionAlgorithm::Aes => BLOCK_SIZE,
      EncryptionAlgorithm::None => 0,
    }
  }

  /// String value of the enum field names used in the ProtoBuf definition.
  ///
  /// The values are not transformed in any way and thus are considered stable
  /// (if the ProtoBuf definition does not change) and safe for programmatic use.
  pub const fn as_str(&self) -> &'static str {
    match self {
      EncryptionAlgorithm::None => "None",
      #[cfg(any(feature = "aes", feature = "aes-std"))]
      EncryptionAlgorithm::Aes => "Aes",
    }
  }
}

/// Encryption
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Encryption {
  algo: EncryptionAlgorithm,
  secret: bytes::Bytes,
}

impl Encryption {
  /// The block size of the encryption algorithm.
  pub const BLOCK_SIZE: usize = BLOCK_SIZE;

  /// Create a new encryption.
  #[inline]
  pub const fn new() -> Self {
    Self {
      algo: EncryptionAlgorithm::None,
      secret: Bytes::new(),
    }
  }

  /// Set the secret used to encrypt/decrypt the encrypted text.
  #[inline]
  pub fn set_secret(mut self, secret: Bytes) -> Self {
    self.secret = secret;
    self
  }

  /// Set the encryption algorithm to use.
  #[inline]
  pub const fn set_algorithm(mut self, algo: EncryptionAlgorithm) -> Self {
    self.algo = algo;
    self
  }

  /// Create a new encryption with AES algorithm.
  #[cfg(any(feature = "aes", feature = "aes-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "aes", feature = "aes-std"))))]
  #[inline]
  pub fn aes(secret: impl Into<Bytes>) -> Self {
    Self {
      algo: EncryptionAlgorithm::Aes,
      secret: secret.into(),
    }
  }

  /// Get the encryption algorithm.
  #[inline]
  pub const fn algorithm(&self) -> EncryptionAlgorithm {
    self.algo
  }

  /// Returns the encryption algorithm is none.
  #[inline]
  pub const fn is_none(&self) -> bool {
    self.algo.is_none()
  }

  /// Returns the encryption algorithm is some.
  #[inline]
  pub const fn is_some(&self) -> bool {
    self.algo.is_some()
  }

  /// Returns the secret used to encrypt/decrypt the encrypted text.
  #[inline]
  pub fn secret(&self) -> &[u8] {
    self.secret.as_ref()
  }

  /// Returns the secret in [`bytes::Bytes`] used to encrypt/decrypt the encrypted text.
  #[inline]
  pub fn secret_bytes(&self) -> bytes::Bytes {
    self.secret.clone()
  }
}

impl prost::Message for Encryption {
  #[allow(unused_variables)]
  fn encode_raw<B>(&self, buf: &mut B)
  where
    B: prost::bytes::BufMut,
  {
    if self.algo != EncryptionAlgorithm::default() {
      prost::encoding::int32::encode(1u32, &(self.algo as i32), buf);
    }
    if self.secret != b"" as &[u8] {
      prost::encoding::bytes::encode(2u32, &self.secret, buf);
    }
  }
  #[allow(unused_variables)]
  fn merge_field<B>(
    &mut self,
    tag: u32,
    wire_type: prost::encoding::WireType,
    buf: &mut B,
    ctx: prost::encoding::DecodeContext,
  ) -> ::core::result::Result<(), prost::DecodeError>
  where
    B: prost::bytes::Buf,
  {
    const STRUCT_NAME: &str = "Encryption";
    match tag {
      1u32 => {
        let value = &mut (self.algo as i32);
        prost::encoding::int32::merge(wire_type, value, buf, ctx).map_err(|mut error| {
          error.push(STRUCT_NAME, "algo");
          error
        })
      }
      2u32 => {
        let value = &mut self.secret;
        prost::encoding::bytes::merge(wire_type, value, buf, ctx).map_err(|mut error| {
          error.push(STRUCT_NAME, "secret");
          error
        })
      }
      _ => prost::encoding::skip_field(wire_type, tag, buf, ctx),
    }
  }
  #[inline]
  fn encoded_len(&self) -> usize {
    (if self.algo != EncryptionAlgorithm::default() {
      prost::encoding::int32::encoded_len(1u32, &(self.algo as i32))
    } else {
      0
    }) + (if self.secret != b"" as &[u8] {
      prost::encoding::bytes::encoded_len(2u32, &self.secret)
    } else {
      0
    })
  }
  fn clear(&mut self) {
    self.algo = EncryptionAlgorithm::default();
    self.secret.clear();
  }
}

/// AES-128 in CTR mode
#[cfg(any(feature = "aes", feature = "aes-std"))]
pub type Aes128Ctr = ctr::Ctr64BE<Aes128>;

/// AES-192 in CTR mode
#[cfg(any(feature = "aes", feature = "aes-std"))]
pub type Aes192Ctr = ctr::Ctr64BE<Aes192>;

/// AES-256 in CTR mode
#[cfg(any(feature = "aes", feature = "aes-std"))]
pub type Aes256Ctr = ctr::Ctr64BE<Aes256>;

/// Aes error
#[cfg(any(feature = "aes", feature = "aes-std"))]
#[derive(Debug, Copy, Clone)]
pub enum AesError {
  /// Invalid length
  InvalidLength(aes::cipher::InvalidLength),
  /// Invalid key size
  KeySizeError(usize),
  /// Stream cipher error
  StreamCipherError(StreamCipherError),
}

#[cfg(any(feature = "aes", feature = "aes-std"))]
impl core::fmt::Display for AesError {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self {
      AesError::KeySizeError(size) => write!(
        f,
        "aes: invalid key size {}, only supports 16, 24, 32 length for key",
        size
      ),
      AesError::StreamCipherError(err) => write!(f, "aes: {}", err),
      AesError::InvalidLength(e) => write!(f, "{}", e),
    }
  }
}

#[cfg(all(any(feature = "aes", feature = "aes-std"), feature = "std"))]
impl std::error::Error for AesError {}

/// Encrypt error
#[derive(Debug, Copy, Clone)]
pub enum EncryptError {
  /// Aes error
  #[cfg(any(feature = "aes", feature = "aes-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "aes", feature = "aes-std"))))]
  Aes(AesError),
  /// Length mismatch
  LengthMismatch {
    /// Source length
    src: usize,
    /// Destination length
    dst: usize,
  },
}

impl core::fmt::Display for EncryptError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      EncryptError::LengthMismatch { src, dst } => write!(
        f,
        "aes length mismatch: the length of source is {} and the length of destination {}",
        src, dst
      ),
      #[cfg(any(feature = "aes", feature = "aes-std"))]
      EncryptError::Aes(e) => write!(f, "{}", e), // EncryptError::IO(kd) => write!(f, "aes fail to write encrypt stream: {:?}", kd),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for EncryptError {}

/// Default encryptor
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DefaultEncryptor;

impl Encryptor for DefaultEncryptor {
  type Error = EncryptError;

  /// Encrypts self with IV.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  #[inline]
  fn encrypt(
    dst: &mut [u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<(), Self::Error> {
    encrypt(dst, key, iv, algo)
  }

  /// Encrypts self with IV to a new `Vec`.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  #[inline]
  fn encrypt_into_vec(
    src: &[u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<Vec<u8>, Self::Error> {
    encrypt_to_vec(src, key, iv, algo)
  }

  /// Encrypts self with IV to `dst`.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  #[inline]
  fn encrypt_to(
    src: &[u8],
    dst: &mut [u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<(), Self::Error> {
    encrypt_to(dst, src, key, iv, algo)
  }
}

/// AES encryption extensions
pub trait Encryptor {
  #[cfg(not(feature = "std"))]
  /// Compression/Decompression Error
  type Error: core::fmt::Display + core::fmt::Debug;

  #[cfg(feature = "std")]
  /// Compression/Decompression Error
  type Error: std::error::Error;

  /// Encrypts self with IV.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  fn encrypt(
    dst: &mut [u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<(), Self::Error>;

  /// Encrypts self with IV to a new `Vec`.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  fn encrypt_into_vec(
    src: &[u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<Vec<u8>, Self::Error>;

  /// Encrypts self with IV to a new [`bytes::Bytes`].
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  fn encrypt_into_bytes(
    src: &[u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<Bytes, Self::Error> {
    Self::encrypt_into_vec(src, key, iv, algo).map(Bytes::from)
  }

  /// Encrypts self with IV to `dst`.
  /// Can be used for both encryption and decryption.
  ///
  /// IV:
  ///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
  ///     - [`EncryptionAlgorithm::None`]: IV is ignored.
  fn encrypt_to(
    src: &[u8],
    dst: &mut [u8],
    key: &[u8],
    iv: &[u8],
    algo: EncryptionAlgorithm,
  ) -> Result<(), Self::Error>;

  /// Check if the private key length is valid
  #[inline]
  fn is_valid_private_key(secret: &[u8], algo: EncryptionAlgorithm) -> bool {
    is_valid_private_key(secret, algo)
  }
}

/// Returns the block size of the encryption algorithm
#[inline(always)]
pub const fn block_size(algo: EncryptionAlgorithm) -> usize {
  match algo {
    EncryptionAlgorithm::None => 0,
    #[cfg(any(feature = "aes", feature = "aes-std"))]
    EncryptionAlgorithm::Aes => BLOCK_SIZE,
  }
}

/// Encrypts data with IV.
/// Can be used for both encryption and decryption.
///
/// IV:
///     - `EncryptionAlgorithm::Aes`: IV is of AES block size.
///     - `EncryptionAlgorithm::None`: IV is ignored.
#[inline]
pub fn encrypt(
  _data: &mut [u8],
  _key: &[u8],
  _iv: &[u8],
  algo: EncryptionAlgorithm,
) -> Result<(), EncryptError> {
  match algo {
    #[cfg(any(feature = "aes", feature = "aes-std"))]
    EncryptionAlgorithm::Aes => aes_encrypt_in(_data, _key, _iv),
    _ => Ok(()),
  }
}

/// Encrypts src with IV to a new `Vec`.
/// Can be used for both encryption and decryption.
///
/// IV:
///     - `EncryptionAlgorithm::Aes`: IV is of AES block size.
///     - `EncryptionAlgorithm::None`: IV is ignored.
#[inline]
pub fn encrypt_to_vec(
  src: &[u8],
  _key: &[u8],
  _iv: &[u8],
  algo: EncryptionAlgorithm,
) -> Result<Vec<u8>, EncryptError> {
  
  match algo {
    #[cfg(any(feature = "aes", feature = "aes-std"))]
    EncryptionAlgorithm::Aes => {
      let mut dst = src.to_vec();
      aes_encrypt_in(dst.as_mut(), _key, _iv).map(|_| dst)
    },
    _ => Ok(src.to_vec()),
  }
}

/// Encrypts `src` with IV to `dst`.
/// Can be used for both encryption and decryption.
///
/// IV:
///     - [`EncryptionAlgorithm::Aes`]: IV is of AES block size.
///     - [`EncryptionAlgorithm::None`]: IV is ignored.
#[inline]
pub fn encrypt_to(
  dst: &mut [u8],
  src: &[u8],
  _key: &[u8],
  _iv: &[u8],
  algo: EncryptionAlgorithm,
) -> Result<(), EncryptError> {
  if dst.len() != src.len() {
    return Err(EncryptError::LengthMismatch {
      src: src.len(),
      dst: dst.len(),
    });
  }
  dst.copy_from_slice(src);
  match algo {
    #[cfg(any(feature = "aes", feature = "aes-std"))]
    EncryptionAlgorithm::Aes => aes_encrypt_in(dst, _key, _iv),
    _ => Ok(()),
  }
}

#[cfg(any(feature = "aes", feature = "aes-std"))]
#[inline(always)]
fn aes_encrypt_in(dst: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), EncryptError> {
  let kl = key.len();
  match kl {
    16 => Aes128Ctr::new_from_slices(key, iv)
      .map_err(|e| EncryptError::Aes(AesError::InvalidLength(e)))?
      .try_apply_keystream(dst)
      .map_err(|e| EncryptError::Aes(AesError::StreamCipherError(e))),
    24 => Aes192Ctr::new_from_slices(key, iv)
      .map_err(|e| EncryptError::Aes(AesError::InvalidLength(e)))?
      .try_apply_keystream(dst)
      .map_err(|e| EncryptError::Aes(AesError::StreamCipherError(e))),
    32 => Aes256Ctr::new_from_slices(key, iv)
      .map_err(|e| EncryptError::Aes(AesError::InvalidLength(e)))?
      .try_apply_keystream(dst)
      .map_err(|e| EncryptError::Aes(AesError::StreamCipherError(e))),
    _ => Err(EncryptError::Aes(AesError::KeySizeError(kl))),
  }
}

/// Check if the private key length is valid
#[inline]
pub const fn is_valid_private_key(_secret: &[u8], algo: EncryptionAlgorithm) -> bool {
  match algo {
    #[cfg(all(any(feature = "aes", feature = "aes-std")))]
    EncryptionAlgorithm::Aes => {
      let key_len = _secret.len();
      key_len == 16 || key_len == 24 || key_len == 32
    }
    EncryptionAlgorithm::None => true,
  }
}

/// generates IV.
#[inline]
pub fn random_iv() -> [u8; BLOCK_SIZE] {
  #[cfg(feature = "std")]
  {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let mut key = [0u8; BLOCK_SIZE];
    rng.fill_bytes(&mut key);
    key
  }

  #[cfg(not(feature = "std"))]
  {
    use rand::{rngs::OsRng, RngCore};
    let mut key = [0u8; BLOCK_SIZE];
    OsRng.fill_bytes(&mut key);
    key
  }
}

macro_rules! impl_encryption_algo_converter {
  ($($ty:ty),+ $(,)?) => {
    $(
      impl From<$ty> for EncryptionAlgorithm {
        fn from(val: $ty) -> EncryptionAlgorithm {
          match val {
            #[cfg(any(feature = "aes", feature = "aes-std"))]
            1 => EncryptionAlgorithm::Aes,
            _ => EncryptionAlgorithm::None,
          }
        }
      }
    )*
  };
}

impl_encryption_algo_converter!(i8, i16, i32, i64, isize, i128, u8, u16, u32, u64, usize, u128);

#[cfg(test)]
mod test {
  use super::*;
  use rand::{thread_rng, Rng};

  #[test]
  fn test_encrypt() {
    let mut rng = thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let iv = random_iv();

    let mut src = [0u8; 1024];
    rng.fill(&mut src);

    let mut dst = vec![0u8; 1024];
    encrypt_to(
      dst.as_mut_slice(),
      &src,
      &key,
      &iv,
      EncryptionAlgorithm::Aes,
    )
    .unwrap();

    let act = encrypt_to_vec(dst.as_slice(), &key, &iv, EncryptionAlgorithm::Aes).unwrap();
    assert_eq!(src.clone().to_vec(), act);

    let mut dst = vec![0u8; 1024];
    encrypt_to(
      dst.as_mut_slice(),
      &src,
      &key,
      &iv,
      EncryptionAlgorithm::None,
    )
    .unwrap();
    assert_eq!(dst.as_slice(), src.as_ref());

    let act = encrypt_to_vec(dst.as_slice(), &key, &iv, EncryptionAlgorithm::None).unwrap();
    assert_eq!(src.clone().to_vec(), act);
  }
}
