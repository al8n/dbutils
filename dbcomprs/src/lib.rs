#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// Default compressor
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DefaultCompressor;

impl Compressor for DefaultCompressor {
  type Error = Error;

  #[inline]
  fn compress_to(src: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Self::Error> {
    compress_to(src, dst, cmp)
  }

  #[inline]
  fn compress_into_vec(src: &[u8], cmp: Compression) -> Result<Vec<u8>, Self::Error> {
    compress_into_vec(src, cmp)
  }

  #[inline]
  fn decompress_to(src: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Self::Error> {
    decompress_to(src, dst, cmp)
  }

  #[inline]
  fn decompress_into_vec(src: &[u8], cmp: Compression) -> Result<Vec<u8>, Self::Error> {
    decompress_into_vec(src, cmp)
  }

  #[inline]
  fn max_compressed_size(src: &[u8], cmp: Compression) -> usize {
    max_compressed_size(cmp, src.len())
  }
}

/// CompressionAlgorithm specifies to use which algorithm to compress a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
#[cfg_attr(feature = "prost", derive(::prost::Enumeration))]
#[repr(u8)]
pub enum CompressionAlgorithm {
  /// None mode indicates that a block is not compressed.
  None = 0,

  /// Snappy mode indicates that a block is compressed using Snappy algorithm.
  #[cfg(feature = "snappy")]
  #[cfg_attr(docsrs, doc(cfg(feature = "snappy")))]
  Snappy = 1,
  /// ZSTD mode indicates that a block is compressed using ZSTD algorithm.
  /// ZSTD,
  #[cfg(feature = "zstd")]
  #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
  Zstd = 2,
  /// Lz4 mode indicates that a block is compressed using lz4 algorithm.
  #[cfg(any(feature = "lz4", feature = "lz4-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "lz4", feature = "lz4-std"))))]
  Lz4 = 3,
}

impl CompressionAlgorithm {
  /// String value of the enum field names used in the ProtoBuf definition.
  ///
  /// The values are not transformed in any way and thus are considered stable
  /// (if the ProtoBuf definition does not change) and safe for programmatic use.
  pub const fn as_str(&self) -> &'static str {
    match self {
      CompressionAlgorithm::None => "None",
      #[cfg(feature = "snappy")]
      CompressionAlgorithm::Snappy => "Snappy",
      #[cfg(feature = "zstd")]
      CompressionAlgorithm::Zstd => "Zstd",
      #[cfg(any(feature = "lz4", feature = "lz4-std"))]
      CompressionAlgorithm::Lz4 => "Lz4",
    }
  }
}

/// Compression specifies how a block should be compressed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Compression {
  /// compression algorithm
  pub algo: CompressionAlgorithm,
  /// only for zstd, <= 0 use default(3) compression level, 1 - 21 uses the exact level of zstd compression level, >=22 use the largest compression level supported by zstd.
  pub level: i32,
}

impl Default for Compression {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl Compression {
  /// Returns a new Compression with the None algorithm.
  #[inline]
  pub const fn new() -> Self {
    Self {
      algo: CompressionAlgorithm::None,
      level: 0,
    }
  }

  /// Set the compression level, only used for zstd compression
  #[inline]
  pub const fn set_level(mut self, level: i32) -> Self {
    self.level = level;
    self
  }

  /// Set the compression algorithm
  #[inline]
  pub const fn set_algorithm(mut self, algo: CompressionAlgorithm) -> Self {
    self.algo = algo;
    self
  }

  /// Returns a new Compression with the lz4 algorithm.
  #[cfg(any(feature = "lz4", feature = "lz4-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "lz4", feature = "lz4-std"))))]
  #[inline]
  pub const fn lz4() -> Self {
    Self {
      algo: CompressionAlgorithm::Lz4,
      level: 0,
    }
  }

  /// Returns a new Compression with the Zstd algorithm.
  #[cfg(feature = "zstd")]
  #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
  #[inline]
  pub const fn zstd(level: i32) -> Self {
    Self {
      algo: CompressionAlgorithm::Zstd,
      level,
    }
  }

  /// Returns a new Compression with the Snappy algorithm.
  #[cfg(feature = "snappy")]
  #[cfg_attr(docsrs, doc(cfg(feature = "snappy")))]
  #[inline]
  pub const fn snappy() -> Self {
    Self {
      algo: CompressionAlgorithm::Snappy,
      level: 0,
    }
  }

  /// Returns true if the compression algorithm is None.
  #[inline]
  pub const fn is_none(&self) -> bool {
    match self.algo {
      #[cfg(feature = "snappy")]
      CompressionAlgorithm::Snappy => false,
      #[cfg(feature = "zstd")]
      CompressionAlgorithm::Zstd => false,
      #[cfg(any(feature = "lz4", feature = "lz4-std"))]
      CompressionAlgorithm::Lz4 => false,
      _ => true,
    }
  }

  /// Returns true if the compression algorithm is not None.
  #[inline]
  pub const fn is_some(&self) -> bool {
    match self.algo {
      #[cfg(feature = "snappy")]
      CompressionAlgorithm::Snappy => true,
      #[cfg(feature = "zstd")]
      CompressionAlgorithm::Zstd => true,
      #[cfg(any(feature = "lz4", feature = "lz4-std"))]
      CompressionAlgorithm::Lz4 => true,
      _ => false,
    }
  }
}

#[cfg(feature = "prost")]
impl prost::Message for Compression {
  #[allow(unused_variables)]
  fn encode_raw<B>(&self, buf: &mut B)
  where
    B: ::prost::bytes::BufMut,
  {
    if self.algo != CompressionAlgorithm::default() {
      ::prost::encoding::int32::encode(1u32, &(self.algo as i32), buf);
    }
    if self.level != 0i32 {
      ::prost::encoding::int32::encode(2u32, &self.level, buf);
    }
  }

  #[allow(unused_variables)]
  fn merge_field<B>(
    &mut self,
    tag: u32,
    wire_type: ::prost::encoding::WireType,
    buf: &mut B,
    ctx: ::prost::encoding::DecodeContext,
  ) -> ::core::result::Result<(), ::prost::DecodeError>
  where
    B: ::prost::bytes::Buf,
  {
    const STRUCT_NAME: &str = "Compression";
    match tag {
      1u32 => {
        let value = &mut (self.algo as i32);
        ::prost::encoding::int32::merge(wire_type, value, buf, ctx).map_err(|mut error| {
          error.push(STRUCT_NAME, "algo");
          error
        })
      }
      2u32 => {
        let value = &mut self.level;
        ::prost::encoding::int32::merge(wire_type, value, buf, ctx).map_err(|mut error| {
          error.push(STRUCT_NAME, "level");
          error
        })
      }
      _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
    }
  }

  #[inline]
  fn encoded_len(&self) -> usize {
    (if self.algo != CompressionAlgorithm::default() {
      ::prost::encoding::int32::encoded_len(1u32, &(self.algo as i32))
    } else {
      0
    }) + (if self.level != 0i32 {
      ::prost::encoding::int32::encoded_len(2u32, &self.level)
    } else {
      0
    })
  }

  #[inline]
  fn clear(&mut self) {
    self.algo = CompressionAlgorithm::default();
    self.level = 0i32;
  }
}

/// Compression/Decompression Error
pub enum Error {
  /// Snappy error
  #[cfg(feature = "snappy")]
  #[cfg_attr(docsrs, doc(cfg(feature = "snappy")))]
  Snappy(snap::Error),
  /// Zstd error
  #[cfg(feature = "zstd")]
  #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
  Zstd(std::io::Error),
  /// Lz4 error
  #[cfg(any(feature = "lz4", feature = "lz4-std"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "lz4", feature = "lz4-std"))))]
  Lz4(Lz4Error),
  /// This error occurs when the given buffer is too small to contain the
  /// maximum possible compressed bytes or the total number of decompressed
  /// bytes.
  BufferTooSmall {
    /// The size of the given output buffer.
    given: u64,
    /// The minimum size of the output buffer.
    min: u64,
  },
}

impl core::fmt::Debug for Error {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self {
      #[cfg(feature = "snappy")]
      Error::Snappy(e) => write!(f, "{:?}", e),
      #[cfg(feature = "zstd")]
      Error::Zstd(e) => write!(f, "{:?}", e),
      #[cfg(any(feature = "lz4", feature = "lz4-std"))]
      Error::Lz4(e) => write!(f, "{:?}", e),
      Error::BufferTooSmall { given, min } => {
        write!(f, "BufferTooSmall {{given {}, min {}}}", given, min)
      }
    }
  }
}

impl core::fmt::Display for Error {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self {
      #[cfg(feature = "snappy")]
      Error::Snappy(e) => write!(f, "snappy error: {}", e),
      #[cfg(feature = "zstd")]
      Error::Zstd(e) => write!(f, "zstd error: {}", e),
      #[cfg(any(feature = "lz4", feature = "lz4-std"))]
      Error::Lz4(e) => write!(f, "{}", e),
      Error::BufferTooSmall { given, min } => {
        write!(f, "buffer too small: given {}, min {}", given, min)
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Lz4 error
#[cfg(any(feature = "lz4", feature = "lz4-std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "lz4", feature = "lz4-std"))))]
pub enum Lz4Error {
  /// Lz4 compression error
  Compression(lz4_flex::block::CompressError),
  /// Lz4 decompression error
  Decompression(lz4_flex::block::DecompressError),
}

#[cfg(any(feature = "lz4", feature = "lz4-std"))]
impl core::fmt::Debug for Lz4Error {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Lz4Error::Compression(e) => write!(f, "lz4 error: {:?}", e),
      Lz4Error::Decompression(e) => write!(f, "lz4 error: {:?}", e),
    }
  }
}

#[cfg(any(feature = "lz4", feature = "lz4-std"))]
impl core::fmt::Display for Lz4Error {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Lz4Error::Compression(e) => write!(f, "lz4 error: {}", e),
      Lz4Error::Decompression(e) => write!(f, "lz4 error: {}", e),
    }
  }
}

#[cfg(all(any(feature = "lz4", feature = "lz4-std"), feature = "std"))]
impl std::error::Error for Lz4Error {}

/// Compression/Decompression trait
pub trait Compressor {
  #[cfg(not(feature = "std"))]
  /// Compression/Decompression Error
  type Error: core::fmt::Display + core::fmt::Debug;

  #[cfg(feature = "std")]
  /// Compression/Decompression Error
  type Error: std::error::Error;

  /// Compresses the given data into the given output buffer, returning the number of bytes written.
  fn compress_to(src: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Self::Error>;

  /// Compresses the given data into a new vector.
  fn compress_into_vec(src: &[u8], cmp: Compression) -> Result<Vec<u8>, Self::Error>;

  /// Compresses the given data into a new [`bytes::Bytes`].
  #[inline]
  fn compress_into_bytes(src: &[u8], cmp: Compression) -> Result<bytes::Bytes, Self::Error> {
    Self::compress_into_vec(src, cmp).map(bytes::Bytes::from)
  }

  /// Decompresses the given data into the given output buffer, returning the number of bytes written.
  fn decompress_to(src: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Self::Error>;

  /// Decompresses the given data into a new vector.
  fn decompress_into_vec(src: &[u8], cmp: Compression) -> Result<Vec<u8>, Self::Error>;

  /// Decompresses the given data into a new [`bytes::Bytes`].
  #[inline]
  fn decompress_into_bytes(src: &[u8], cmp: Compression) -> Result<bytes::Bytes, Self::Error> {
    Self::decompress_into_vec(src, cmp).map(bytes::Bytes::from)
  }

  /// Returns the maximum size of the compressed data according to the compression algorithm and src size.
  fn max_compressed_size(src: &[u8], cmp: Compression) -> usize;
}

/// Compress data using the specified compression algorithm to the given buffer and return how many bytes were written.
#[inline]
pub fn compress_to(data: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Error> {
  match cmp.algo {
    #[cfg(feature = "snappy")]
    CompressionAlgorithm::Snappy => snap::raw::Encoder::new()
      .compress(data, dst)
      .map_err(Error::Snappy),
    #[cfg(feature = "zstd")]
    CompressionAlgorithm::Zstd => {
      let range = zstd_compression::compression_level_range();
      match cmp.level {
        lvl if range.contains(&lvl) => {
          zstd_compression::bulk::compress_to_buffer(data, dst, lvl).map_err(Error::Zstd)
        }
        lvl if lvl <= 0 => {
          zstd_compression::bulk::compress_to_buffer(data, dst, 0).map_err(Error::Zstd)
        }
        _ => zstd_compression::bulk::compress_to_buffer(data, dst, range.last().unwrap())
          .map_err(Error::Zstd),
      }
    }
    #[cfg(any(feature = "lz4", feature = "lz4-std"))]
    CompressionAlgorithm::Lz4 => lz4_flex::compress_into(data, &mut dst[4..])
      .map(|size| {
        dst[..4].copy_from_slice((size as u32).to_le_bytes().as_ref());
        size
      })
      .map_err(|e| Error::Lz4(Lz4Error::Compression(e))),
    _ => {
      if data.len() > dst.len() {
        return Err(Error::BufferTooSmall {
          given: dst.len() as u64,
          min: data.len() as u64,
        });
      }
      dst[..data.len()].copy_from_slice(data);
      Ok(data.len())
    }
  }
}

/// Compresses the given data into a new vector.
#[inline]
pub fn compress_into_vec(data: &[u8], cmp: Compression) -> Result<Vec<u8>, Error> {
  match cmp.algo {
    #[cfg(feature = "snappy")]
    CompressionAlgorithm::Snappy => snap::raw::Encoder::new()
      .compress_vec(data)
      .map_err(Error::Snappy),
    #[cfg(feature = "zstd")]
    CompressionAlgorithm::Zstd => {
      let range = zstd_compression::compression_level_range();
      match cmp.level {
        lvl if range.contains(&lvl) => zstd_compression::encode_all(data, lvl),
        lvl if lvl <= 0 => zstd_compression::encode_all(data, 0),
        _ => zstd_compression::encode_all(data, range.last().unwrap()),
      }
      .map_err(Error::Zstd)
    }
    #[cfg(any(feature = "lz4", feature = "lz4-std"))]
    CompressionAlgorithm::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
    _ => Ok(data.to_vec()),
  }
}

/// Decompresses the given data into the given buffer, returning the number of bytes written.
#[inline]
pub fn decompress_to(data: &[u8], dst: &mut [u8], cmp: Compression) -> Result<usize, Error> {
  match cmp.algo {
    #[cfg(feature = "snappy")]
    CompressionAlgorithm::Snappy => snap::raw::Decoder::new()
      .decompress(data, dst)
      .map_err(Error::Snappy),
    #[cfg(feature = "zstd")]
    CompressionAlgorithm::Zstd => {
      zstd_compression::bulk::decompress_to_buffer(data, dst).map_err(Error::Zstd)
    }
    #[cfg(any(feature = "lz4", feature = "lz4-std"))]
    CompressionAlgorithm::Lz4 => {
      lz4_flex::decompress_into(&data[4..], dst).map_err(|e| Error::Lz4(Lz4Error::Decompression(e)))
    }
    _ => {
      if data.len() > dst.len() {
        return Err(Error::BufferTooSmall {
          given: dst.len() as u64,
          min: data.len() as u64,
        });
      }
      dst[..data.len()].copy_from_slice(data);
      Ok(data.len())
    }
  }
}

/// Decompresses the data into a new vector.
#[inline]
pub fn decompress_into_vec(data: &[u8], cmp: Compression) -> Result<Vec<u8>, Error> {
  match cmp.algo {
    #[cfg(feature = "snappy")]
    CompressionAlgorithm::Snappy => snap::raw::Decoder::new()
      .decompress_vec(data)
      .map_err(Error::Snappy),
    #[cfg(feature = "zstd")]
    CompressionAlgorithm::Zstd => zstd_compression::decode_all(data).map_err(Error::Zstd),
    #[cfg(any(feature = "lz4", feature = "lz4-std"))]
    CompressionAlgorithm::Lz4 => {
      lz4_flex::decompress_size_prepended(data).map_err(|e| Error::Lz4(Lz4Error::Decompression(e)))
    }
    _ => Ok(data.to_vec()),
  }
}

/// Returns the maximum size of the compressed data according to the compression algorithm and src size.
#[inline]
pub fn max_compressed_size(cmp: Compression, sz: usize) -> usize {
  match cmp.algo {
    #[cfg(feature = "snappy")]
    CompressionAlgorithm::Snappy => snap::raw::max_compress_len(sz),
    #[cfg(feature = "zstd")]
    CompressionAlgorithm::Zstd => {
      let low_limit = 128 << 10; // 128 kb
      let margin = if sz < low_limit {
        (low_limit - sz) >> 11
      } else {
        0
      };
      sz + (sz >> 8) + margin
    }
    #[cfg(any(feature = "lz4", feature = "lz4-std"))]
    CompressionAlgorithm::Lz4 => {
      lz4_flex::block::get_maximum_output_size(sz) + core::mem::size_of::<u32>()
    }
    _ => sz,
  }
}

macro_rules! impl_compression_algo_converter {
  ($($ty:ty),+ $(,)?) => {
    $(
      impl From<$ty> for CompressionAlgorithm {
        fn from(val: $ty) -> CompressionAlgorithm {
          match val {
            #[cfg(feature = "snappy")]
            1 => CompressionAlgorithm::Snappy,
            #[cfg(feature = "zstd")]
            2 => CompressionAlgorithm::Zstd,
            #[cfg(any(feature = "lz4", feature = "lz4-std"))]
            3 => CompressionAlgorithm::Lz4,
            _ => CompressionAlgorithm::None,
          }
        }
      }
    )*
  };
}

impl_compression_algo_converter!(i8, i16, i32, i64, isize, i128, u8, u16, u32, u64, usize, u128);
