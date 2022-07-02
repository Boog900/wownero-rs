// Rust Wownero Library
// Written in 2019-2022 by
//    Monero Rust Contributors
// Adapted to Wownero in 2022 by
//    Boog900
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

//! Block and block header structures.
//!
//! This module defines structures for manipulating Wownero blocks. A block is composed of an
//! [`Header`](BlockHeader), the miner [`Transaction`], and a list of transactions'
//! [`Hash`](hash::Hash) included in the block.
//!

use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::{self, Decodable, VarInt};
use crate::cryptonote::hash;
use crate::util::ringct::Signature;
use sealed::sealed;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use std::{fmt, io};

/// Enum for pre or post Vote by block
///
/// post: major_version >= 18
/// pre: major_version < 18
///
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Vote {
    /// Pre vote by block
    PreVote,
    /// Post vote by block
    PostVote(u16),
}

impl Default for Vote {
    fn default() -> Self {
        Vote::PreVote
    }
}

impl fmt::Display for Vote {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Vote::PreVote => {
                writeln!(fmt, "Pre vote by block")?;
            }
            Vote::PostVote(vote) => {
                writeln!(fmt, "Vote: {}", vote)?;
            }
        }
        Ok(())
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Vote {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            Vote::PreVote => Ok(len),
            Vote::PostVote(vote) => {
                len += vote.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl Vote {
    fn consensus_decode<D: io::Read>(
        d: &mut D,
        major_version: &VarInt,
    ) -> Result<Vote, encode::Error> {
        if major_version >= &VarInt(18) {
            let vote: u16 = Decodable::consensus_decode(d)?;
            Ok(Vote::PostVote(vote))
        } else {
            Ok(Vote::PreVote)
        }
    }
}

/// Enum for pre or post miner sig
///
/// post: major_version >= 18
/// pre: major_version < 18
///
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum MinerSig {
    /// Pre miner sig
    PreSig,
    /// Post miner sig
    PostSig(Signature),
}

impl Default for MinerSig {
    fn default() -> Self {
        MinerSig::PreSig
    }
}

impl fmt::Display for MinerSig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            MinerSig::PreSig => {
                writeln!(fmt, "Pre MinerSig")?;
            }
            MinerSig::PostSig(sig) => {
                writeln!(fmt, "Miner signature: {}", sig)?;
            }
        }
        Ok(())
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for MinerSig {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            MinerSig::PreSig => Ok(len),
            MinerSig::PostSig(sig) => {
                len += sig.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl MinerSig {
    fn consensus_decode<D: io::Read>(
        d: &mut D,
        major_version: &VarInt,
    ) -> Result<MinerSig, encode::Error> {
        if major_version >= &VarInt(18) {
            let sig: Signature = Decodable::consensus_decode(d)?;
            Ok(MinerSig::PostSig(sig))
        } else {
            Ok(MinerSig::PreSig)
        }
    }
}

/// A block header containing the version, the mining timestamp, the previous block hash and the
/// nonce.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct BlockHeader {
    /// Major version, defines the consensus rules.
    pub major_version: VarInt,
    /// Minor version, also used to vote.
    pub minor_version: VarInt,
    /// Block mining timestamp.
    pub timestamp: VarInt,
    /// Previous block hash.
    pub prev_id: hash::Hash,
    /// The nonce used for the proof of work.
    pub nonce: u32,
    /// Miners signature to prevent pool mining
    pub signature: MinerSig,
    /// Vote
    pub vote: Vote,
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Major version: {}", self.major_version,)?;
        writeln!(fmt, "Minor version: {}", self.minor_version,)?;
        writeln!(fmt, "Timestamp: {}", self.timestamp,)?;
        writeln!(fmt, "Previous id: {}", self.prev_id,)?;
        writeln!(fmt, "Nonce: {}", self.nonce,)?;
        writeln!(fmt, "Signature: {}", self.signature,)?;
        writeln!(fmt, "Vote: {}", self.vote)
    }
}

impl Decodable for BlockHeader {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<BlockHeader, encode::Error> {
        let major_version: VarInt = Decodable::consensus_decode(d)?;
        let minor_version: VarInt = Decodable::consensus_decode(d)?;
        let timestamp: VarInt = Decodable::consensus_decode(d)?;
        let prev_id: hash::Hash = Decodable::consensus_decode(d)?;
        let nonce: u32 = Decodable::consensus_decode(d)?;
        let signature = MinerSig::consensus_decode(d, &major_version)?;
        let vote = Vote::consensus_decode(d, &major_version)?;
        Ok(BlockHeader {
            major_version,
            minor_version,
            timestamp,
            prev_id,
            nonce,
            signature,
            vote,
        })
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for BlockHeader {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.major_version.consensus_encode(s)?;
        len += self.minor_version.consensus_encode(s)?;
        len += self.timestamp.consensus_encode(s)?;
        len += self.prev_id.consensus_encode(s)?;
        len += self.nonce.consensus_encode(s)?;
        len += self.signature.consensus_encode(s)?;
        len += self.vote.consensus_encode(s)?;
        Ok(len)
    }
}

/// A full block with the mining transaction and the commitments (hash) to all included
/// transaction.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Block {
    /// The block header.
    pub header: BlockHeader,
    /// The coinbase transaction (mining transaction).
    pub miner_tx: Transaction,
    /// List of included transactions within this block, only hashes are store.
    pub tx_hashes: Vec<hash::Hash>,
}

impl fmt::Display for Block {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Block header: {}", self.header,)?;
        writeln!(fmt, "Miner tx: {}", self.miner_tx)?;
        for tx in &self.tx_hashes {
            writeln!(fmt, "tx: {}", tx,)?;
        }
        Ok(())
    }
}

impl_consensus_encoding!(Block, header, miner_tx, tx_hashes);

#[cfg(test)]
mod test {
    use super::*;
    use crate::consensus::encode::deserialize;
    use crate::consensus::encode::serialize;
    use crate::cryptonote::hash::Hashable;

    #[test]
    fn test_block_ser_pre_sig() {
        // block with only the miner tx and no other transactions
        let hex = "0808d7c6ffd605b338ed21e6c09427584853b424a87eea47163e4f7e06b16ccdf50f5155430b4477be6d0002f53601ffb93601be84d6f8cdfc03029d99799f49753366da3ad742aac5085360aee627f21a38fb6d93d29ac85d335f34015b19f62f5aa43c094623de7d824e0d9ad1812654d815ad83d1a0163211b68d6b0211000000bb9b02a6000000000100000101000000";
        // blockhashing blob for above block as accepted by Wownero
        let hex_blockhash_blob="0808d7c6ffd605b338ed21e6c09427584853b424a87eea47163e4f7e06b16ccdf50f5155430b4477be6d00c8dd108dd7da2f115d6265534f4970badd6dc74cc2eec926fa50341981ad1cac01";
        let bytes = hex::decode(hex).unwrap();
        let block = deserialize::<Block>(&bytes[..]).unwrap();
        let header = serialize::<BlockHeader>(&block.header);
        let mut count = serialize::<VarInt>(&VarInt(1 + block.tx_hashes.len() as u64));
        let mut root = block.miner_tx.hash().0.to_vec(); //tree_hash(hashes); // tree_hash.c used by Wownero, will be the miner tx hash here
        let mut encode2 = header;
        encode2.append(&mut root);
        encode2.append(&mut count);
        assert_eq!(hex::encode(encode2), hex_blockhash_blob);
        let bytes2 = serialize::<Block>(&block);
        assert_eq!(bytes, bytes2);
        let hex2 = hex::encode(bytes2);
        assert_eq!(hex, hex2);
    }

    #[test]
    fn test_block_ser_post_sig() {
        // block with only the miner tx and no other transactions
        let hex = "1313aee6e69206bd69bc9aa035073458c550577631d0880b1bc86a4d12ba54a73abc87abd2d6ff0bfa0bcfb2aee1cf7379455aae8ca93048767d5fceaa1fe07701e74e56e0d8f1ad6e9202009c33772db196bc3ff1189a3dc3454ec74dff92054720577aec59e9083afc02000002fc9f1901ffdc9d19019af3c7b197d9020206f3b155076296ce7ea499348439775a6c4fecca8bcc0a7ea8b1ff31e8028fa72b01f6affc050bc0b2539f6a78f74206d38a68e1a1afe6411e37dd2c4c2cad176c7b0208defc772e10c708ab0000";
        // blockhashing blob for above block as accepted by wownero
        let hex_blockhash_blob="1313aee6e69206bd69bc9aa035073458c550577631d0880b1bc86a4d12ba54a73abc87abd2d6ff0bfa0bcfb2aee1cf7379455aae8ca93048767d5fceaa1fe07701e74e56e0d8f1ad6e9202009c33772db196bc3ff1189a3dc3454ec74dff92054720577aec59e9083afc020000c1354695b547ef9a134eb93eba9e33681e92ff90c97c8f06f1ed9b1d08e2e78501";
        let bytes = hex::decode(hex).unwrap();
        let block = deserialize::<Block>(&bytes[..]).unwrap();
        let header = serialize::<BlockHeader>(&block.header);
        let mut count = serialize::<VarInt>(&VarInt(1 + block.tx_hashes.len() as u64));
        let mut root = block.miner_tx.hash().0.to_vec(); //tree_hash(hashes); // tree_hash.c used by Wownero, will be the miner tx hash here
        let mut encode2 = header;
        encode2.append(&mut root);
        encode2.append(&mut count);
        assert_eq!(hex::encode(encode2), hex_blockhash_blob);
        let bytes2 = serialize::<Block>(&block);
        assert_eq!(bytes, bytes2);
        let hex2 = hex::encode(bytes2);
        assert_eq!(hex, hex2);
    }
    #[test]
    fn test_block_ser() {
        // block with the miner tx and one other transaction
        let hex = "1313e8e8e69206fadcd0e9131d5eb096d630e7316e6f0bfe62c1faf7dea5a52dfe51f423efe065c2810bcf17f729c5f733e540ee25f57c42f948a7dac4e96d84d60c38525d3397b6984101137be1cedda414681fa250739c603772121cbe065b90ee780abca9163f3b7309000002fe9f1901ffde9d1901a6fae18898d90202d4caf7bc40cf60734fc088b1cdfbef7723333ba8d194b881f4a86f78a437fe452b019d60dd68184e4e9e9b0684825393951c617968fe84e91ecd07a057aee9e60da8020873fcc8522e0780400001c50ecadac939ae36053dd9257275506e29eadf58758972f8c583a4362f1584e6";
        // blockhashing blob for above block as accepted by wownero
        let hex_blockhash_blob="1313e8e8e69206fadcd0e9131d5eb096d630e7316e6f0bfe62c1faf7dea5a52dfe51f423efe065c2810bcf17f729c5f733e540ee25f57c42f948a7dac4e96d84d60c38525d3397b6984101137be1cedda414681fa250739c603772121cbe065b90ee780abca9163f3b73090000d7dc7273061b14bc0580b85ef653d61ee3e00fcf5e6a60fa8fd78707bb8eaf7402";
        let bytes = hex::decode(hex).unwrap();
        let block = deserialize::<Block>(&bytes[..]).unwrap();
        let header = serialize::<BlockHeader>(&block.header);
        let mut count = serialize::<VarInt>(&VarInt(1 + block.tx_hashes.len() as u64));
        let mut root = block.miner_tx.hash().0.to_vec(); //tree_hash(hashes); // tree_hash.c used by Wownero, will be the miner tx hash here
        let mut encode2 = header;
        encode2.append(&mut root);
        encode2.append(&mut count);
        assert_eq!(hex::encode(encode2), hex_blockhash_blob);
        let bytes2 = serialize::<Block>(&block);
        assert_eq!(bytes, bytes2);
        let hex2 = hex::encode(bytes2);
        assert_eq!(hex, hex2);
        assert_eq!(
            "c50ecadac939ae36053dd9257275506e29eadf58758972f8c583a4362f1584e6",
            hex::encode(block.tx_hashes[0])
        );
    }
}
