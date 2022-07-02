// Rust Monero Library
// Written in 2019-2022 by
//   Monero Rust Contributors
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

//! Transaction, transaction's prefix, inputs and outputs structures used to parse and create
//! transactions.
//!
//! This module support (de)serializing Monero transaction and input/amount discovery/recovery with
//! private view key and public spend key (view key-pair: [`ViewPair`]).
//!

use crate::consensus::encode::{self, serialize, Decodable, VarInt};
use crate::cryptonote::hash;
use crate::cryptonote::onetime_key::{KeyRecoverer, SubKeyChecker};
use crate::cryptonote::subaddress::Index;
use crate::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use crate::util::ringct::{Opening, RctSig, RctSigBase, RctSigPrunable, RctType, Signature};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex::encode as hex_encode;
use sealed::sealed;
use thiserror::Error;

use std::ops::Range;
use std::{fmt, io};

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// Errors possible when manipulating transactions.
#[derive(Error, Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// No transaction public key found in extra.
    #[error("No transaction public key found")]
    NoTxPublicKey,
    /// Scripts input/output are not supported.
    #[error("Script not supported")]
    ScriptNotSupported,
    /// Missing ECDH info for the output.
    #[error("Missing ECDH info for the output")]
    MissingEcdhInfo,
    /// Invalid commitment.
    #[error("Invalid commitment")]
    InvalidCommitment,
    /// Missing commitment.
    #[error("Missing commitment")]
    MissingCommitment,
}

/// The key image used in transaction inputs [`TxIn`] to commit to the use of an output one-time
/// public key as in [`TxOutTarget::ToKey`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct KeyImage {
    /// The actual key image data.
    pub image: hash::Hash,
}

impl_consensus_encoding!(KeyImage, image);

/// A transaction input, either a coinbase spend or a one-time key spend which defines the ring
/// size and the key image to avoid double spend.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum TxIn {
    /// A coinbase input.
    Gen {
        /// Block height of where the coinbase transaction is included.
        height: VarInt,
    },
    /// A key input from a key output.
    ToKey {
        /// Amount spend from the output, 0 in case of CT.
        amount: VarInt,
        /// Relative offsets of keys use in the ring.
        key_offsets: Vec<VarInt>,
        /// The corresponding key image of the output.
        k_image: KeyImage,
    },
}

/// Type of output formats, only [`TxOutTarget::ToKey`] is used, other formats are legacy to the
/// original cryptonote implementation.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum TxOutTarget {
    /// A script output, not used.
    ToScript {
        /// A list of keys.
        keys: Vec<PublicKey>,
        /// The script.
        script: Vec<u8>,
    },
    /// A one-time public key output.
    ToKey {
        /// The one-time public key of that output.
        key: PublicKey,
    },
    /// A script hash output, not used.
    ToScriptHash {
        /// The script hash
        hash: hash::Hash,
    },
}

impl TxOutTarget {
    /// Retrieve the public keys, if any.
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        match self {
            TxOutTarget::ToScript { keys, .. } => Some(keys.clone()),
            TxOutTarget::ToKey { key } => Some(vec![*key]),
            TxOutTarget::ToScriptHash { .. } => None,
        }
    }

    /// Returns the one-time public key if this is a [`TxOutTarget::ToKey`] and `None` otherwise.
    pub fn as_one_time_key(&self) -> Option<&PublicKey> {
        match self {
            TxOutTarget::ToKey { key } => Some(key),
            _ => None,
        }
    }
}

/// A transaction output, can be consumed by a [`TxIn`] input of the matching format.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TxOut {
    /// The amount sent to the associated key, can be 0 in case of Confidential Transaction (CT).
    pub amount: VarInt,
    /// The output target format.
    pub target: TxOutTarget,
}

impl_consensus_encoding!(TxOut, amount, target);

impl TxOut {
    /// Retreive the public keys, if any
    pub fn get_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.target.get_pubkeys()
    }
}

/// Transaction ouput that can be redeemed by a private key pair at a given index and are returned
/// by the [`check_outputs`] method.
///
/// [`check_outputs`]: TransactionPrefix::check_outputs
///
/// ```rust
/// use wownero::blockdata::transaction::Transaction;
/// use wownero::consensus::encode::deserialize;
/// use wownero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
/// # use std::str::FromStr;
///
/// # let raw_tx = hex::decode("020001020016f59307c0fc76e1bc0488169e8101903cba8d01e513a70cbb039001db088f01e302e0020e30050c0b8d0427d790ca60636139f487c8af3b4556f97e221522514a7882e635d959044bbd680b0200027f54099f27e5d3e85ee9b49bf34054866cf8586fd02aba11ae1ac23bbbae5942000259d6d150201a6703930ae5c12516bedf99b3b58f7c12f53d379549285a880fd62c01c5b77961dde6b0fca945540cc536330d338f13788be9daa2daf870d6973c13a70209015f4b5718291d14fa08e8bcd53fe739299938da24ea360333d4428b590a2807cb3fe4e98f9363919fe36498b3d02c2b071501b2e906e7cc990eba910c3e1b0cf827ddb37f15020c433d97ec18d1f81110f2fffba58d6fa1889d47f0639901fa0429a9ab5fb8389a1478f29bf05d534f8aeaa964d7dcf9df2335edb793ccee6e15aa30fa948a4df98d7b869db0c04feeb4d49f221fab7887fd1b4565acee5fb36644e41bfe8d642575caa54deb4e0e18d48efdab57aa428d3f0dc5b6648c1fecfe0af68fd1035a2ea56c8f60652b6b4284f6792504dfb3a55623bb03f8d80451c51e691c2f355dae9470307663c742f841e08decfcb5c49a5b497d2e310505a2b7de1d27ac465bcae84e04c78494394863d233147856e4d2a266a821639d0707e0f8540ee5f7f0501ab9b8162c87e987942fbd36a2d91e501f95471bd7baa6c59b7601cfa8e8bd58038e4428725a426afe54287f970883b3588c0e2eced5460850fb05a925b73aa55ea5003ce3c25af0338f1df6627f40d9be9ebe130609c7ab285a24b852eaa84908d4833c988dfd233c181a79bcaa243318831f8dd4ef2d4ac903da5ef705c386d92c08e6a7d57b7becf210d6fc6a520dbb1d410324675edba55c29871ba1e625ac5ff102a686fc7a3b1b9d29b94b40107d84450dc1f84dbe7de7a126db6de3a447b17924cf4a88bc5e719883d9817c1191c478094ef9f97707c44a38c4a24c8c29d8e09794b285c660956a12ddf47a77562571a6104d7157138a353107c1f07d2f536e1baf5a266e4669c0c08452934068a62c65d50f6722a4fb571cc2af0f428b8c39797db23b03701285fba8a676db9f2d86fd6c8a2576304b1b7a4bdeafac33c048f9eb15accf2cf8f57b9db67805bb10757767739e6ff3c5f6c52c6d562989d463c8217e25e1bc383ddc471395a9656fd7acb9d0070ea80967d3982a86a6654af058c70b26cbcba298f8eae3601976b88845ae5e2a4efcebfb7cb4a01c03874e57ce147239a4fb70bedcba5dfe8a8828434a572aed4712ebf85612930ed82805939607536fea8324840dd280c72e5ac39df76f88ae600421eb661e14a38b5c59a86a0ed1e60703be695fb00b0df2f34b95b5e91b6a8301d0e45e1040475987bf3b18bab8a5654a7219a8744d46a4d9b3254fbd376364083c3d44c468e6aa5632641c001d34d8aa29c32f93c2c22cda2373363819e1d4001491505c192c605e41a39af664d5190165bcf2d0d525ca54feb6ffc75b5c02049e6803c263272d33160501578eae5495c1fa144da2ce833e628d914531ee30044d24079244ca21f4cbe9b03179830a8582a6c943838a7fc0dbc7b78ac1eb2106078b9013f8dc7df4e2e58e59fc3f8373e8c582e026f62b267dce1c91e8cb3a0adf5f106f0af67b91c6ce6b55bca04fb75ad325d4cdff2643dcea9e37ecab41051d5382d08064fc54a70e7167c6dbcce6a9fbb0cc6b192086b19f264ffe64a8047fb568395d53088e7b9eb3fd0a729057a07aca72d1f5b33599fcfebc0eefca03f1cba0032d7bd93a74a0edc47a7ae0377fb2d473b894249142987ef3824f0c06eaf63102940f98cf1c1cf10b56a5ff63db90b1dade0cde2cea8f971e97cc06034a3654714c87f1c027cf9de4efdc816bf6819b4eeb6534185e505bdb428fa9051b93a5f760a65b3b454e77205d8d69d4eaa1fda7b72be26ac9e77c4354c34b01201f47a408a37a12a7aa83b4b7d369afc0d7647f80761dee5b53c308b748a8028a9c9cf908d71eac6eaeed172d966512480314e2a4b7fb0ac186b01d9b55e00bbe68cd6b1ad411dbea7856084eb4b6d1ea4d701643b2aebb12bda04a322bba0e08e6ae693fbb9fbad0c291f2616b88d13de751fc415b0e0147fbeef3f5fcd9098a54e6037a7b26c2c63b114617dce2cf1ac6763cd0a99e7e4d3729bee117d00831763d2b60b7571072b782f61a28af112564398fe2e3cfa05b80c95fbfb06903e77c320bd6bf6fb6113b64053c52a2dd70cf51b54c7bd5fda60bffc35a10a50ade75df35f7d83b1f7e77ff68c8cb2bb6abc9271c386445d77a4736475eb57b02c7a770cd299c6895041c21ca27e61d50376037cbc9749ec25c5034d4920c6a6f8ad867c03a4172e9d1b007de8e0818662ef14a62c8484392416e9aa3493211fe").unwrap();
/// # let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");
/// # let secret_view_bytes =
/// #     hex::decode("66f87043a02f41ad494d1a2311ffd1d5dda1d8d786d1b72257ad99925013f906").unwrap();
/// # let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();
/// # let public_view = PublicKey::from_private_key(&secret_view);
/// #
/// # let secret_spend_bytes =
/// #     hex::decode("996420ae86c8101d86b56120092a7c5646f42a2967bcbc3bb2d54f81e84ae201").unwrap();
/// # let secret_spend = PrivateKey::from_slice(&secret_spend_bytes).unwrap();
/// # let public_spend = PublicKey::from_private_key(&secret_spend);
/// #
/// // Keypair used to recover the ephemeral spend key of an output
/// let keypair = KeyPair {
///     view: secret_view,
///     spend: secret_spend,
/// };
///
/// # let spend = public_spend;
/// #
/// // Viewpair used to scan a transaction to retreive owned outputs
/// let view_pair = ViewPair { view: secret_view, spend };
///
/// // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
/// let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();
///
/// for out in owned_outputs {
///     // Recover the ephemeral private spend key
///     let private_key = out.recover_key(&keypair);
/// }
/// ```
///
#[derive(Debug)]
pub struct OwnedTxOut<'a> {
    index: usize,
    out: &'a TxOut,
    sub_index: Index,
    tx_pubkey: PublicKey,
    opening: Option<Opening>,
}

impl<'a> OwnedTxOut<'a> {
    /// Returns the index of this output in the transaction
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns a reference to the actual redeemable output.
    pub fn out(&self) -> &'a TxOut {
        self.out
    }

    /// Returns the index of the key pair to use, can be `0/0` for main address.
    pub fn sub_index(&self) -> Index {
        self.sub_index
    }

    /// Returns the associated transaction public key.
    pub fn tx_pubkey(&self) -> PublicKey {
        self.tx_pubkey
    }

    /// Returns the unblinded or clear amount of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn amount(&self) -> Option<u64> {
        match self.opening {
            Some(Opening { amount, .. }) => Some(amount),
            None => match self.out.amount {
                VarInt(0) => None,
                VarInt(a) => Some(a),
            },
        }
    }

    /// Returns the original blinding factor of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn blinding_factor(&self) -> Option<Scalar> {
        self.opening.as_ref().map(|o| o.blinding_factor)
    }

    /// Returns the original commitment of this output.
    ///
    /// None if we didn't have enough information to unblind the output.
    pub fn commitment(&self) -> Option<EdwardsPoint> {
        self.opening.as_ref().map(|o| o.commitment)
    }

    /// Retreive the public keys, if any.
    pub fn pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.out.get_pubkeys()
    }

    /// Recover the ephemeral private key for spending the output, this requires access to the
    /// private spend key.
    pub fn recover_key(&self, keys: &KeyPair) -> PrivateKey {
        let recoverer = KeyRecoverer::new(keys, self.tx_pubkey);
        recoverer.recover(self.index, self.sub_index)
    }
}

/// Every transaction contains an extra field, which is a part of transaction prefix and allow
/// storing extra data inside the transaction. The most common use case is for the transaction
/// public key.
///
/// Extra field is composed of typed sub fields of variable or fixed length.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct ExtraField(pub Vec<SubField>);

impl fmt::Display for ExtraField {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for field in &self.0 {
            writeln!(fmt, "Subfield: {}", field)?;
        }
        Ok(())
    }
}

impl ExtraField {
    /// Return the transaction public key, if any, present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.0.iter().find_map(|x| match x {
            SubField::TxPublicKey(pubkey) => Some(*pubkey),
            _ => None,
        })
    }

    /// Return the additional public keys, if any, present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.0.iter().find_map(|x| match x {
            SubField::AdditionalPublickKey(pubkeys) => Some(pubkeys.clone()),
            _ => None,
        })
    }
}

/// Each sub-field contains a sub-field tag followed by sub-field content of fixed or variable
/// length, in variable length case the length is encoded with a [`VarInt`] before the content
/// itself.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum SubField {
    /// Transaction public key, fixed length of 32 bytes.
    TxPublicKey(PublicKey),
    /// 255 bytes limited nonce, can contain an encrypted or unencrypted payment id, variable
    /// length.
    Nonce(Vec<u8>),
    /// Padding size is limited to 255 null bytes, variable length.
    Padding(u8),
    /// Merge mining infos: `depth` and `merkle_root`, fixed length of one VarInt and 32 bytes
    /// hash.
    MergeMining(VarInt, hash::Hash),
    /// Additional public keys for [`Subaddresses`](crate::cryptonote::subaddress) outputs,
    /// variable length of `n` additional public keys.
    AdditionalPublickKey(Vec<PublicKey>),
    /// Mysterious `MinerGate`, variable length.
    MysteriousMinerGate(String),
}

impl fmt::Display for SubField {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            SubField::TxPublicKey(public_key) => writeln!(fmt, "Tx public Key: {}", public_key),
            SubField::Nonce(nonce) => {
                let nonce_str = hex_encode(serialize(nonce));
                writeln!(fmt, "Nonce: {}", nonce_str)
            }
            SubField::Padding(padding) => writeln!(fmt, "Padding: {}", padding),
            SubField::MergeMining(code, hash) => writeln!(fmt, "Merge mining: {}, {}", code, hash),
            SubField::AdditionalPublickKey(keys) => {
                writeln!(fmt, "Additional publick keys: ")?;
                for key in keys {
                    writeln!(fmt, "key: {}", key)?;
                }
                Ok(())
            }
            SubField::MysteriousMinerGate(miner_gate) => {
                writeln!(fmt, "Mysterious miner gate: {}", miner_gate)
            }
        }
    }
}

/// The part of the transaction that contains all the data except signatures.
///
/// As transaction prefix implements [`hash::Hashable`] it is possible to generate the transaction
/// prefix hash with `tx_prefix.hash()`.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct TransactionPrefix {
    /// Transaction format version.
    pub version: VarInt,
    /// The transaction can not be spend until after a certain number of blocks, or until a certain
    /// time.
    pub unlock_time: VarInt,
    /// Array of inputs.
    pub inputs: Vec<TxIn>,
    /// Array of outputs.
    pub outputs: Vec<TxOut>,
    /// Additional data associated with a transaction.
    pub extra: ExtraField,
}

impl fmt::Display for TransactionPrefix {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Version: {}", self.version)?;
        writeln!(fmt, "Unlock time: {}", self.unlock_time)?;
        writeln!(fmt, "Extra field: {}", self.extra)
    }
}

impl_consensus_encoding!(
    TransactionPrefix,
    version,
    unlock_time,
    inputs,
    outputs,
    extra
);

impl TransactionPrefix {
    /// Return the number of transaction's inputs.
    pub fn nb_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Return the number of transaction's outputs.
    pub fn nb_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// Return the transaction public key present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.extra.tx_pubkey()
    }

    /// Return the additional public keys present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.extra.tx_additional_pubkeys()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
        rct_sig_base: Option<&RctSigBase>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        let checker = SubKeyChecker::new(pair, major, minor);
        self.check_outputs_with(&checker, rct_sig_base)
    }

    /// Iterate over transaction outputs using the provided [`SubKeyChecker`] to find outputs
    /// related to the `SubKeyChecker`'s view pair.
    pub fn check_outputs_with(
        &self,
        checker: &SubKeyChecker,
        rct_sig_base: Option<&RctSigBase>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        let tx_pubkeys = match self.tx_additional_pubkeys() {
            Some(additional_keys) => additional_keys,
            None => {
                let tx_pubkey = self.tx_pubkey().ok_or(Error::NoTxPublicKey)?;

                // if we don't have additional_pubkeys, we check every output against the single `tx_pubkey`
                vec![tx_pubkey; self.outputs.len()]
            }
        };

        let owned_txouts = self
            .outputs
            .iter()
            .enumerate()
            .zip(tx_pubkeys.iter())
            .filter_map(|((i, out), tx_pubkey)| {
                let key = out.target.as_one_time_key()?;
                let sub_index = checker.check(i, key, tx_pubkey)?;

                Some((i, out, sub_index, tx_pubkey))
            })
            .map(|(i, out, sub_index, tx_pubkey)| {
                let opening = match rct_sig_base {
                    Some(RctSigBase {
                        rct_type: RctType::Null,
                        ..
                    }) => None,
                    Some(rct_sig_base) => {
                        let ecdh_info = rct_sig_base
                            .ecdh_info
                            .get(i)
                            .ok_or(Error::MissingEcdhInfo)?;
                        let out_pk = rct_sig_base.out_pk.get(i).ok_or(Error::MissingCommitment)?;
                        let mut actual_commitment = CompressedEdwardsY(out_pk.mask.key)
                            .decompress()
                            .ok_or(Error::InvalidCommitment)?;
                        // https://git.wownero.com/wownero/wownero/commit/34884a4b00cc3f06bb1f3b8be4cf64cfea9a1b81
                        if rct_sig_base.rct_type == RctType::BulletproofPlus {
                            // Multiplies the commitment by 8
                            actual_commitment = actual_commitment.mul_by_cofactor();
                        }
                        let opening = ecdh_info
                            .open_commitment(checker.keys, tx_pubkey, i, &actual_commitment)
                            .ok_or(Error::InvalidCommitment)?;

                        Some(opening)
                    }
                    None => None,
                };

                Ok(OwnedTxOut {
                    index: i,
                    out,
                    sub_index: *sub_index,
                    tx_pubkey: *tx_pubkey,
                    opening,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(owned_txouts)
    }
}

// To get transaction prefix hash
impl hash::Hashable for TransactionPrefix {
    fn hash(&self) -> hash::Hash {
        hash::Hash::new(&serialize(self))
    }
}

/// A full transaction containing the prefix and all the signing data.
///
/// As transaction implements [`hash::Hashable`] it is possible to generate the transaction hash
/// with `tx.hash()`.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Transaction {
    /// The transaction prefix.
    pub prefix: TransactionPrefix,
    /// The signatures.
    pub signatures: Vec<Vec<Signature>>,
    /// The RingCT signatures.
    pub rct_signatures: RctSig,
}

impl fmt::Display for Transaction {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "Prefix: {}", self.prefix)?;
        for sigs in &self.signatures {
            for sig in sigs {
                writeln!(fmt, "Signature: {}", sig)?;
            }
        }
        writeln!(fmt, "RCT signature: {}", self.rct_signatures)
    }
}

impl Transaction {
    /// Return the transaction prefix.
    pub fn prefix(&self) -> &TransactionPrefix {
        &self.prefix
    }

    /// Return the number of transaction's inputs.
    pub fn nb_inputs(&self) -> usize {
        self.prefix().inputs.len()
    }

    /// Return the number of transaction's outputs.
    pub fn nb_outputs(&self) -> usize {
        self.prefix().outputs.len()
    }

    /// Return the transaction public key present in extra field.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.prefix().extra.tx_pubkey()
    }

    /// Return the additional public keys present in extra field.
    pub fn tx_additional_pubkeys(&self) -> Option<Vec<PublicKey>> {
        self.prefix().extra.tx_additional_pubkeys()
    }

    /// Iterate over transaction outputs and find outputs related to view pair.
    pub fn check_outputs(
        &self,
        pair: &ViewPair,
        major: Range<u32>,
        minor: Range<u32>,
    ) -> Result<Vec<OwnedTxOut>, Error> {
        self.prefix()
            .check_outputs(pair, major, minor, self.rct_signatures.sig.as_ref())
    }

    /// Iterate over transaction outputs using the provided [`SubKeyChecker`] to find outputs
    /// related to the `SubKeyChecker`'s view pair.
    pub fn check_outputs_with(&self, checker: &SubKeyChecker) -> Result<Vec<OwnedTxOut>, Error> {
        self.prefix()
            .check_outputs_with(checker, self.rct_signatures.sig.as_ref())
    }

    #[cfg(feature = "experimental")]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    /// Compute the message to be signed by the CLSAG signature algorithm.
    ///
    /// The message consists of three parts:
    ///
    /// 1. The hash of the transaction prefix.
    /// 2. The hash of a consensus-encoded [`RctSigBase`].
    /// 3. The hash of all bulletproofs.
    pub fn signature_hash(&self) -> Result<hash::Hash, SignatureHashError> {
        let rct_type = self
            .rct_signatures
            .sig
            .as_ref()
            .ok_or(SignatureHashError::MissingRctSigBase)?
            .rct_type;

        if rct_type != RctType::Clsag {
            return Err(SignatureHashError::UnsupportedRctType(rct_type));
        }

        use tiny_keccak::Hasher as _;

        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&self.transaction_prefix_hash());
        keccak.update(&self.rct_sig_base_hash()?);
        keccak.update(&self.bulletproof_hash()?);

        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        Ok(hash::Hash(hash))
    }

    #[cfg(feature = "experimental")]
    fn transaction_prefix_hash(&self) -> [u8; 32] {
        use crate::cryptonote::hash::Hashable as _;

        self.prefix.hash().to_bytes()
    }

    #[cfg(feature = "experimental")]
    fn rct_sig_base_hash(&self) -> Result<[u8; 32], SignatureHashError> {
        use crate::cryptonote::hash::keccak_256;

        let rct_sig_base = self
            .rct_signatures
            .sig
            .as_ref()
            .ok_or(SignatureHashError::MissingRctSigBase)?;
        let bytes = crate::consensus::serialize(rct_sig_base);

        Ok(keccak_256(&bytes))
    }

    #[cfg(feature = "experimental")]
    fn bulletproof_hash(&self) -> Result<[u8; 32], SignatureHashError> {
        use tiny_keccak::Hasher as _;

        let bulletproofs = self
            .rct_signatures
            .p
            .as_ref()
            .ok_or(SignatureHashError::NoBulletproofs)?
            .bulletproofs
            .as_slice();
        if bulletproofs.is_empty() {
            return Err(SignatureHashError::NoBulletproofs);
        }

        let mut keccak = tiny_keccak::Keccak::v256();

        for bp in bulletproofs {
            keccak.update(&bp.A.key);
            keccak.update(&bp.S.key);
            keccak.update(&bp.T1.key);
            keccak.update(&bp.T2.key);
            keccak.update(&bp.taux.key);
            keccak.update(&bp.mu.key);

            for i in &bp.L {
                keccak.update(&i.key);
            }

            for i in &bp.R {
                keccak.update(&i.key);
            }

            keccak.update(&bp.a.key);
            keccak.update(&bp.b.key);
            keccak.update(&bp.t.key);
        }

        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        Ok(hash)
    }
}

/// Possible errors when calculating the signature hash of a transaction.
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
#[derive(Debug, Error)]
pub enum SignatureHashError {
    /// [`RctSigBase`] was not set in [`Transaction`]
    #[error("`RctSigBase` is required for computing the signature hash")]
    MissingRctSigBase,
    /// Either all of [`RctSigPrunable`] was not set within [`Transaction`] or the list of bulletproofs was empty.
    #[error("Bulletproofs are required for computing the signature hash")]
    NoBulletproofs,
    /// The transaction's [`RctType`] is not supported.
    #[error("Computing the signature hash for RctType {0} is not supported")]
    UnsupportedRctType(RctType),
}

impl hash::Hashable for Transaction {
    fn hash(&self) -> hash::Hash {
        match *self.prefix.version {
            1 => hash::Hash::new(&serialize(self)),
            _ => {
                let mut hashes: Vec<hash::Hash> = vec![self.prefix.hash()];
                if let Some(sig_base) = &self.rct_signatures.sig {
                    hashes.push(sig_base.hash());
                    if sig_base.rct_type == RctType::Null {
                        hashes.push(hash::Hash::null());
                    } else {
                        match &self.rct_signatures.p {
                            Some(p) => {
                                let mut encoder = io::Cursor::new(vec![]);
                                p.consensus_encode(&mut encoder, sig_base.rct_type).unwrap();
                                hashes.push(hash::Hash::new(&encoder.into_inner()));
                            }
                            None => {
                                let empty_hash = hash::Hash::from_slice(&[
                                    0x70, 0xa4, 0x85, 0x5d, 0x04, 0xd8, 0xfa, 0x7b, 0x3b, 0x27,
                                    0x82, 0xca, 0x53, 0xb6, 0x00, 0xe5, 0xc0, 0x03, 0xc7, 0xdc,
                                    0xb2, 0x7d, 0x7e, 0x92, 0x3c, 0x23, 0xf7, 0x86, 0x01, 0x46,
                                    0xd2, 0xc5,
                                ]);
                                hashes.push(empty_hash);
                            }
                        }
                    }
                }
                let bytes: Vec<u8> = hashes
                    .into_iter()
                    .flat_map(|h| Vec::from(&h.to_bytes()[..]))
                    .collect();
                hash::Hash::new(&bytes)
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------

impl Decodable for ExtraField {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<ExtraField, encode::Error> {
        let mut fields: Vec<SubField> = vec![];
        let bytes: Vec<u8> = Decodable::consensus_decode(d)?;
        let mut decoder = io::Cursor::new(&bytes[..]);
        // Decode each extra field
        while decoder.position() < bytes.len() as u64 {
            fields.push(Decodable::consensus_decode(&mut decoder)?);
        }
        // Fail if data are not consumed entirely.
        if decoder.position() as usize == bytes.len() {
            Ok(ExtraField(fields))
        } else {
            Err(encode::Error::ParseFailed(
                "data not consumed entirely when explicitly deserializing",
            ))
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for ExtraField {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut buffer = Vec::new();
        for field in self.0.iter() {
            field.consensus_encode(&mut buffer)?;
        }
        buffer.consensus_encode(s)
    }
}

impl Decodable for SubField {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<SubField, encode::Error> {
        let tag: u8 = Decodable::consensus_decode(d)?;

        match tag {
            0x0 => {
                let mut i = 0;
                loop {
                    // Consume all bytes until the end of cursor
                    // A new cursor must be created when parsing extra bytes otherwise
                    // transaction bytes will be consumed
                    //
                    // This works because extra padding must be the last one
                    let byte: Result<u8, encode::Error> = Decodable::consensus_decode(d);
                    match byte {
                        Ok(_) => {
                            i += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(SubField::Padding(i))
            }
            0x1 => Ok(SubField::TxPublicKey(Decodable::consensus_decode(d)?)),
            0x2 => Ok(SubField::Nonce(Decodable::consensus_decode(d)?)),
            0x3 => Ok(SubField::MergeMining(
                Decodable::consensus_decode(d)?,
                Decodable::consensus_decode(d)?,
            )),
            0x4 => Ok(SubField::AdditionalPublickKey(Decodable::consensus_decode(
                d,
            )?)),
            0xde => Ok(SubField::MysteriousMinerGate(Decodable::consensus_decode(
                d,
            )?)),
            _ => Err(encode::Error::ParseFailed("Invalid sub-field type")),
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for SubField {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = 0;
        match *self {
            SubField::Padding(nbytes) => {
                len += 0x0u8.consensus_encode(s)?;
                for _ in 0..nbytes {
                    len += 0u8.consensus_encode(s)?;
                }
                Ok(len)
            }
            SubField::TxPublicKey(ref pubkey) => {
                len += 0x1u8.consensus_encode(s)?;
                Ok(len + pubkey.consensus_encode(s)?)
            }
            SubField::Nonce(ref nonce) => {
                len += 0x2u8.consensus_encode(s)?;
                Ok(len + nonce.consensus_encode(s)?)
            }
            SubField::MergeMining(ref depth, ref merkle_root) => {
                len += 0x3u8.consensus_encode(s)?;
                len += depth.consensus_encode(s)?;
                Ok(len + merkle_root.consensus_encode(s)?)
            }
            SubField::AdditionalPublickKey(ref pubkeys) => {
                len += 0x4u8.consensus_encode(s)?;
                Ok(len + pubkeys.consensus_encode(s)?)
            }
            SubField::MysteriousMinerGate(ref string) => {
                len += 0xdeu8.consensus_encode(s)?;
                Ok(len + string.consensus_encode(s)?)
            }
        }
    }
}

impl Decodable for TxIn {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<TxIn, encode::Error> {
        let intype: u8 = Decodable::consensus_decode(d)?;
        match intype {
            0xff => Ok(TxIn::Gen {
                height: Decodable::consensus_decode(d)?,
            }),
            0x0 | 0x1 => Err(Error::ScriptNotSupported.into()),
            0x2 => Ok(TxIn::ToKey {
                amount: Decodable::consensus_decode(d)?,
                key_offsets: Decodable::consensus_decode(d)?,
                k_image: Decodable::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("Invalid input type")),
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TxIn {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            TxIn::Gen { height } => {
                let len = 0xffu8.consensus_encode(s)?;
                Ok(len + height.consensus_encode(s)?)
            }
            TxIn::ToKey {
                amount,
                key_offsets,
                k_image,
            } => {
                let mut len = 0x2u8.consensus_encode(s)?;
                len += amount.consensus_encode(s)?;
                len += key_offsets.consensus_encode(s)?;
                Ok(len + k_image.consensus_encode(s)?)
            }
        }
    }
}

impl Decodable for TxOutTarget {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<TxOutTarget, encode::Error> {
        let outtype: u8 = Decodable::consensus_decode(d)?;
        match outtype {
            0x2 => Ok(TxOutTarget::ToKey {
                key: Decodable::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("Invalid output type")),
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for TxOutTarget {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        match self {
            TxOutTarget::ToKey { key } => {
                let len = 0x2u8.consensus_encode(s)?;
                Ok(len + key.consensus_encode(s)?)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                Error::ScriptNotSupported,
            )),
        }
    }
}

#[allow(non_snake_case)]
impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Transaction, encode::Error> {
        let prefix: TransactionPrefix = Decodable::consensus_decode(d)?;

        let inputs = prefix.inputs.len();
        let outputs = prefix.outputs.len();

        match *prefix.version {
            1 => {
                let signatures: Result<Vec<Vec<Signature>>, encode::Error> = prefix
                    .inputs
                    .iter()
                    .filter_map(|input| match input {
                        TxIn::ToKey { key_offsets, .. } => {
                            let sigs: Result<Vec<Signature>, encode::Error> = key_offsets
                                .iter()
                                .map(|_| Decodable::consensus_decode(d))
                                .collect();
                            Some(sigs)
                        }
                        _ => None,
                    })
                    .collect();
                Ok(Transaction {
                    prefix,
                    signatures: signatures?,
                    rct_signatures: RctSig { sig: None, p: None },
                })
            }
            _ => {
                let signatures = vec![];
                let mut rct_signatures = RctSig { sig: None, p: None };
                if inputs == 0 {
                    return Ok(Transaction {
                        prefix,
                        signatures,
                        rct_signatures: RctSig { sig: None, p: None },
                    });
                }

                if let Some(sig) = RctSigBase::consensus_decode(d, inputs, outputs)? {
                    let p = {
                        if sig.rct_type != RctType::Null {
                            let mixin_size = if inputs > 0 {
                                match &prefix.inputs[0] {
                                    TxIn::ToKey { key_offsets, .. } => key_offsets.len() - 1,
                                    _ => 0,
                                }
                            } else {
                                0
                            };
                            RctSigPrunable::consensus_decode(
                                d,
                                sig.rct_type,
                                inputs,
                                outputs,
                                mixin_size,
                            )?
                        } else {
                            None
                        }
                    };
                    rct_signatures = RctSig { sig: Some(sig), p };
                }

                Ok(Transaction {
                    prefix,
                    signatures,
                    rct_signatures,
                })
            }
        }
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Transaction {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(s)?;
        match *self.prefix.version {
            1 => {
                for sig in self.signatures.iter() {
                    len += encode_sized_vec!(sig, s);
                }
            }
            _ => {
                if let Some(sig) = &self.rct_signatures.sig {
                    len += sig.consensus_encode(s)?;
                    if let Some(p) = &self.rct_signatures.p {
                        len += p.consensus_encode(s, sig.rct_type)?;
                    }
                }
            }
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ExtraField, Transaction, TransactionPrefix};
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize, VarInt};
    use crate::cryptonote::hash::Hashable;
    use crate::util::key::{PrivateKey, PublicKey, ViewPair};
    use crate::util::ringct::{RctSig, RctSigBase, RctType};
    use crate::TxOut;
    use crate::{
        blockdata::transaction::{SubField, TxIn, TxOutTarget},
        cryptonote::onetime_key::SubKeyChecker,
    };

    #[test]
    fn deserialize_transaction_prefix() {
        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<TransactionPrefix>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx));
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );

        let tx = deserialize::<Transaction>(&hex[..]).unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
    }

    #[test]
    fn transaction_hash() {
        let hex = hex::decode("020002020016f8d17bcaf502cf8e0386329472a00d9e07b90ffd07cb13b2011f4485016ec5040c84010d8e010434b5a9452ecc321f1a178838039004c968d24f853611b6217fde4c95913e732994020016f3ff35db9145858c06c29401c508840984039455c206e001dc09b303ab05d00321d1015f1f1ebb01ae03b602884b10c94370e3b882849785708a451b13d1b7c820793560eb45370a7911ec41020002b773759666c43d3d1575d93d37ccc36bc6daee61c840beba50fbf0a49682165700024e352288e6dee2a3a2d7dac41c960660fe78b42429ea1254135fa1e93596edfc2c01a1237b89efd8f61ee483917b559903ba672ece98a5c9bbd1929e81240e14101202090128fd80dcef7b3e6b08c8e4fe61c806ed05ce7420cb1feb5e67eab1cbcb77d6341a1f38212fedd7a56f2e0771459dc67fab215b7f166e4e4ff4465a887fe9ce400ee9b1894b52b4c88bafd4dc15c310af018ff893f3055561fb6a2006e3019966757ba296f26f4fea519e14668fd8223f2bef215f58400fca27679610edac6e89345cf126002599f7e5c59c9b1e861e669433f568b2b9b5bfe35189e9b6b18b867aa3e63d75ab6ab23ba1b4785e5e4e7a31ec31c11d175e5101f1bcc257f11a15979da2500ed0ffe7dd7b2745d46febbc927478a8d23022e99971c0cba2073ef062bff803380f98b57de75e66adeb24f98b1911105c7979d9f64ca9b63e06be762ca201566cd04de846ddf80659bdbd0486f18b3e74d8308ccc0df9f9de0407f964b8d4c216d2782c8c7d01fb0d7ce2de5aaa35933836807cbfdf171310b51154f5339b4336eb00847886d346576e8e8c0ad36e8fc2efd635fe5e91055dd2b3d489a1724f7714b4445beaddbf5c74168f54a69042ce86ea581b8d8bb4c5969b5468efa8df184dab42a428365714f243b7da0f04f677d631a4e56bcc84235f1a2798118d4627ffad24b7144bd06188c67552daf512707efbbaa73c351472cc6d3fe18156274abe2fa48b8655da7df9faabee8b1bee12b1c03a1dd4cae1255f5220b895377c13ebce6792c9315344aecc2c8518bfe1307babff994c5c244a1ce907508f7a73b67d3a1ecc5991aa4beb4e86aaab33f79ee82368d7e20a8fe01796328af8015ff42f300bf285c38ab332d6ebdfa401504657e31e54af722669ff9f24e1ac4da253f0c2ef9e38f0a0112a6263ffac579b123e07e88318a2e219cd6a376030e6b3b929e019fc8f94584e0674887ecb488083d29e3d9982552fc10f9ba4e1fc08886980dcb08d12262dab350acde00ba232d97c4a8039a2060a511031e70991d0c08dd76e4616ddaf84b4ba5586915c734d8e6f3fc62026c8b24f7dbde7d3e07905f4fb974f8e6a29ed9bde34f40b9583ee065c227a5ed5c0507f57073da0fee137db62111ed9f8ea98f9489bb21d2b52a60b1a967cba051a98624c9f059c85237b6063e39fc236312efd6abb649516187900da02efc2e9b48314134e0281d050b5826f72889e5cc36b5cc4f18749aefb92affbda3328a38dbd0adf000fb87e0e0bce4eff0f3b1c09fd0e254fa70201e4a0562016340566a859fd2bb50920222b26ee114fc28758e45f9fb1283800e8bb065339b5186730c324b31624003ece04335bcdaebb18279c9bdb7c5dff2e1a3efc6e22fd5c5faae795c211d800283d93f2c733409e549e92ce91092bfdc90a69c9cde2afa68ee0b77d75312f04af936450855b3a3b4521a1d31b9fa1e942d7589c1b974cb3cc63182a046f200cbbbdfb6912dc1a5191f1a6c6aaa440c65d636aaa3a3df21bdcea7edf1ec5d6068377e162a8c1699a06f82eca4c7ef81f30a9d128118e8aeb344e32714f7b5e09cf8080d396bd37fa5e01d79fd9f3f382aad97c5da2153d2bf7dd228ddef0b30092cdf4145e9bb47b36cf36e66be9cb240b337f0a05a72b43ab21492534a28e07258f7c4f966bef3b4eb53902b42e74b324675a370d4842a0bc590be5063ba40ae1ed7cb39beadc9d7ea983fee12b72b3e600a8f08adc7a62d0ee36bba45faa014e4e17627ff9a46b679a5499953645f98819bee983f982bac89158afe5bf970290f4973382c16892ab41a6e83b2aacc259ae5905fa16424d63575b06a5e7ba0165c7140df98a94830afa809d8e24d99f8a095ca39ceb86faa79bd95bfc25350844472fc0d87479c734e9a36861940d2efa0d3f2310f69a92c93c5d7c3c5b75036c7cc0fb4d10cb7f4da6923c369d9c2c5187f60c546b59eeab3cd3dee0729103cdcec58a49a28c8314a182ffce0b489ec36a5b37cb4383c2dce447ec747c060a29dbe7929cfe73d5cc3ed498963fb0fc96d3614eed1bab400964fbf0c016a80fd1999292bef353256db14726c25a2d18a6dc8f3a7e5e6ebc0fcb2830faf8940b3edf44aceec76b185ab653f26b404a8dc59e76787a14f363b47a923e3dc2d20e86501f99ec03777f5a2c47dc0cf5dfd6d0c3982d9f0ad30087784de3fb2cf9860b5eb5daa3fc8c3e100a965fc8e332b23bc479b6016ff9ff954b2862583ef7006c976ddd3efe982e6a5496ec17c44e92368cd762ee1526a07c76b119b53c000bab77efa559b3f84773d10c447048a13edf921ea36496992af5aef0a1c1692804143c07f4d6a872b5cfacf570843900d5da62b443807d4ef013c76fa237526902bf2f634e830929acf5ec3be82be0533c498b42e9aa03bc539a9ceee46b3ec10c8e8df58636275fec7f7d839a289a19a9b6d2ba303c576792080f2f6fe86c32076f3c0b1a0933dfb337b6027b2d2283896c7b690676dbf46f86852b164a2fde0b067efc0500b74d47026583081a7af37e1c6306191d8bb79c6dbecf4ae47e320d30704ccd3dcf9698610891260f58c1049d721331c011d729eb2a00127710d90e3b0117426d36420fc73ae63fb766a1431f63fecd18d5b65c06fa928a44a7b200085fa60f5448303aa041f9536e801ce3b57fa6b051c113f41093fa5dba015807cfb4497dc36696cace4cbf1d9c37b8764fe54399f8d4f7392071ecf770dddf02fa35e8ce7e18627b729530aa34335a729824218839bf86846763e8b590f7f30a7d28bc2ba192e98aec1ff67500740749681c51d8852aab2a5342120da3ec1b08cfcbcf1aac5a8451b586b719dd9ad6f2b2dfe23f729e7752a996a53f8f0c690d6d327c497100738fe1f3ec3b1727c288f4513db60dd6f36cc8dbf11e38bb240e00f3c20824d4a6b8bc9a3223887ac7197bd7129a1b6e57f02f3b7b071af1ad0e53428d3a7686317aa57db2bbcbde1a50283de66ae6937b56099978e82c294e09f795f352b4719185cc09ce756cad91a98066f2101eff854143511de0a52fb400da81eba97aff02fe9e28e5389d5a12cbc3bfd87861277025cfd0f8feaf51170bc02e060f60fb3cee485dcaf93b2199e536444d9a071f5fd6039603a6b93e27077549cf0ccb6f15d907befae3d8857ef4a7f2850c6aa83c297c3848ddb0229402e9a1a1bae766bc8425aa41dd235754e648826a3eafece99e765862ff7978ce0380592385f01781e983faa10f0294037074eed1027f0097db1b5adc172e950c2ec18b2e08f75485cc1870fc76931c8ae1e72d4b5fdddb8db6c2556c7233ed0ee39d956c11d39dd833b269c195139bb9e3a90b8af6eace971fd5cca6039819b33a").unwrap();
        let tx = deserialize_partial::<TransactionPrefix>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap().0;
        assert_eq!(
            "d02d71fdc662090302353b1cddc0796264b7f16d13f9bade64c1f0a86bf442ea",
            format!("{:02x}", tx.hash())
        );

        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex, serialize(&tx));
        assert_eq!(
            "c50ecadac939ae36053dd9257275506e29eadf58758972f8c583a4362f1584e6",
            format!("{:02x}", tx.hash())
        );
    }

    #[test]
    fn find_outputs() {
        let view = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let spend = PublicKey::from_private_key(&b);
        let viewpair = ViewPair { view, spend };

        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<TransactionPrefix>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
        assert!(tx.check_outputs(&viewpair, 0..1, 0..200, None).is_ok());
        assert_eq!(hex, serialize(&tx));

        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );
    }

    #[test]
    fn find_outputs_with_checker() {
        let view = PrivateKey::from_str(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404",
        )
        .unwrap();
        let b = PrivateKey::from_str(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09",
        )
        .unwrap();
        let spend = PublicKey::from_private_key(&b);
        let viewpair = ViewPair { view, spend };

        let hex = hex::decode("01f18d0601ffb58d0605efefead70202eb72f82bd8bdda51e0bdc25f04e99ffb90c6214e11b455abca7b116c7857738880e497d01202e87c65a22b78f4b7686ef3a30113674659a4fe769a7ded73d60e6f7c556a19858090dfc04a022ee52dca8845438995eb6d7af985ca07186cc34a7eb696937f78fc0fd9008e2280c0f9decfae0102cec392ffdcae05a370dc3c447465798d3688677f4a5937f1fef9661df99ac2fb80c0caf384a30202e2b6ce11475c2312d2de5c9f26fbd88b7fcac0dbbb7b31f49abe9bd631ed49e42b0104d46cf1a204ae727c14473d67ea95da3e97b250f3c63e0997198bfc812d7a81020800000000d8111b25").unwrap();
        let tx = deserialize::<Transaction>(&hex[..]);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(
            "3bc7ff015b227e7313cc2e8668bfbb3f3acbee274a9c201d6211cf681b5f6bb1",
            format!("{:02x}", tx.hash())
        );

        let checker = SubKeyChecker::new(&viewpair, 0..1, 0..200);

        assert!(tx.check_outputs_with(&checker).is_ok());
        assert_eq!(hex, serialize(&tx));
    }

    #[test]
    fn test_tx_hash() {
        let tx = "f8ad7c58e6fce1792dd78d764ce88a11db0e3c3bb484d868ae05a7321fb6c6b0";

        let pk_extra = vec![
            179, 155, 220, 223, 213, 23, 81, 160, 95, 232, 87, 102, 151, 63, 70, 249, 139, 40, 110,
            16, 51, 193, 175, 208, 38, 120, 65, 191, 155, 139, 1, 4,
        ];
        let transaction = Transaction {
            prefix: TransactionPrefix {
                version: VarInt(2),
                unlock_time: VarInt(2143845),
                inputs: vec![TxIn::Gen {
                    height: VarInt(2143785),
                }],
                outputs: vec![TxOut {
                    amount: VarInt(1550800739964),
                    target: TxOutTarget::ToKey {
                        key: PublicKey::from_slice(
                            hex::decode(
                                "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                            )
                            .unwrap()
                            .as_slice(),
                        )
                        .unwrap(),
                    },
                }],
                extra: ExtraField(vec![
                    SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                    SubField::Nonce(vec![
                        196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                ]),
            },
            signatures: vec![],
            rct_signatures: RctSig {
                sig: Option::from(RctSigBase {
                    rct_type: RctType::Null,
                    txn_fee: Default::default(),
                    pseudo_outs: vec![],
                    ecdh_info: vec![],
                    out_pk: vec![],
                }),
                p: None,
            },
        };
        assert_eq!(
            tx.as_bytes().to_vec(),
            hex::encode(transaction.hash().0).as_bytes().to_vec()
        );
    }

    #[test]
    #[should_panic]
    fn test_tx_hash_fail() {
        let tx = "f8ad7c58e6fce1792dd78d764ce88a11db0e3c3bb484d868ae05a7321fb6c6b0";

        let pk_extra = vec![
            179, 155, 220, 223, 213, 23, 81, 160, 95, 232, 87, 102, 151, 63, 70, 249, 139, 40, 110,
            16, 51, 193, 175, 208, 38, 120, 65, 191, 155, 139, 1, 4,
        ];
        let transaction = Transaction {
            prefix: TransactionPrefix {
                version: VarInt(2),
                unlock_time: VarInt(2143845),
                inputs: vec![TxIn::Gen {
                    height: VarInt(2143785),
                }],
                outputs: vec![TxOut {
                    amount: VarInt(1550800739964),
                    target: TxOutTarget::ToKey {
                        key: PublicKey::from_slice(
                            hex::decode(
                                "e2e19d8badb15e77c8e1f441cf6acd9bcde34a07cae82bbe5ff9629bf88e6e81",
                            )
                            .unwrap()
                            .as_slice(),
                        )
                        .unwrap(),
                    },
                }],
                extra: ExtraField(vec![
                    SubField::TxPublicKey(PublicKey::from_slice(pk_extra.as_slice()).unwrap()),
                    SubField::Nonce(vec![
                        196, 37, 4, 0, 27, 37, 187, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                ]),
            },
            signatures: vec![],
            rct_signatures: RctSig { sig: None, p: None },
        };
        assert_eq!(
            tx.as_bytes().to_vec(),
            hex::encode(transaction.hash().0).as_bytes().to_vec()
        );
    }
}
