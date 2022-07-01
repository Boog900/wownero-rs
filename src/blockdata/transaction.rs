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
/// use monero::blockdata::transaction::Transaction;
/// use monero::consensus::encode::deserialize;
/// use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
/// # use std::str::FromStr;
///
/// # let raw_tx = hex::decode("02000102000bb2e38c0189ea01a9bc02a533fe02a90705fd0540745f59f49374365304f8b4d5da63b444b2d74a40f8007ea44940c15cbbc80c9d106802000267f0f669ead579c1067cbffdf67c4af80b0287c549a10463122b4860fe215f490002b6a2e2f35a93d637ff7d25e20da326cee8e92005d3b18b3c425dabe8336568992c01d6c75cf8c76ac458123f2a498512eb65bb3cecba346c8fcfc516dc0c88518bb90209016f82359eb1fe71d604f0dce9470ed5fd4624bb9fce349a0e8317eabf4172f78a8b27dec6ea1a46da10ed8620fa8367c6391eaa8aabf4ebf660d9fe0eb7e9dfa08365a089ad2df7bce7ef776467898d5ca8947152923c54a1c5030e0c2f01035c555ff4285dcc44dfadd6bc37ec8b9354c045c6590446a81c7f53d8f199cace3faa7f17b3b8302a7cbb3881e8fdc23cca0275c9245fdc2a394b8d3ae73911e3541b10e7725cdeef5e0307bc218caefaafe97c102f39c8ce78f62cccf23c69baf0af55933c9d384ceaf07488f2f1ac7343a593449afd54d1065f6a1a4658845817e4b0e810afc4ca249096e463f9f368625fa37d5bbcbe87af68ce3c4d630f93a66defa4205b178f4e9fa04107bd535c7a4b2251df2dad255e470b611ffe00078c2916fc1eb2af1273e0df30dd1c74b6987b9885e7916b6ca711cbd4b7b50576e51af1439e9ed9e33eb97d8faba4e3bd46066a5026a1940b852d965c1db455d1401687ccaccc524e000b05966763564b7deb8fd64c7fb3d649897c94583dca1558893b071f5e6700dad139f3c6f973c7a43b207ee3e67dc7f7f18b52df442258200c7fe6d16685127da1df9b0d93d764c2659599bc6d300ae33bf8b7c2a504317da90ea2f0bb2af09bd531feae57cb4a0273d8add62fadfc6d43402372e5caf854e112b88417936f1a9c4045d48b5b0b7703d96801b35ff66c716cddbee1b92407aa069a162c163071710e28ccddf6fb560feea32485f2c54a477ae23fd8210427eabe4288cbe0ecbef4ed19ca049ceded424d9f839da957f56ffeb73060ea15498fcbc2d73606e85e963a667dafdb2641fb91862c07b98c1fdae8fadf514600225036dd63c22cdadb57d2125ebf30bc77f7ea0bc0dafb484bf01434954c5053b9c8a143f06972f80fa66788ea1e3425dc0104a9e3674729967b9819552ebb172418da0e4b3778ad4b3d6acd8f354ba09e54bbc8604540010e1e1e4d3066515aed457bd3399c0ce787236dbcd3923de4fb8faded10199b33c1251191612ab5526c1cf0cd55a0aeaed3f7a955ceced16dabdbeb0a2a19a9fdb5aa8c4fc8767cf70e4ad1838518bc6b9de7c420c1f57636579a14a5a8bdacd24e61a68adede8a2e07416c25409dd91ab78905bc99bab4ab4fb9e4ea628e09a271837769c4e67e580dcd5485e12e4e308cb4509686a7484a71f7dfe334499808c7122f07d45d89230b1f19ed86f675b7fec44ef5f3b178ae0af92ff114bd96baa264604fea5a762307bdce6cb483b7bc780d32ed5343fcc3aa306997f211dc075f6dfd66035c1db10bef8656fefbb45645264d401682e42fe3e05906f79d65481b87508f1a4c434e0d1dfc247d4276306f801a6b57e4e4a525177bae24e0bd88a216597d9db44f2604c29d8a5f74e7b934f55048690b5dcefd6489a81aa64c1edb49b320faab94130e603d99e455cfd828bca782176192ece95e9b967fe3dd698574cf0c0b6926970b156e1134658de657de42c4930e72b49c0d94da66c330ab188c10f0d2f578590f31bcac6fcff7e21f9ff67ae1a40d5a03b19301dcbbadc1aa9392795cf81f1401ec16d986a7f96fbb9e8e12ce04a2226e26b78117a4dfb757c6a44481ff68bb0909e7010988cd37146fb45d4cca4ba490aae323bb51a12b6864f88ea6897aa700ee9142eaf0880844083026f044a5e3dba4aae08578cb057976001beb27b5110c41fe336bf7879733739ce22fb31a1a6ac2c900d6d6c6facdbc60085e5c93d502542cfea90dbc62d4e061b7106f09f9c4f6c1b5506dd0550eb8b2bf17678b140de33a10ba676829092e6a13445d1857d06c715eea4492ff864f0b34d178a75a0f1353078f83cfee1440b0a20e64abbd0cab5c6e7083486002970a4904f8371805d1a0ee4aea8524168f0f39d2dfc55f545a98a031841a740e8422a62e123c8303021fb81afbb76d1120c0fbc4d3d97ba69f4e2fe086822ece2047c9ccea507008654c199238a5d17f009aa2dd081f7901d0688aa15311865a319ccba8de4023027235b5725353561c5f1185f6a063fb32fc65ef6e90339d406a6884d66be49d03daaf116ee4b65ef80dd3052a13157b929f98640c0bbe99c8323ce3419a136403dc3f7a95178c3966d2d7bdecf516a28eb2cf8cddb3a0463dc7a6248883f7be0a10aae1bb50728ec9b8880d6011b366a850798f6d7fe07103695dded3f371ca097c1d3596967320071d7f548938afe287cb9b8fae761fa592425623dcbf653028").unwrap();
/// # let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");
/// # let secret_view_bytes =
/// #     hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07").unwrap();
/// # let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();
/// # let public_view = PublicKey::from_private_key(&secret_view);
/// #
/// # let secret_spend_bytes =
/// #     hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907").unwrap();
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
                            let out_pk_mask = out_pk.mask.scalarmult8()?;
                            actual_commitment = CompressedEdwardsY(out_pk_mask.key)
                                .decompress()
                                .ok_or(Error::InvalidCommitment)?;
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
