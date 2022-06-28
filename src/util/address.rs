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

//! Monero addresses types and helper functions.
//!
//! Support for (de)serializable Monero addresses in Monero `base58` format (not equivalent to
//! Bitcoin `base58` format).
//!
//! ## Parsing an address
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::{Address, Network};
//! use monero::util::address::{AddressType, Error};
//!
//! let addr = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
//! let address = Address::from_str(addr)?;
//!
//! assert_eq!(address.network, Network::Mainnet);
//! assert_eq!(address.addr_type, AddressType::Standard);
//!
//! let public_spend_key = address.public_spend;
//! let public_view_key = address.public_view;
//! # Ok::<(), Error>(())
//! ```
//!

use std::fmt;
use std::str::FromStr;

use base58_monero::base58;

use crate::consensus::encode::{self, Decodable};
use crate::cryptonote::hash::keccak_256;
use crate::network::{self, Network, NetworkByte};
use crate::util::key::{KeyPair, PublicKey, ViewPair};

use sealed::sealed;
use thiserror::Error;

/// Potential errors encountered when manipulating addresses.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Invalid address magic byte.
    #[error("Invalid magic byte")]
    InvalidMagicByte,
    /// Invalid payment id.
    #[error("Invalid payment ID")]
    InvalidPaymentId,
    /// Missmatch address checksums.
    #[error("Invalid checksum")]
    InvalidChecksum,
    /// Generic invalid format.
    #[error("Invalid format")]
    InvalidFormat,
    /// Monero base58 error.
    #[error("Base58 error: {0}")]
    Base58(#[from] base58::Error),
    /// Network error.
    #[error("Network error: {0}")]
    Network(#[from] network::Error),
}

/// Address type: standard, integrated, or sub-address.
///
/// AddressType implements [`Default`] and returns [`AddressType::Standard`].
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AddressType {
    /// Standard address.
    Standard,
    /// Address with a short 8 bytes payment id.
    Integrated(PaymentId),
    /// Sub-address.
    SubAddress,
}

impl AddressType {
    /// Recover the address type given an address bytes and the network.
    pub fn from_slice(bytes: &[u8], net: Network) -> Result<AddressType, Error> {
        let byte = bytes[0];
        use AddressType::*;
        use Network::*;
        match net {
            Mainnet => match (byte, bytes[1]) {
                (178, 32) => Ok(Standard),
                (154, 53) => {
                    let payment_id = PaymentId::from_slice(&bytes[66..74]);
                    Ok(Integrated(payment_id))
                }
                (176, 95) => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Testnet => match byte {
                53 => Ok(Standard),
                54 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Integrated(payment_id))
                }
                63 => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Stagenet => match byte {
                24 => Ok(Standard),
                25 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Integrated(payment_id))
                }
                36 => Ok(SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
        }
    }
}

impl Default for AddressType {
    fn default() -> AddressType {
        AddressType::Standard
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressType::Standard => write!(f, "Standard address"),
            AddressType::Integrated(_) => write!(f, "Integrated address"),
            AddressType::SubAddress => write!(f, "Subaddress"),
        }
    }
}

fixed_hash::construct_fixed_hash! {
    /// Short Payment Id for integrated address, a fixed 8-bytes array.
    pub struct PaymentId(8);
}

/// A complete Monero typed address valid for a specific network.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct Address {
    /// The network on which the address is valid and should be used.
    pub network: Network,
    /// The address type.
    pub addr_type: AddressType,
    /// The address spend public key.
    pub public_spend: PublicKey,
    /// The address view public key.
    pub public_view: PublicKey,
}

impl Address {
    /// Create a standard address which is valid on the given network.
    pub fn standard(network: Network, public_spend: PublicKey, public_view: PublicKey) -> Address {
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Create a sub-address which is valid on the given network.
    pub fn subaddress(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
    ) -> Address {
        Address {
            network,
            addr_type: AddressType::SubAddress,
            public_spend,
            public_view,
        }
    }

    /// Create an address with an integrated payment id which is valid on the given network.
    pub fn integrated(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
        payment_id: PaymentId,
    ) -> Address {
        Address {
            network,
            addr_type: AddressType::Integrated(payment_id),
            public_spend,
            public_view,
        }
    }

    /// Create a standard address from a view pair which is valid on the given network.
    pub fn from_viewpair(network: Network, keys: &ViewPair) -> Address {
        let public_view = PublicKey::from_private_key(&keys.view);
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend: keys.spend,
            public_view,
        }
    }

    /// Create a standard address from a key pair which is valid on the given network.
    pub fn from_keypair(network: Network, keys: &KeyPair) -> Address {
        let public_spend = PublicKey::from_private_key(&keys.spend);
        let public_view = PublicKey::from_private_key(&keys.view);
        Address {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Parse an address from a vector of bytes, fail if the magic byte is incorrect, if public
    /// keys are not valid points, if payment id is invalid, and if checksums missmatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Address, Error> {
        let network = Network::from_u8(bytes[0])?;
        let addr_type = AddressType::from_slice(bytes, network)?;
        let netbytes_size = NetworkByte::number_of_bytes(network);
        let public_spend = PublicKey::from_slice(&bytes[netbytes_size..32 + netbytes_size])
            .map_err(|_| Error::InvalidFormat)?;
        let public_view = PublicKey::from_slice(&bytes[32 + netbytes_size..64 + netbytes_size])
            .map_err(|_| Error::InvalidFormat)?;
        let (checksum_bytes, checksum) = match addr_type {
            AddressType::Standard | AddressType::SubAddress => (
                &bytes[0..64 + netbytes_size],
                &bytes[64 + netbytes_size..68 + netbytes_size],
            ),
            AddressType::Integrated(_) => (&bytes[0..74], &bytes[74..78]),
        };
        let verify_checksum = keccak_256(checksum_bytes);
        if &verify_checksum[0..4] != checksum {
            return Err(Error::InvalidChecksum);
        }

        Ok(Address {
            network,
            addr_type,
            public_spend,
            public_view,
        })
    }

    /// Serialize the address as a vector of bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.network.as_u8(&self.addr_type).as_vec());
        bytes.extend_from_slice(self.public_spend.as_bytes());
        bytes.extend_from_slice(self.public_view.as_bytes());
        if let AddressType::Integrated(payment_id) = &self.addr_type {
            bytes.extend_from_slice(&payment_id.0);
        }

        let checksum = keccak_256(bytes.as_slice());
        bytes.extend_from_slice(&checksum[0..4]);
        bytes
    }

    /// Serialize the address as an hexadecimal string.
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base58::encode(self.as_bytes().as_slice()).unwrap())
    }
}

impl FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base58::decode(s)?)
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    use serde_crate::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Address {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Address {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s).map_err(D::Error::custom)
        }
    }
}

impl Decodable for Address {
    fn consensus_decode<D: std::io::Read>(d: &mut D) -> Result<Address, encode::Error> {
        let address: Vec<u8> = Decodable::consensus_decode(d)?;
        Ok(Address::from_bytes(&address)?)
    }
}

#[sealed]
impl crate::consensus::encode::Encodable for Address {
    fn consensus_encode<S: std::io::Write>(&self, s: &mut S) -> Result<usize, std::io::Error> {
        self.as_bytes().consensus_encode(s)
    }
}

// TODO: Add tests for stage & testnet
#[cfg(test)]
mod tests {
    use crate::consensus::encode::{Decodable, Encodable};
    use std::str::FromStr;

    use super::{base58, Address, AddressType, Network, PaymentId, PublicKey};

    #[test]
    fn deserialize_address() {
        let pub_spend = PublicKey::from_slice(&[
            56, 93, 20, 64, 236, 199, 20, 180, 215, 185, 240, 157, 76, 197, 78, 27, 209, 3, 203,
            70, 77, 105, 16, 142, 48, 100, 115, 107, 58, 233, 221, 199,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            65, 193, 78, 9, 72, 8, 78, 159, 185, 244, 246, 193, 13, 12, 240, 178, 193, 248, 239,
            33, 198, 159, 243, 17, 72, 62, 141, 204, 208, 25, 111, 248,
        ])
        .unwrap();
        let address = "Wo3YvSv2rqk4TswCUpHHwzE4kc9HxvZax3mcHZBtC56Ge6XcSkej5JXE9kY6DFgU19hG5LU2PjE9khf4SXXyfGHn1xkzYoWsk";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );

        let bytes = base58::decode(address).unwrap();
        let add = Address::from_bytes(&bytes);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );

        let full_address = add.unwrap();
        let mut encoder = Vec::new();
        full_address.clone().consensus_encode(&mut encoder).unwrap();
        let mut res = std::io::Cursor::new(encoder);
        let addr_decoded = Address::consensus_decode(&mut res).unwrap();
        assert_eq!(full_address, addr_decoded);
    }

    #[test]
    fn deserialize_integrated_address() {
        let pub_spend = PublicKey::from_slice(&[
            171, 162, 233, 87, 229, 250, 158, 156, 25, 187, 161, 81, 56, 122, 81, 83, 17, 169, 228,
            121, 208, 253, 233, 196, 244, 89, 253, 248, 77, 86, 78, 251,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            82, 123, 6, 39, 245, 166, 42, 115, 238, 61, 40, 135, 197, 49, 193, 169, 235, 157, 127,
            236, 22, 251, 247, 54, 184, 236, 60, 244, 20, 191, 147, 176,
        ])
        .unwrap();
        let payment_id = PaymentId([170, 185, 129, 214, 9, 100, 93, 195]);

        let address = "So2Z5hH3RnRTXiNyYMJqkuEbx4onpQ3vCg6rd776aTXjEDDrmeZhENq86r4Ut7fjXEZPnJDza7sDUiMHRUNzWKAvRhnBdmEu9bZ1oh6U1hnX";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::integrated(
                Network::Mainnet,
                pub_spend,
                pub_view,
                payment_id
            )),
            add
        );
    }

    #[test]
    fn deserialize_sub_address() {
        let pub_spend = PublicKey::from_slice(&[
            159, 84, 131, 221, 26, 253, 171, 45, 177, 66, 136, 23, 73, 98, 112, 165, 192, 97, 149,
            190, 75, 156, 140, 215, 229, 61, 165, 60, 28, 10, 11, 202,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            41, 52, 237, 179, 210, 253, 52, 104, 18, 3, 1, 59, 249, 212, 246, 134, 208, 199, 48,
            239, 150, 166, 61, 39, 235, 1, 206, 217, 202, 70, 119, 88,
        ])
        .unwrap();

        let address = "WW3ZSaMkez8VdeTGsj5CW5KqpeeRnzLioQZMhR8xoaZf2yNjjqPXc3E9mQifiGPQW7iEcnnCJUkfPBEHmcjKhrTX22RwPkAFY";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::subaddress(Network::Mainnet, pub_spend, pub_view)),
            add
        );
    }

    #[test]
    fn deserialize_address_with_paymentid() {
        let address = "So2Z5hH3RnRTXiNyYMJqkuEbx4onpQ3vCg6rd776aTXjEDDrmeZhENq86r4Ut7fjXEZPnJDza7sDUiMHRUNzWKAvRhnBdmEu9bZ1oh6U1hnX";
        let addr = Address::from_str(address).unwrap();
        let payment_id = PaymentId([170, 185, 129, 214, 9, 100, 93, 195]);
        assert_eq!(addr.addr_type, AddressType::Integrated(payment_id));
    }

    #[test]
    fn serialize_address() {
        let address = "Wo3YvSv2rqk4TswCUpHHwzE4kc9HxvZax3mcHZBtC56Ge6XcSkej5JXE9kY6DFgU19hG5LU2PjE9khf4SXXyfGHn1xkzYoWsk";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_integrated_address() {
        let address = "So2Z5hH3RnRTXiNyYMJqkuEbx4onpQ3vCg6rd776aTXjEDDrmeZhENq86r4Ut7fjXEZPnJDza7sDUiMHRUNzWKAvRhnBdmEu9bZ1oh6U1hnX";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_to_string() {
        let address = "So2Z5hH3RnRTXiNyYMJqkuEbx4onpQ3vCg6rd776aTXjEDDrmeZhENq86r4Ut7fjXEZPnJDza7sDUiMHRUNzWKAvRhnBdmEu9bZ1oh6U1hnX";
        let add = Address::from_str(address).unwrap();
        assert_eq!(address, add.to_string());
    }
}
