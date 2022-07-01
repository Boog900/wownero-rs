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

//! Monero networks definition and related error types.
//!
//! This module defines the existing Monero networks and their associated magic bytes.
//!

use crate::util::address::AddressType;
use thiserror::Error;

/// Potential errors encountered while manipulating Monero networks.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid magic network byte.
    #[error("Invalid magic network byte")]
    InvalidMagicByte,
}

/// Wownero has a different amount of bytes depending if
/// you are using Mainnet(2) or not(1)  :) :) :)
///
pub enum NetworkByte {
    /// Mainnet uses 2 bytes for net byte
    Mainnet(u8, u8),
    /// Stagenet && Testnet use 1 byte
    NotMainnet(u8),
}

impl NetworkByte {
    /// Turns the network byte(s) into a Vec
    pub fn as_vec(self) -> Vec<u8> {
        match self {
            NetworkByte::Mainnet(x, y) => vec![x, y],
            NetworkByte::NotMainnet(x) => vec![x],
        }
    }
    /// returns the amount of Netbytes for each net
    pub fn number_of_bytes(network: Network) -> usize {
        match network {
            Network::Mainnet => 2,
            Network::Stagenet | Network::Testnet => 1,
        }
    }
}
/// The list of the existing Monero networks.
///
/// Network implements [`Default`] and returns [`Network::Mainnet`].
///
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Network {
    /// Mainnet is the "production" network and blockchain.
    Mainnet,
    /// Stagenet is technically equivalent to mainnet, both in terms of features and consensus
    /// rules.
    Stagenet,
    /// Testnet is the "experimental" network and blockchain where things get released long before
    /// mainnet.
    Testnet,
}

impl Network {
    /// Get the associated magic byte given an address type.
    ///
    /// **Source:** [`monero/src/cryptonote_config.h`](https://github.com/monero-project/monero/blob/159c78758af0a0af9df9a4f9ab81888f9322e9be/src/cryptonote_config.h#L190-L239)
    pub fn as_u8(self, addr_type: &AddressType) -> NetworkByte {
        use AddressType::*;
        use Network::*;
        match self {
            Mainnet => match addr_type {
                Standard => NetworkByte::Mainnet(178, 32),
                Integrated(_) => NetworkByte::Mainnet(154, 53),
                SubAddress => NetworkByte::Mainnet(176, 95),
            },
            Testnet => match addr_type {
                Standard => NetworkByte::NotMainnet(53),
                Integrated(_) => NetworkByte::NotMainnet(54),
                SubAddress => NetworkByte::NotMainnet(63),
            },
            Stagenet => match addr_type {
                Standard => NetworkByte::NotMainnet(24),
                Integrated(_) => NetworkByte::NotMainnet(25),
                SubAddress => NetworkByte::NotMainnet(36),
            },
        }
    }

    /// Recover the network type given an address magic byte.
    ///
    /// **Source:** [`monero/src/cryptonote_config.h`](https://github.com/monero-project/monero/blob/159c78758af0a0af9df9a4f9ab81888f9322e9be/src/cryptonote_config.h#L190-L239)
    pub fn from_u8(byte: u8) -> Result<Network, Error> {
        use Network::*;
        match byte {
            178 | 154 | 176 => Ok(Mainnet),
            53 | 54 | 63 => Ok(Testnet),
            24 | 25 | 36 => Ok(Stagenet),
            _ => Err(Error::InvalidMagicByte),
        }
    }
}

impl Default for Network {
    fn default() -> Network {
        Network::Mainnet
    }
}
