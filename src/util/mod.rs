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

//! Utility functions to manipulate addresses, amounts, keys, or ringct data types.
//!
//! Shared functions needed in different part of the library or utility types for external
//! integrations.
//!

pub mod address;
pub mod amount;
pub mod key;
pub mod ringct;

use super::network;
use crate::blockdata::transaction;

use thiserror::Error;

/// A general error code, other errors should implement conversions to/from this if appropriate.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Wownero network error.
    #[error("Network error: {0}")]
    Network(#[from] network::Error),
    /// Wownero address error.
    #[error("Address error: {0}")]
    Address(#[from] address::Error),
    /// Wownero key error.
    #[error("Key error: {0}")]
    Key(#[from] key::Error),
    /// Wownero RingCt error.
    #[error("RingCt error: {0}")]
    RingCt(#[from] ringct::Error),
    /// Wownero transaction error.
    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::Error),
    /// Wownero amount parsing error.
    #[error("Amount parsing error: {0}")]
    AmountParsing(#[from] amount::ParsingError),
}
