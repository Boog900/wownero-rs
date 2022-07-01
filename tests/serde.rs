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

#![cfg(any(feature = "serde"))]

use monero::util::amount::{
    serde::{SerdeAmount, SerdeAmountForOpt},
    SignedAmount,
};
use monero::Amount;
use serde_crate::{Deserialize, Serialize};

#[test]
fn serde_amount_and_signed_amount() {
    #[derive(Serialize, Deserialize)]
    #[serde(crate = "serde_crate")]
    pub struct HasAmount<T: SerdeAmountForOpt + SerdeAmount> {
        #[serde(with = "monero::util::amount::serde::as_wow")]
        pub wow_amount: T,
        #[serde(with = "monero::util::amount::serde::as_wow::opt")]
        pub some_wow_amount: Option<T>,
        #[serde(with = "monero::util::amount::serde::as_dust")]
        pub dust_amount: T,
        #[serde(with = "monero::util::amount::serde::as_dust::opt")]
        pub some_dust_amount: Option<T>,
    }

    let amt = Amount::ONE_DUST;
    let _t = HasAmount {
        wow_amount: amt,
        some_wow_amount: Some(amt),
        dust_amount: amt,
        some_dust_amount: Some(amt),
    };

    let amt = SignedAmount::ONE_DUST;
    let _t = HasAmount {
        wow_amount: amt,
        some_wow_amount: Some(amt),
        dust_amount: amt,
        some_dust_amount: Some(amt),
    };
}
