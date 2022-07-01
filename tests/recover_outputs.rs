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

use wownero::blockdata::block::Block;
use wownero::blockdata::transaction::Transaction;
use wownero::consensus::encode::deserialize;
use wownero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use std::str::FromStr;

const TRANSACTION: &str = "020001020016f59307c0fc76e1bc0488169e8101903cba8d01e513a70cbb039001db088f01e302e0020e30050c0b8d0427d790ca60636139f487c8af3b4556f97e221522514a7882e635d959044bbd680b0200027f54099f27e5d3e85ee9b49bf34054866cf8586fd02aba11ae1ac23bbbae5942000259d6d150201a6703930ae5c12516bedf99b3b58f7c12f53d379549285a880fd62c01c5b77961dde6b0fca945540cc536330d338f13788be9daa2daf870d6973c13a70209015f4b5718291d14fa08e8bcd53fe739299938da24ea360333d4428b590a2807cb3fe4e98f9363919fe36498b3d02c2b071501b2e906e7cc990eba910c3e1b0cf827ddb37f15020c433d97ec18d1f81110f2fffba58d6fa1889d47f0639901fa0429a9ab5fb8389a1478f29bf05d534f8aeaa964d7dcf9df2335edb793ccee6e15aa30fa948a4df98d7b869db0c04feeb4d49f221fab7887fd1b4565acee5fb36644e41bfe8d642575caa54deb4e0e18d48efdab57aa428d3f0dc5b6648c1fecfe0af68fd1035a2ea56c8f60652b6b4284f6792504dfb3a55623bb03f8d80451c51e691c2f355dae9470307663c742f841e08decfcb5c49a5b497d2e310505a2b7de1d27ac465bcae84e04c78494394863d233147856e4d2a266a821639d0707e0f8540ee5f7f0501ab9b8162c87e987942fbd36a2d91e501f95471bd7baa6c59b7601cfa8e8bd58038e4428725a426afe54287f970883b3588c0e2eced5460850fb05a925b73aa55ea5003ce3c25af0338f1df6627f40d9be9ebe130609c7ab285a24b852eaa84908d4833c988dfd233c181a79bcaa243318831f8dd4ef2d4ac903da5ef705c386d92c08e6a7d57b7becf210d6fc6a520dbb1d410324675edba55c29871ba1e625ac5ff102a686fc7a3b1b9d29b94b40107d84450dc1f84dbe7de7a126db6de3a447b17924cf4a88bc5e719883d9817c1191c478094ef9f97707c44a38c4a24c8c29d8e09794b285c660956a12ddf47a77562571a6104d7157138a353107c1f07d2f536e1baf5a266e4669c0c08452934068a62c65d50f6722a4fb571cc2af0f428b8c39797db23b03701285fba8a676db9f2d86fd6c8a2576304b1b7a4bdeafac33c048f9eb15accf2cf8f57b9db67805bb10757767739e6ff3c5f6c52c6d562989d463c8217e25e1bc383ddc471395a9656fd7acb9d0070ea80967d3982a86a6654af058c70b26cbcba298f8eae3601976b88845ae5e2a4efcebfb7cb4a01c03874e57ce147239a4fb70bedcba5dfe8a8828434a572aed4712ebf85612930ed82805939607536fea8324840dd280c72e5ac39df76f88ae600421eb661e14a38b5c59a86a0ed1e60703be695fb00b0df2f34b95b5e91b6a8301d0e45e1040475987bf3b18bab8a5654a7219a8744d46a4d9b3254fbd376364083c3d44c468e6aa5632641c001d34d8aa29c32f93c2c22cda2373363819e1d4001491505c192c605e41a39af664d5190165bcf2d0d525ca54feb6ffc75b5c02049e6803c263272d33160501578eae5495c1fa144da2ce833e628d914531ee30044d24079244ca21f4cbe9b03179830a8582a6c943838a7fc0dbc7b78ac1eb2106078b9013f8dc7df4e2e58e59fc3f8373e8c582e026f62b267dce1c91e8cb3a0adf5f106f0af67b91c6ce6b55bca04fb75ad325d4cdff2643dcea9e37ecab41051d5382d08064fc54a70e7167c6dbcce6a9fbb0cc6b192086b19f264ffe64a8047fb568395d53088e7b9eb3fd0a729057a07aca72d1f5b33599fcfebc0eefca03f1cba0032d7bd93a74a0edc47a7ae0377fb2d473b894249142987ef3824f0c06eaf63102940f98cf1c1cf10b56a5ff63db90b1dade0cde2cea8f971e97cc06034a3654714c87f1c027cf9de4efdc816bf6819b4eeb6534185e505bdb428fa9051b93a5f760a65b3b454e77205d8d69d4eaa1fda7b72be26ac9e77c4354c34b01201f47a408a37a12a7aa83b4b7d369afc0d7647f80761dee5b53c308b748a8028a9c9cf908d71eac6eaeed172d966512480314e2a4b7fb0ac186b01d9b55e00bbe68cd6b1ad411dbea7856084eb4b6d1ea4d701643b2aebb12bda04a322bba0e08e6ae693fbb9fbad0c291f2616b88d13de751fc415b0e0147fbeef3f5fcd9098a54e6037a7b26c2c63b114617dce2cf1ac6763cd0a99e7e4d3729bee117d00831763d2b60b7571072b782f61a28af112564398fe2e3cfa05b80c95fbfb06903e77c320bd6bf6fb6113b64053c52a2dd70cf51b54c7bd5fda60bffc35a10a50ade75df35f7d83b1f7e77ff68c8cb2bb6abc9271c386445d77a4736475eb57b02c7a770cd299c6895041c21ca27e61d50376037cbc9749ec25c5034d4920c6a6f8ad867c03a4172e9d1b007de8e0818662ef14a62c8484392416e9aa3493211fe";

#[test]
fn recover_output_and_amount() {
    let raw_tx = hex::decode(TRANSACTION).unwrap();
    let tx = deserialize::<Transaction>(&raw_tx).expect("Raw tx deserialization failed");

    let secret_view_bytes =
        hex::decode("66f87043a02f41ad494d1a2311ffd1d5dda1d8d786d1b72257ad99925013f906").unwrap();
    let secret_view = PrivateKey::from_slice(&secret_view_bytes).unwrap();

    let secret_spend_bytes =
        hex::decode("996420ae86c8101d86b56120092a7c5646f42a2967bcbc3bb2d54f81e84ae201").unwrap();
    let secret_spend = PrivateKey::from_slice(&secret_spend_bytes).unwrap();
    let public_spend = PublicKey::from_private_key(&secret_spend);

    // Keypair used to recover the ephemeral spend key of an output
    let keypair = KeyPair {
        view: secret_view,
        spend: secret_spend,
    };

    let spend = public_spend;

    // Viewpair used to scan a transaction to retreive owned outputs
    let view_pair = ViewPair {
        view: secret_view,
        spend,
    };

    // Get all owned output for sub-addresses in range of 0-1 major index and 0-2 minor index
    let owned_outputs = tx.check_outputs(&view_pair, 0..2, 0..3).unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    // Recover the ephemeral private spend key
    let private_key = out.recover_key(&keypair);
    assert_eq!(
        "2b86de084155e92537b887a1108408f7788a27b5656410cfc3e4100020ca150b",
        format!("{}", private_key)
    );
    assert_eq!(
        "7f54099f27e5d3e85ee9b49bf34054866cf8586fd02aba11ae1ac23bbbae5942",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap(), 9171600000000);
}

#[test]
fn check_output_on_miner_tx() {
    // Generated new wallet: 49cttiQ3JH4ewwyVotG84TdCe367rziTsbkpsguMSmuMBf2igZMcBZDMs7TecAvKmMg4pnrz5WmiiXQgGLSVGVWzSdv21dw
    //
    // spendkey:
    // secret: 57cabb831c03159455ef561e7ce7daf841c5921b264f837d970115b9ef24c100
    // public: d30282faa44fa7e2df5ec621bf030cd86dfc6f3d4ddcd2cfca4bca51ce1b743f
    //
    // viewkey:
    // secret: b526321e8a138afba32063ac87d21f3deb05cb40a46410f8fe861f5ab95ac606
    // public: b4c76e76ad3eac7cbcd60983966d8ce98f582a8b288acbb5cc841d69c6d2b3e3
    //
    // swiftly september faked having annoyed ourselves pedantic cunning
    // fetches major potato peeled answers against building soprano
    // eternal school lipstick wickets python puzzled large lava building
    //
    //   1  block unlocked       2022-06-29 07:33:29      35.184338534400 50ad877c2f126c9278dc4b043774bceb995c80bc2fa11de10a0f8379a856422e 0000000000000000 0.000000000000 49cttiQ3JH4ewwyVotG84TdCe367rziTsbkpsguMSmuMBf2igZMcBZDMs7TecAvKmMg4pnrz5WmiiXQgGLSVGVWzSdv21dw:35.184338534400 0 -
    //
    let block = hex::decode("0e0ec980f09506418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e38475c625023d01ff0101808080f0ffff0702e928dfd0a413a4eac0b541fcc434c56da56cb34c95d8d6916146c3a4f7071ae82101b0f38ad895b9a7bc053e9be31ddd16139ad7006396ae7a29eb6365306ae6f4b70000").unwrap();
    let block = deserialize::<Block>(&block).expect("Block deserialization failed");
    println!("{:#?}", block);

    let secret_view =
        PrivateKey::from_str("b526321e8a138afba32063ac87d21f3deb05cb40a46410f8fe861f5ab95ac606")
            .unwrap();

    let secret_spend =
        PrivateKey::from_str("57cabb831c03159455ef561e7ce7daf841c5921b264f837d970115b9ef24c100")
            .unwrap();
    let public_spend = PublicKey::from_private_key(&secret_spend);

    let keypair = KeyPair {
        view: secret_view,
        spend: secret_spend,
    };

    let spend = public_spend;
    let view_pair = ViewPair {
        view: secret_view,
        spend,
    };

    let owned_outputs = block
        .miner_tx
        .check_outputs(&view_pair, 0..1, 0..1)
        .unwrap();

    assert_eq!(owned_outputs.len(), 1);
    let out = owned_outputs.get(0).unwrap();

    let private_key = out.recover_key(&keypair);
    assert_eq!(
        "f984b89e6c4f18ff1d6e2bd9eb5571097dbc48d5d7b4cc51ac1a548cb9d3b809",
        format!("{}", private_key)
    );
    assert_eq!(
        "e928dfd0a413a4eac0b541fcc434c56da56cb34c95d8d6916146c3a4f7071ae8",
        format!("{}", PublicKey::from_private_key(&private_key))
    );

    let amount = out.amount();
    assert!(amount.is_some());
    assert_eq!(amount.unwrap(), 35184338534400);
}
