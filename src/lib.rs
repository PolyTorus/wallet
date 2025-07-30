#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Core modules
pub mod error;

// Crypto modules
pub mod crypto;

// Utility modules
pub mod utils;

// Wallet modules
pub mod wallet;

// Re-export all types
pub use crypto::keypair::{KeyPair, KeyType};
pub use crypto::signature::{Signature, SignatureScheme};
pub use utils::address::{Address, AddressFormat};
pub use utils::encoding::{encode_hex, decode_hex, encode_base58, decode_base58};
pub use error::{WalletError, Result};
pub use wallet::standard::{Wallet, WalletManager};
pub use wallet::hd::{HdWallet, Mnemonic};

// Common coin types for HD wallets
pub mod coin_types {
    pub const BITCOIN: u32 = 0;
    pub const ETHEREUM: u32 = 60;
    pub const CARDANO: u32 = 1815;
    pub const SOLANA: u32 = 501;
    pub const POLYTORUS: u32 = 9999;
    pub const CUSTOM: u32 = 9999;
}
