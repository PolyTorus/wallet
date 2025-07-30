//! Error types for the PolyTorus Wallet library

use alloc::string::String;
use alloc::format;

#[cfg(feature = "std")]
use thiserror::Error;

/// Result type alias for wallet operations
pub type Result<T> = core::result::Result<T, WalletError>;

/// Comprehensive error types for wallet operations
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, Clone, PartialEq)]
pub enum WalletError {
    /// Cryptographic operation failed
    #[cfg_attr(feature = "std", error("Cryptographic error: {message}"))]
    CryptographicError { message: String },

    /// Invalid key format or data
    #[cfg_attr(feature = "std", error("Invalid key: {message}"))]
    InvalidKey { message: String },

    /// Invalid signature format or verification failed
    #[cfg_attr(feature = "std", error("Invalid signature: {message}"))]
    InvalidSignature { message: String },

    /// Invalid address format
    #[cfg_attr(feature = "std", error("Invalid address format: {format}"))]
    InvalidAddressFormat { format: String },

    /// Address derivation failed
    #[cfg_attr(feature = "std", error("Address derivation failed: {message}"))]
    AddressDerivationError { message: String },

    /// Encoding/decoding error
    #[cfg_attr(feature = "std", error("Encoding error: {message}"))]
    EncodingError { message: String },

    /// Serialization error
    #[cfg_attr(feature = "std", error("Serialization error: {message}"))]
    SerializationError { message: String },

    /// BIP39 mnemonic related errors
    #[cfg(feature = "bip39")]
    #[cfg_attr(feature = "std", error("Mnemonic error: {message}"))]
    MnemonicError { message: String },

    /// HD wallet derivation errors
    #[cfg(feature = "bip39")]
    #[cfg_attr(feature = "std", error("HD wallet error: {message}"))]
    HdWalletError { message: String },

    /// Invalid input parameters
    #[cfg_attr(feature = "std", error("Invalid input: {message}"))]
    InvalidInput { message: String },

    /// Key storage/retrieval errors
    #[cfg_attr(feature = "std", error("Key storage error: {message}"))]
    KeyStorageError { message: String },

    /// Generic wallet operation error
    #[cfg_attr(feature = "std", error("Wallet operation failed: {message}"))]
    OperationError { message: String },
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::CryptographicError { message } => write!(f, "Cryptographic error: {}", message),
            WalletError::InvalidKey { message } => write!(f, "Invalid key: {}", message),
            WalletError::InvalidSignature { message } => write!(f, "Invalid signature: {}", message),
            WalletError::InvalidAddressFormat { format } => write!(f, "Invalid address format: {}", format),
            WalletError::AddressDerivationError { message } => write!(f, "Address derivation failed: {}", message),
            WalletError::EncodingError { message } => write!(f, "Encoding error: {}", message),
            WalletError::SerializationError { message } => write!(f, "Serialization error: {}", message),
            #[cfg(feature = "bip39")]
            WalletError::MnemonicError { message } => write!(f, "Mnemonic error: {}", message),
            #[cfg(feature = "bip39")]
            WalletError::HdWalletError { message } => write!(f, "HD wallet error: {}", message),
            WalletError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
            WalletError::KeyStorageError { message } => write!(f, "Key storage error: {}", message),
            WalletError::OperationError { message } => write!(f, "Wallet operation failed: {}", message),
        }
    }
}

impl WalletError {
    /// Create a new cryptographic error
    pub fn cryptographic<S: Into<String>>(message: S) -> Self {
        Self::CryptographicError { message: message.into() }
    }

    /// Create a new invalid key error
    pub fn invalid_key<S: Into<String>>(message: S) -> Self {
        Self::InvalidKey { message: message.into() }
    }

    /// Create a new invalid signature error
    pub fn invalid_signature<S: Into<String>>(message: S) -> Self {
        Self::InvalidSignature { message: message.into() }
    }

    /// Create a new address derivation error
    pub fn address_derivation<S: Into<String>>(message: S) -> Self {
        Self::AddressDerivationError { message: message.into() }
    }

    /// Create a new encoding error
    pub fn encoding<S: Into<String>>(message: S) -> Self {
        Self::EncodingError { message: message.into() }
    }

    /// Create a new operation error
    pub fn operation<S: Into<String>>(message: S) -> Self {
        Self::OperationError { message: message.into() }
    }
}

// Conversion from external error types
impl From<hex::FromHexError> for WalletError {
    fn from(err: hex::FromHexError) -> Self {
        Self::EncodingError { message: format!("Hex decoding failed: {}", err) }
    }
}

impl From<base58::FromBase58Error> for WalletError {
    fn from(err: base58::FromBase58Error) -> Self {
        Self::EncodingError { message: format!("Base58 decoding failed: {:?}", err) }
    }
}

impl From<bech32::Error> for WalletError {
    fn from(err: bech32::Error) -> Self {
        Self::EncodingError { message: format!("Bech32 encoding/decoding failed: {}", err) }
    }
}

#[cfg(feature = "serde_support")]
impl From<serde_json::Error> for WalletError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError { message: format!("JSON serialization failed: {}", err) }
    }
}

impl From<ed25519_dalek::SignatureError> for WalletError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::CryptographicError { message: format!("Ed25519 signature error: {}", err) }
    }
}

impl From<secp256k1::Error> for WalletError {
    fn from(err: secp256k1::Error) -> Self {
        Self::CryptographicError { message: format!("secp256k1 error: {}", err) }
    }
}
