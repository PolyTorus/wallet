//! Integration tests for the PolyTorus wallet

use wallet::{KeyType, Wallet, AddressFormat};

#[test]
fn test_wallet_creation_and_operations() {
    // Create a new wallet
    let mut wallet = Wallet::new_ed25519().expect("Failed to create wallet");
    
    // Test address generation
    let address = wallet.get_address(AddressFormat::Hex).expect("Failed to get address");
    assert!(!address.to_string().is_empty());
    
    // Test signing
    let message = b"Test message";
    let signature = wallet.sign(message).expect("Failed to sign message");
    
    // Verify signature
    assert!(wallet.verify(message, &signature).expect("Failed to verify signature"));
}

#[test]
fn test_keypair_types() {
    // Test Ed25519
    let ed25519_wallet = Wallet::new_ed25519().expect("Failed to create Ed25519 wallet");
    assert_eq!(ed25519_wallet.key_type(), KeyType::Ed25519);
    
    // Test Secp256k1
    let secp256k1_wallet = Wallet::new_secp256k1().expect("Failed to create Secp256k1 wallet");
    assert_eq!(secp256k1_wallet.key_type(), KeyType::Secp256k1);
}

#[test]
fn test_address_formats() {
    let mut wallet = Wallet::new_ed25519().expect("Failed to create wallet");
    
    // Test different address formats
    let hex_address = wallet.get_address(AddressFormat::Hex).expect("Failed to get hex address");
    let base58_address = wallet.get_address(AddressFormat::Base58).expect("Failed to get base58 address");
    let bech32_address = wallet.get_address(AddressFormat::Bech32).expect("Failed to get bech32 address");
    let blake3_address = wallet.get_address(AddressFormat::Blake3).expect("Failed to get blake3 address");
    
    // Ensure all addresses are different (except for the underlying key)
    assert_ne!(hex_address.to_string(), base58_address.to_string());
    assert_ne!(hex_address.to_string(), bech32_address.to_string());
    assert_ne!(hex_address.to_string(), blake3_address.to_string());
}