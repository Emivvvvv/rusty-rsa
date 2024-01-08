use num_bigint::BigUint;
use rusty_rsa::keys::Keys;
use rusty_rsa::messages::{decrypt, encrypt};

#[test]
fn create_key_pair_and_send_message_test() {
    let key_pair = Keys::generate().unwrap();
    let (public_key, private_key) = key_pair.get_keys();

    let cipher = encrypt::<u8>(69, public_key.get_pubk(), public_key.get_product());
    let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
    assert_eq!(Ok(69), encrypted_cipher);
}

#[test]
fn from_key_pair_and_send_message_test() {
    let key_pair = Keys::from(BigUint::from(7u8), BigUint::from(19u8), BigUint::from(29u8)).unwrap();
    let (public_key, private_key) = key_pair.get_keys();

    assert_eq!(public_key.get_pubk(), &BigUint::from(29u8));
    assert_eq!(public_key.get_product(), &BigUint::from(133u8));
    assert_eq!(private_key.get_privk(), &BigUint::from(41u8));

    let cipher = encrypt::<u8>(31u8, public_key.get_pubk(), public_key.get_product());
    let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
    assert_eq!(Ok(31), encrypted_cipher);
}