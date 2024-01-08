use num_bigint::{BigUint};
use crate::errors::MsgError;

// encrypts the message with public key and the product.
// try to use u8 for message.
pub fn encrypt<T>(message: T, public_key: &BigUint, product: &BigUint) -> BigUint
    where BigUint: From<T>
{
    modular_exponentiation(&BigUint::from(message), public_key, product)
}

// encrypts the message with private key and the product.
// try to use u8 for resulting value.
pub fn decrypt<T>(cipher: BigUint, private_key: &BigUint, product: &BigUint) -> Result<T, MsgError>
    where T: TryFrom<BigUint>
{
    let message = modular_exponentiation(&cipher, private_key, product);
    T::try_from(message).map_err(|_| MsgError::BadMessage)
}

fn modular_exponentiation(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exponent = exponent.clone();
    let modulus = modulus.clone();

    if modulus == BigUint::from(1u8) {
        return BigUint::from(0u8);
    }

    let mut result = BigUint::from(1u8);
    base = base % modulus.clone();

    while exponent > BigUint::from(0u8) {
        if exponent.clone() % BigUint::from(2u8) == BigUint::from(1u8) {
            result = (result * base.clone()) % modulus.clone();
        }

        exponent = exponent >> 1;
        base = (base.clone() * base) % modulus.clone();
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::keys::Keys;
    use super::*;

    #[test]
    fn known_key_pair_message_test_u8_1() {
        let key_pair = Keys::from(BigUint::from(7u8), BigUint::from(19u8), BigUint::from(29u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(31u8, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
        assert_eq!(Ok(31), encrypted_cipher);
    }

    #[test]
    fn known_key_pair_message_test_u8_2() {
        let key_pair = Keys::from(BigUint::from(29u8), BigUint::from(23u8), BigUint::from(3u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(69, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
        assert_eq!(Ok(69), encrypted_cipher);
    }

    #[test]
    fn known_key_pair_message_test_u8_3() {
        let key_pair = Keys::from(BigUint::from(37u8), BigUint::from(41u8), BigUint::from(7u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u64>(123, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u64>(cipher, private_key.get_privk(), public_key.get_product());
        assert_eq!(Ok(123), encrypted_cipher);
    }
    #[test]
    fn known_key_pair_message_should_fail_test_u8_1() {
        let key_pair = Keys::from(BigUint::from(29u8), BigUint::from(23u8), BigUint::from(3u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(11, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt(cipher, private_key.get_privk(), public_key.get_product());
        assert_ne!(Ok(22), encrypted_cipher);
    }

    #[test]
    fn new_key_pair_message_test_u8_1() {
        let key_pair = Keys::generate().unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(31, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
        assert_eq!(Ok(31), encrypted_cipher);
    }

    #[test]
    fn new_key_pair_message_test_u8_2() {
        let key_pair = Keys::generate().unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(69, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
        assert_eq!(Ok(69), encrypted_cipher);
    }

    #[test]
    fn new_key_pair_message_should_fail_test_u8_1() {
        let key_pair = Keys::generate().unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        let cipher = encrypt::<u8>(11, public_key.get_pubk(), public_key.get_product());
        let encrypted_cipher = decrypt::<u8>(cipher, private_key.get_privk(), public_key.get_product());
        assert_ne!(Ok(22), encrypted_cipher);
    }
}