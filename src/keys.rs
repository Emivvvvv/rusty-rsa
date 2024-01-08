use glass_pumpkin::prime;
use num_bigint::{BigInt, BigUint};
use crate::errors::KeyError;


// Keys struct
// use Keys::generate() to generate your randomly generated keypair.
// or you can use Keys::from(p_prime, q_prime, pub_k) to create a Keys struct for your key pair.
pub struct Keys {
    public_key: PublicKey,
    private_key: PrivateKey
}

impl Keys {

    // generates a randomly generated pair (exponent is set to 65537 as default)
    pub fn generate() -> Result<Self, KeyError> {
        // p and q are 1024 bit length random prime numbers (secure enough for my basicass rsa implementation)
        let p = prime::new(1024)
            .map_err(|_| KeyError::BadPrimeNumberOnGeneration)?;
        let q = prime::new(1024)
            .map_err(|_| KeyError::BadPrimeNumberOnGeneration)?;

        let product = &p * &q;
        let totient = (p - BigUint::from(1u8)) * (q - BigUint::from(1u8));

        // default public key is 65537. I was generating public key randomly but this is a well tested field used public
        // key so I decided to set this as default
        let public_key = PublicKey::generate(product);
        let private_key = PrivateKey::generate(public_key.get_pubk(), &totient)?;

        Ok(Self {
            public_key,
            private_key,
        })
    }


    // Generates a Keys struct from your given prime numbers and public key (exponent).
    // Returns an Result
    // Checks if your public key is valid or not. If it is not valid returns an error.
    pub fn from(p_prime: BigUint, q_prime: BigUint, pub_k: BigUint) -> Result<Self, KeyError> {

        if !prime::check(&p_prime) || !prime::check(&q_prime) {
            return Err(KeyError::BadPrimeNumber)
        }

        let product = &p_prime * &q_prime;
        let totient = (p_prime - BigUint::from(1u8)) * (q_prime - BigUint::from(1u8));

        let public_key = PublicKey::from(&pub_k, &product, &totient)?;
        let private_key = PrivateKey::generate(&pub_k, &totient)?;

        Ok(
            Self {
            public_key,
            private_key,
        })
    }

    pub fn get_keys(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }

    pub fn get_keys_ref(&self) -> (&PublicKey, &PrivateKey) {
        (&self.public_key, &self.private_key)
    }
}

pub struct PublicKey {
    pub_k: BigUint,
    product: BigUint
}

impl PublicKey {
    fn generate(product: BigUint) -> Self{
        Self {
            pub_k: BigUint::from(65537u32),
            product,
        }
    }

    fn from(pub_k: &BigUint, product: &BigUint, totient: &BigUint) -> Result<Self, KeyError> {
        if Self::check_validity(pub_k, totient) {
            Ok(Self {
                pub_k: pub_k.clone(),
                product: product.clone(),
            })
        } else {
            Err(
                KeyError::BadPublicKey
            )
        }
    }

    // check_validity function checks certain if the current Public key is valid or not
    // if the current key is valid returns true else returns false
    //
    // A public key must satisfy these three rules
    // 1- public key must be a prime number
    // 2- public key must be less than Totient (T)
    // 3- public key must NOT be a factor of Totient (T)
    fn check_validity(public_key: &BigUint, totient: &BigUint) -> bool {
        if !prime::check(public_key) || public_key > totient || totient % public_key == BigUint::from(0u8) {
            return false;
        }
        true
    }

    pub fn get_pubk(&self) -> &BigUint {
        &self.pub_k
    }

    pub fn get_product(&self) -> &BigUint {
        &self.product
    }
}

pub struct PrivateKey {
    private_key: BigUint
}

impl PrivateKey {
    pub fn generate(pub_k: &BigUint, totient: &BigUint) -> Result<Self, KeyError> {
        let i_pub_k = BigInt::from(pub_k.clone());
        let i_totient = BigInt::from(totient.clone());
        let i_private_key = Self::mod_inverse(i_pub_k, i_totient);

        let private_key = BigUint::try_from(i_private_key)
            .map_err(|_|
                KeyError::ErrorOnPrivateNumberGeneration)?;
        Ok(
            Self { private_key }
        )
    }

    pub fn get_privk(&self) -> &BigUint {
        &self.private_key
    }

    fn mod_inverse(a0: BigInt, m0: BigInt) -> BigInt {
        if m0 == BigInt::from(1u8) { return BigInt::from(1u8) }
        let (mut a, mut m, mut x0, mut inv) = (a0, m0.clone(), BigInt::from(0u8), BigInt::from(1u8));
        while a > BigInt::from(1u8) {
            inv -= (&a / &m) * &x0;
            a = &a % &m;
            std::mem::swap(&mut a, &mut m);
            std::mem::swap(&mut x0, &mut inv)
        }
        if inv < BigInt::from(0u8) { inv += m0 }
        inv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_from_test_1() {
        let key_pair = Keys::from(BigUint::from(7u8), BigUint::from(19u8), BigUint::from(29u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        assert_eq!(public_key.get_pubk(), &BigUint::from(29u8));
        assert_eq!(public_key.get_product(), &BigUint::from(133u8));
        assert_eq!(private_key.get_privk(), &BigUint::from(41u8))
    }

    #[test]
    fn keys_from_test_2() {
        let key_pair = Keys::from(BigUint::from(29u8), BigUint::from(23u8), BigUint::from(3u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        assert_eq!(public_key.get_pubk(), &BigUint::from(3u8));
        assert_eq!(public_key.get_product(), &BigUint::from(667u16));
        assert_eq!(private_key.get_privk(), &BigUint::from(411u16))
    }

    #[test]
    fn keys_from_test_3() {
        let key_pair = Keys::from(BigUint::from(37u8), BigUint::from(41u8), BigUint::from(7u8)).unwrap();
        let (public_key, private_key) = key_pair.get_keys();

        assert_eq!(public_key.get_pubk(), &BigUint::from(7u8));
        assert_eq!(public_key.get_product(), &BigUint::from(1517u16));
        assert_eq!(private_key.get_privk(), &BigUint::from(823u16))
    }
}