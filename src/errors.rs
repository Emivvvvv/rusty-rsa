use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("The entered public key is not satisfying the rules. \
            \nA public key must satisfy these three rules\
            \n1- public key must be a prime number\
            \n2- public key must be less than Totient (T)\
            \n3- public key must NOT be a factor of Totient (T)")]
    BadPublicKey,
    #[error("One or all prime numbers are not prime number.")]
    BadPrimeNumber,
    #[error("Something went wrong while generating the prime number.")]
    BadPrimeNumberOnGeneration,
    #[error("Something went wrong while trying to chang private key's type from BigInt to BigUint")]
    ErrorOnPrivateNumberGeneration,
}

#[derive(Error, Debug, PartialEq)]
pub enum MsgError {
    #[error("Can not parse BigUint to generic type T")]
    BadMessage,
}