use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use argon2::password_hash;
use argon2::password_hash::Salt;
pub use password_hash::PasswordHashString;
use password_hash::SaltString;
use password_hash::errors::Error as PasswordHashError;
use rand::CryptoRng;
use rand::RngCore;
use rand::prelude::ThreadRng;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_with::SerializeDisplay;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const ARGON2_ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
pub const ARGON2_COST_M_KIB: u32 = 96 * 1024;
pub const ARGON2_COST_T: u32 = 23;
pub const ARGON2_COST_P: u32 = 1;

pub const MAX_PASSWORD_LENGTH: usize = 512;
pub const MIN_EXPECTED_PASSWORD_VERIFY_TIME: std::time::Duration =
    std::time::Duration::from_millis(650);

pub fn external_password_argon() -> Argon2<'static> {
    let argon2_params =
        argon2::Params::new(ARGON2_COST_M_KIB, ARGON2_COST_T, ARGON2_COST_P, None).unwrap();

    Argon2::new(ARGON2_ALGORITHM, argon2::Version::default(), argon2_params)
}

#[derive(Clone)]
pub struct Password(secrecy::SecretString);

impl Password {
    pub fn new(password: &str) -> Result<Password, PasswordTooLongError> {
        if password.len() > MAX_PASSWORD_LENGTH {
            Err(PasswordTooLongError)
        } else {
            Ok(Password(secrecy::SecretString::from(password)))
        }
    }
}

#[derive(Error, Debug)]
/// The provided password was too long
#[error("the password provided was too long")]
pub struct PasswordTooLongError;

#[derive(Error, Debug)]
#[error("failed to set password")]
pub struct PasswordSetError(#[from] argon2::password_hash::errors::Error);

#[derive(Error, Debug)]
#[error("failed to verify password")]
pub struct PasswordVerifyError(#[from] argon2::password_hash::errors::Error);

#[derive(Clone, Debug, Deserialize, SerializeDisplay, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct NewPasswordHash(PasswordHashString);

impl fmt::Display for NewPasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl NewPasswordHash {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<NewPasswordHash> for PasswordHashString {
    fn from(value: NewPasswordHash) -> Self {
        value.0
    }
}

impl FromStr for NewPasswordHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NewPasswordHash(parse_phc_hash(s)?))
    }
}

impl TryFrom<String> for NewPasswordHash {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Create and verify stored passwords for local-only Silo users
// This is currently a thin wrapper around `argon2`.  It encapsulates the
// specific key derivation function (KDF) and related policy choices.  It also
// encapsulates the random number generator.  All this helps with testing.
pub struct Hasher<R: CryptoRng + RngCore> {
    argon2: Argon2<'static>,
    rng: R,
}

impl Default for Hasher<ThreadRng> {
    fn default() -> Self {
        Hasher::new(external_password_argon(), rand::rng())
    }
}

impl<R: CryptoRng + RngCore> Hasher<R> {
    pub fn new(argon2: Argon2<'static>, rng: R) -> Self {
        Hasher { argon2, rng }
    }

    pub fn create_password(
        &mut self,
        password: &Password,
    ) -> Result<PasswordHashString, PasswordSetError> {
        let salt = generate_salt_string(&mut self.rng);

        Ok(self
            .argon2
            .hash_password(password.0.expose_secret().as_bytes(), &salt)?
            .serialize())
    }

    pub fn verify_password(
        &self,
        password: &Password,
        hashed: &PasswordHashString,
    ) -> Result<bool, PasswordVerifyError> {
        let parsed = hashed.password_hash();
        match self
            .argon2
            .verify_password(password.0.expose_secret().as_bytes(), &parsed)
        {
            Ok(_) => Ok(true),
            Err(PasswordHashError::Password) => Ok(false),
            Err(error) => Err(PasswordVerifyError(error)),
        }
    }
}

fn generate_salt_string<R>(rng: &mut R) -> SaltString
where
    R: RngCore + CryptoRng,
{
    // Hand-write the code to fill the salt bytes because we're on rand 0.9
    // while password-hash 0.5.0 is on an older version of rand.
    let mut bytes = [0u8; Salt::RECOMMENDED_LENGTH];
    rng.fill_bytes(&mut bytes);
    SaltString::encode_b64(&bytes).expect("salt string invariant violated")
}

/// Parses the given PHC-format password hash string and returns it only if it
/// meets some basic requirements (which match the way we generate password
/// hashes).
fn parse_phc_hash(s: &str) -> Result<PasswordHashString, String> {
    let hash = PasswordHashString::new(s).map_err(|e| format!("password hash: {}", e))?;
    verify_strength(&hash)?;
    Ok(hash)
}

fn verify_strength(hash: &PasswordHashString) -> Result<(), String> {
    if hash.algorithm() != ARGON2_ALGORITHM.ident() {
        return Err(format!(
            "password hash: algorithm: expected {}, found {}",
            ARGON2_ALGORITHM,
            hash.algorithm()
        ));
    }

    match hash.salt() {
        None => return Err("password hash: expected salt".to_string()),
        Some(s) if s.len() < argon2::RECOMMENDED_SALT_LEN => {
            return Err(format!(
                "password hash: salt: expected at least {} bytes",
                argon2::RECOMMENDED_SALT_LEN
            ));
        }
        _ => (),
    };

    match hash.hash() {
        None => return Err("password hash: expected hash".to_string()),
        Some(s) if s.len() < argon2::Params::DEFAULT_OUTPUT_LEN => {
            return Err(format!(
                "password hash: output: expected at least {} bytes",
                argon2::Params::DEFAULT_OUTPUT_LEN
            ));
        }
        _ => (),
    };

    let params = argon2::Params::try_from(&hash.password_hash())
        .map_err(|e| format!("password hash: argon2 parameters: {}", e))?;
    if params.m_cost() < ARGON2_COST_M_KIB {
        return Err(format!(
            "password hash: parameter 'm': expected at least {} (KiB), \
            found {}",
            ARGON2_COST_M_KIB,
            params.m_cost()
        ));
    }

    if params.t_cost() < ARGON2_COST_T {
        return Err(format!(
            "password hash: parameter 't': expected at least {}, found {}",
            ARGON2_COST_T,
            params.t_cost()
        ));
    }

    if params.p_cost() < ARGON2_COST_P {
        return Err(format!(
            "password hash: parameter 'p': expected at least {}, found {}",
            ARGON2_COST_P,
            params.p_cost()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::ARGON2_COST_M_KIB;
    use super::ARGON2_COST_P;
    use super::ARGON2_COST_T;
    use super::Hasher;
    use super::MAX_PASSWORD_LENGTH;
    use super::MIN_EXPECTED_PASSWORD_VERIFY_TIME;
    use super::Password;
    use super::PasswordTooLongError;
    use super::external_password_argon;
    use super::generate_salt_string;
    use super::parse_phc_hash;
    use super::verify_strength;
    use argon2::password_hash::PasswordHashString;
    use rand::SeedableRng;

    // A well-known password.
    const PASSWORD_STR: &str = "hunter2";
    const BAD_PASSWORD_STR: &str = "hunter";

    #[test]
    fn test_password_constraints() {
        // See the note on MAX_PASSWORD_LENGTH above.  We're not trying to
        // enforce security policy here.
        let _ = Password::new("").unwrap();
        let _ = Password::new(PASSWORD_STR).unwrap();
        let _ = Password::new(&"o".repeat(MAX_PASSWORD_LENGTH)).unwrap();
        assert!(matches!(
            Password::new(&"o".repeat(MAX_PASSWORD_LENGTH + 1)),
            Err(PasswordTooLongError)
        ));
    }

    // Various smoke tests.
    //
    // Some of these are basically testing the underlying crate.  But it's
    // important enough that it's worth smoke testing both the crate and our own
    // understanding.
    #[test]
    fn test_smoke() {
        // Hash a well-known password.
        let mut hasher = Hasher::default();
        let password = Password::new(PASSWORD_STR).unwrap();
        let bad_password = Password::new(BAD_PASSWORD_STR).unwrap();
        let hash_str = hasher.create_password(&password).unwrap();
        let hash = hash_str.password_hash();
        println!("example password: {}", PASSWORD_STR);
        println!("hashed:           {}", hash_str);
        println!("structured hash:  {:?}", hash);

        // Verify that the generated hash matches our own requirements.
        verify_strength(&hash_str).unwrap();

        // Verify that salt strings are at least as long as we think they are
        // (16 bytes).
        assert!(generate_salt_string(&mut rand::rng()).len() >= 16);

        // Verify that the output length produced by this crate hasn't changed
        // unexpectedly.  It may not be a big deal if this does change, but we
        // may need to adjust how we store these.
        //
        // The hash string length here (128 bytes) is a generous round-up of an
        // example hash output (96 bytes).  This is more than enough to support
        // slightly longer (but still supportable) parameter values.
        assert_eq!(hash.hash.unwrap().as_bytes().len(), 32);
        assert!(hash_str.len() < 128);

        // Verify expected properties of the chosen hash.
        // "m", "t", and "p" are parameters to the Argon2 KDF.  See above.
        assert_eq!(hash.algorithm, argon2::ARGON2ID_IDENT);
        assert_eq!(hash.version, Some(argon2::Version::V0x13.into()));
        assert_eq!(hash.params.get_decimal("m").unwrap(), ARGON2_COST_M_KIB);
        assert_eq!(hash.params.get_decimal("t").unwrap(), ARGON2_COST_T);
        assert_eq!(hash.params.get_decimal("p").unwrap(), ARGON2_COST_P);

        // The correct password should verify correctly.  Small variations
        // obviously should not.  Edge conditions should not produce unexpected
        // errors.
        let start = std::time::Instant::now();
        assert!(hasher.verify_password(&password, &hash_str).unwrap());
        assert!(!hasher.verify_password(&bad_password, &hash_str).unwrap());
        let time_elapsed = start.elapsed();
        assert!(
            !hasher
                .verify_password(&Password::new("hunter22").unwrap(), &hash_str)
                .unwrap()
        );
        assert!(
            !hasher
                .verify_password(&Password::new("").unwrap(), &hash_str)
                .unwrap()
        );
        assert!(
            !hasher
                .verify_password(&Password::new(&"o".repeat(512)).unwrap(), &hash_str)
                .unwrap()
        );

        // Verifies that password hash verification takes as long as we think it
        // does.  As of this writing, it's calibrated to take at least one
        // second on the class of hardware that we intend to run.  Parameters
        // will need to be adjusted in the future to ensure this continues to be
        // the case with newer generations of hardware.  We only take one sample
        // because we're only trying to establish a lower bound.  This might
        // result in false negatives (not the end of the world), but it
        // shouldn't result in false positives.
        println!("elapsed time for two verifications: {:?}", time_elapsed);
        if time_elapsed < 2 * MIN_EXPECTED_PASSWORD_VERIFY_TIME {
            panic!(
                "password verification was too fast (took {:?} for two \
                verifications, expected at least {:?} for one)",
                time_elapsed, MIN_EXPECTED_PASSWORD_VERIFY_TIME
            );
        }

        // If we hash the same password again, we should get a different string
        // (because of the random salt).  It should behave the same way.
        let hash_str2 = hasher.create_password(&password).unwrap();
        assert_ne!(hash_str, hash_str2);
        assert!(hasher.verify_password(&password, &hash_str2).unwrap());
        assert!(!hasher.verify_password(&bad_password, &hash_str2).unwrap());
        verify_strength(&hash_str2).unwrap();

        // If we create a new hasher and hash the same password, we should also
        // get a different string.  It should behave the same way.
        let mut hasher2 = Hasher::default();
        let hash_str3 = hasher2.create_password(&password).unwrap();
        assert_ne!(hash_str, hash_str3);
        assert_ne!(hash_str2, hash_str3);
        assert!(hasher.verify_password(&password, &hash_str2).unwrap());
        assert!(!hasher.verify_password(&bad_password, &hash_str2).unwrap());
        verify_strength(&hash_str3).unwrap();
    }

    #[test]
    fn test_reproducible() {
        // If we seed a known random number generator with a known value, we
        // should get back a known hash.
        let password = Password::new(PASSWORD_STR).unwrap();
        let known_seed = [0; 32];
        let known_rng = rand::rngs::StdRng::from_seed(known_seed);
        let hash1 = {
            let mut hasher = Hasher::new(external_password_argon(), known_rng.clone());
            hasher.create_password(&password).unwrap()
        };
        verify_strength(&hash1).unwrap();
        let hash2 = {
            let mut hasher = Hasher::new(external_password_argon(), known_rng);
            hasher.create_password(&password).unwrap()
        };
        assert_eq!(hash1, hash2);
        verify_strength(&hash2).unwrap();
    }

    // Verifies that known password hashes continue to verify as we expect.
    // This exercises the case where we've stored hashes in the database
    // (potentially with a much older version of this software with a different
    // implementation).  This ensures that those hashes continue to work.
    //
    // Do NOT replace the hardcoded hashes here with code that generates
    // equivalent ones -- that defeats the point!
    #[test]
    fn test_stable() {
        struct TestCase {
            password: &'static str,
            hash: &'static str,
        }

        let bad_password = Password::new("arglebargle").unwrap();
        let test_cases = vec![
            // This example was generated by test code above.
            TestCase {
                password: "hunter2",
                hash: "$argon2id$v=19$m=4096,t=3,p=1$e1Pt0O1JJk2zaeopxjn3wA\
                    $dIsKqkXJWe+SjWgh8o9Cfx3upYw74VBqV2TgEa0HLXM",
            },
            // This example was generated by the argon2.online online generator.
            // It uses a shorter hash length than we normally do.
            TestCase {
                password: "foofaraw",
                hash: "$argon2id$v=19$m=16,t=2,p=1$M0FTbEJLcnBpeVIxaFVZNA\
                $pBecT2oR4m5T9UK0CgPgmA",
            },
            // This example was generated by the argon2.online online generator.
            // It uses a different algorithm and parallelism factor.
            TestCase {
                password: "foofaraw",
                hash: "$argon2i$v=19$m=32,t=2,p=2$M0FTbEJLcnBpeVIxaFVZNA\
                $4dZ7Y53EeLVFmxrujKHeGFsh21C4Wq5aop1BvxMHWSQ",
            },
        ];

        let hasher = Hasher::default();
        for t in test_cases {
            println!("testing password {:?} with hash {:?}", t.password, t.hash);
            let password = Password::new(t.password).unwrap();
            let hash = PasswordHashString::new(t.hash).unwrap();
            assert!(hasher.verify_password(&password, &hash).unwrap());
            assert!(!hasher.verify_password(&bad_password, &hash).unwrap());
        }
    }

    // Verifies that the implementation of argon2 that we're using is compatible
    // with at least one other implementation.  This might seem paranoid and may
    // indeed be excessive.  But similar things have happened and they've been
    // rather painful to deal with.  Since this check seems cheap to do, we go
    // ahead and do it.
    #[test]
    fn test_compatible() {
        let mut hasher = Hasher::default();

        // First, verify that a password that we hash can be verified with the
        // alternate implementation.  It shouldn't matter what the algorithm or
        // parameters are because that's encoded in the hash string.
        let password = Password::new(PASSWORD_STR).unwrap();
        let password_hash_str = hasher.create_password(&password).unwrap();
        verify_strength(&password_hash_str).unwrap();
        assert!(
            argon2alt::verify_encoded(password_hash_str.as_ref(), PASSWORD_STR.as_bytes()).unwrap()
        );

        // Now, verify that a password hashed with the alternate implementation
        // can be verified with ours.
        let salt = b"randomsalt";
        let alt_hashed = argon2alt::hash_encoded(
            BAD_PASSWORD_STR.as_bytes(),
            salt,
            &argon2alt::Config::default(),
        )
        .unwrap();
        assert!(
            hasher
                .verify_password(
                    &Password::new(BAD_PASSWORD_STR).unwrap(),
                    &PasswordHashString::new(&alt_hashed).unwrap()
                )
                .unwrap()
        );

        // This isn't really necessary, but again, since this is easy to do:
        // check that the two implementations produce the exact same result
        // given the same input.  They should.
        let password_hash = password_hash_str.password_hash();
        let password_bytes = PASSWORD_STR.as_bytes();
        let mut salt_buffer = [0; 32];
        let salt_bytes = password_hash
            .salt
            .unwrap()
            .decode_b64(&mut salt_buffer)
            .unwrap();
        let config = argon2alt::Config {
            variant: argon2alt::Variant::Argon2id,
            version: argon2alt::Version::Version13,
            mem_cost: ARGON2_COST_M_KIB,
            time_cost: ARGON2_COST_T,
            lanes: ARGON2_COST_P,
            secret: &[],
            ad: &[],
            hash_length: 32,
        };
        let alt_hash = argon2alt::hash_encoded(password_bytes, salt_bytes, &config).unwrap();
        assert_eq!(alt_hash, password_hash_str.to_string());
    }

    #[test]
    fn test_weak_hashes() {
        assert_eq!(
            parse_phc_hash("dummy").unwrap_err(),
            "password hash: password hash string missing field"
        );
        // This input was generated via `cargo run --example argon2 -- --input ""`.
        let _ = parse_phc_hash(
            "$argon2id$v=19$m=98304,t=23,\
             p=1$E4DE+f6Yduuy0nSubo5qtg$57JDYGov3SZoEZnLyZZBHOACH95s\
             8aOpG22zBoWZ2S4",
        )
        .unwrap();

        // The following inputs were constructed by taking the valid hash above
        // and adjusting the string by hand.
        assert_eq!(
            parse_phc_hash(
                "$argon2i$v=19$m=98304,t=23,\
                 p=1$E4DE+f6Yduuy0nSubo5qtg$57JDYGov3SZoEZnLyZZBHOACH95s\
                 8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            "password hash: algorithm: expected argon2id, found argon2i"
        );
        assert_eq!(
            parse_phc_hash(
                "$argon2id$v=19$m=98304,t=23,p=1$\
                 $57JDYGov3SZoEZnLyZZBHOACH95s8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            // sic
            "password hash: salt invalid: value to short",
        );
        assert_eq!(
            parse_phc_hash(
                "$argon2id$v=19$m=98304,t=23,p=1$E4DE+f6Ydu$\
                 57JDYGov3SZoEZnLyZZBHOACH95s8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            "password hash: salt: expected at least 16 bytes",
        );
        assert_eq!(
            parse_phc_hash(
                "$argon2id$v=19$m=4096,t=23,\
                 p=1$E4DE+f6Yduuy0nSubo5qtg$57JDYGov3SZoEZnLyZZBHOACH95s\
                 8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            "password hash: parameter 'm': expected at least 98304 (KiB), \
            found 4096"
        );
        assert_eq!(
            parse_phc_hash(
                "$argon2id$v=19$m=98304,t=22,\
                 p=1$E4DE+f6Yduuy0nSubo5qtg$57JDYGov3SZoEZnLyZZBHOACH95s\
                 8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            "password hash: parameter 't': expected at least 23, found 22"
        );
        assert_eq!(
            parse_phc_hash(
                "$argon2id$v=19$m=98304,t=23,\
                 p=0$E4DE+f6Yduuy0nSubo5qtg$57JDYGov3SZoEZnLyZZBHOACH95s\
                 8aOpG22zBoWZ2S4",
            )
            .unwrap_err(),
            // sic
            "password hash: argon2 parameters: invalid parameter value: \
            value to short"
        );
    }
}
