/// The minimum length of a password to be considered valid.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// The maximum length of a password to be considered valid.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// A value from `[0-4]`, as per [`zxcvbn::Entropy::score()`].
#[cfg(feature = "zxcvbn")]
pub const MIN_PASSWORD_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

macro_rules! define_algorithms {
    ($algorith0_type:ty: $algorithm0:expr, $($algorithm:expr,)*) => {
        mod algo {
            use std::sync::OnceLock;

            use password_hash::{PasswordVerifier, PasswordHasher};

            use crate::hash_utils::HasherRef;

            type Hasher = $algorith0_type;

            struct Algorithms {
                generate: HasherRef<Hasher>,
                verify: Box<[&'static (dyn PasswordVerifier + Sync)]>,
            }

            static ALGORITHMS: OnceLock<Algorithms> = OnceLock::new();

            fn leak<T>(t: T) -> &'static T {
                Box::leak(Box::new(t))
            }

            fn algorithms_init() -> Algorithms {
                let algo0 = leak($algorithm0);
                let algos = Box::new([
                    algo0 as &'static (dyn PasswordVerifier + Sync),
                    $(leak($algorithm) as &'static (dyn PasswordVerifier + Sync)),*
                ]);
                Algorithms {
                    generate: HasherRef(algo0),
                    verify: algos,
                }
            }

            pub fn algorithms_verify() -> &'static [&'static (dyn PasswordVerifier + Sync)] {
                &*ALGORITHMS.get_or_init(algorithms_init).verify
            }

            pub fn algorithm_generate() -> impl PasswordHasher {
                ALGORITHMS.get_or_init(algorithms_init).generate
            }
        }

        use algo::{algorithms_verify, algorithm_generate};
    }
}

define_algorithms![
    argon2::Argon2<'static>: argon2::Argon2::default(),
];

fn generate_salt() -> password_hash::SaltString {
    let mut rng = rand::thread_rng();
    password_hash::SaltString::generate(&mut rng)
}

/// A compile-time token to prove authentication.
#[derive(Debug)]
pub struct Authenticated(());

/// The reason a password is considered invalid.
#[derive(Clone, Debug)]
pub enum BadPassword {
    /// The password is too short.
    TooShort,
    /// The password is too long.
    TooLong,
    /// The password is too weak.
    #[cfg(feature = "zxcvbn")]
    Weak(zxcvbn::Entropy),
}

/// A password that has been validated.
pub struct ValidPassword(String);

impl ValidPassword {
    /// Validate a password.
    pub async fn new(
        password: String,
        fields: &[&str],
    ) -> Result<Self, BadPassword> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(BadPassword::TooShort);
        }
        if password.len() > MAX_PASSWORD_LENGTH {
            return Err(BadPassword::TooLong);
        }
        #[cfg(feature = "zxcvbn")]
        {
            let entropy = zxcvbn::zxcvbn(&password, fields);
            if entropy.score() < MIN_PASSWORD_SCORE {
                return Err(BadPassword::Weak(entropy));
            }
        }
        #[cfg(not(feature = "zxcvbn"))]
        let _ = fields; // Avoid unused variable warning.
        Ok(Self(password))
    }
}

/// A password that has been hashed.
pub struct HashedPassword(password_hash::PasswordHashString);

impl HashedPassword {
    /// Create a new hashed password.
    pub fn new(password: &ValidPassword) -> Self {
        let salt = generate_salt();
        let algo = algorithm_generate();
        Self(
            password_hash::PasswordHash::generate(algo, &password.0, &salt)
                .unwrap()
                .serialize(),
        )
    }

    /// Verify a password against a hashed password.
    ///
    /// This functions returns a compile-time token to prove authentication.
    /// If the password is invalid, this returns `None`.
    pub fn verify(&self, password: &str) -> Option<Authenticated> {
        let hash = self.0.password_hash();
        for algo in algorithms_verify() {
            if algo.verify_password(password.as_ref(), &hash).is_ok() {
                return Some(Authenticated(()));
            }
        }
        None
    }

    /// Get the hashed password as a string.
    ///
    /// Be careful not to leak this value in logs or other places.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::str::FromStr for HashedPassword {
    type Err = password_hash::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl std::fmt::Debug for ValidPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValidPassword([...])")
    }
}

impl std::fmt::Debug for HashedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HashedPassword([...])")
    }
}
