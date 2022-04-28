use rand::rngs::ThreadRng;
use ibe::kiltz_vahlis_one::{extract_usk, Identity, PublicKey, SecretKey, setup, UserSecretKey};
use rand;

struct PKG {
    pk: PublicKey,
    sk: SecretKey,
    rng: ThreadRng,
}

impl PKG {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let (pk, sk) = setup(&mut rng);
        return PKG { pk, sk, rng };
    }

    fn derive_user_sk(&mut self, identity: &Identity) -> UserSecretKey {
        return extract_usk(&self.pk, &self.sk, identity, &mut self.rng);
    }
}