use num_bigint_dig::{BigUint, ModInverse, RandBigInt};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{Error, Result};

#[derive(Debug, Clone, Default, Zeroize)]
pub struct RsaPrivateKey {
    pub p: BigUint,
    pub q: BigUint,
    pub d: BigUint,
    pub u: BigUint,
    e: BigUint,
}

impl RsaPrivateKey {
    pub fn from_mpi_bytes(data: &[u8]) -> Result<Self> {
        let (p, data) = get_mpi(data)?;
        let (q, data) = get_mpi(data)?;
        let (d, data) = get_mpi(data)?;
        let (u, data) = get_mpi(data)?;
        let one = BigUint::from(1u8);
        let p = BigUint::from_bytes_be(p);
        let q = BigUint::from_bytes_be(q);
        let d = BigUint::from_bytes_be(d);
        let u = BigUint::from_bytes_be(u);

        if p <= BigUint::from(2u8)
            || q <= BigUint::from(2u8)
            || p == q
            || d == BigUint::from(0u8)
            || u == BigUint::from(0u8)
            || u >= q
        {
            return Err(Error::InvalidRsaPrivateKeyFormat);
        }
        if data.len() >= 16 {
            return Err(Error::InvalidRsaPrivateKeyFormat);
        }

        let phi = (&p - &one) * (&q - &one);
        let e = d
            .clone()
            .mod_inverse(&phi)
            .and_then(|e| e.to_biguint())
            .filter(|e| e > &one)
            .ok_or(Error::InvalidRsaPrivateKeyFormat)?;

        Ok(Self { p, q, d, u, e })
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(Error::InvalidRsaInput);
        }

        let m = BigUint::from_bytes_be(data);
        let modulus = &self.p * &self.q;
        if m >= modulus {
            return Err(Error::InvalidRsaInput);
        }

        let plaintext = decrypt_rsa_blinded(&m, &self.p, &self.q, &self.d, &self.u, &self.e)
            .ok_or(Error::InvalidRsaInput)?;
        Ok(plaintext.to_bytes_be())
    }
}

/// Extracts the bytes (in BE order) of the MPI-formatted number, along with the rest of the data.
pub(crate) fn get_mpi(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let &[fst, snd, ref data @ ..] = data else {
        return Err(Error::InvalidRsaPrivateKeyFormat);
    };
    let len = (usize::from(fst) * 256 + usize::from(snd) + 7) >> 3;
    if len > data.len() {
        return Err(Error::InvalidRsaPrivateKeyFormat);
    }
    Ok(data.split_at(len))
}

pub(crate) fn decrypt_rsa(
    m: &BigUint,
    p: &BigUint,
    q: &BigUint,
    d: &BigUint,
    u: &BigUint,
) -> BigUint {
    let one = BigUint::from(1u8);
    let xp = (m % p).modpow(&(d % (p - &one)), p);
    let xq = (m % q).modpow(&(d % (q - &one)), q);
    let t = if xq >= xp {
        (&xq - &xp) * u % q
    } else {
        q - (((&xp - &xq) * u) % q)
    };
    t * p + xp
}

fn decrypt_rsa_blinded(
    m: &BigUint,
    p: &BigUint,
    q: &BigUint,
    d: &BigUint,
    u: &BigUint,
    e: &BigUint,
) -> Option<BigUint> {
    let modulus = p * q;
    let two = BigUint::from(2u8);
    let mut rng = OsRng;
    let (r, r_inverse) = loop {
        let r = rng.gen_biguint_range(&two, &modulus);
        let Some(r_inverse) = r
            .clone()
            .mod_inverse(&modulus)
            .and_then(|value| value.to_biguint())
        else {
            continue;
        };
        break (r, r_inverse);
    };

    // The exponentiation with the private exponent remains variable-time, but
    // blinding makes its input independent of the attacker-controlled
    // ciphertext and masks timing variation from the private key.
    let blinded = (m * r.modpow(e, &modulus)) % &modulus;
    let blinded_plaintext = decrypt_rsa(&blinded, p, q, d, u);
    Some((blinded_plaintext * r_inverse) % modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crt_decrypt_matches_direct_modpow() {
        let p = BigUint::from(61u8);
        let q = BigUint::from(53u8);
        let d = BigUint::from(2753u16);
        let u = BigUint::from(20u8);
        let ciphertext = BigUint::from(2790u16);
        let direct = ciphertext.modpow(&d, &(&p * &q));

        assert_eq!(decrypt_rsa(&ciphertext, &p, &q, &d, &u), direct);
    }

    fn mpi_bytes(value: &[u8]) -> Vec<u8> {
        let bit_len = (value.len() * 8) as u16;
        let mut bytes = bit_len.to_be_bytes().to_vec();
        bytes.extend_from_slice(value);
        bytes
    }

    #[test]
    fn private_key_allows_zero_padding_after_mpis() {
        let mut bytes = Vec::new();
        bytes.extend(mpi_bytes(&[61]));
        bytes.extend(mpi_bytes(&[53]));
        bytes.extend(mpi_bytes(&[0x0a, 0xc1]));
        bytes.extend(mpi_bytes(&[20]));
        bytes.extend([0, 0, 0]);

        let key = RsaPrivateKey::from_mpi_bytes(&bytes).unwrap();

        assert_eq!(key.p, BigUint::from(61u8));
        assert_eq!(key.q, BigUint::from(53u8));
        assert_eq!(key.d, BigUint::from(2753u16));
        assert_eq!(key.u, BigUint::from(20u8));
        assert_eq!(key.e, BigUint::from(17u8));
    }

    #[test]
    fn private_key_allows_partial_block_padding_after_mpis() {
        let mut bytes = Vec::new();
        bytes.extend(mpi_bytes(&[61]));
        bytes.extend(mpi_bytes(&[53]));
        bytes.extend(mpi_bytes(&[0x0a, 0xc1]));
        bytes.extend(mpi_bytes(&[20]));
        bytes.extend([0, 1]);

        let key = RsaPrivateKey::from_mpi_bytes(&bytes).unwrap();

        assert_eq!(key.u, BigUint::from(20u8));
    }

    #[test]
    fn private_key_rejects_extra_trailing_block() {
        let mut bytes = Vec::new();
        bytes.extend(mpi_bytes(&[61]));
        bytes.extend(mpi_bytes(&[53]));
        bytes.extend(mpi_bytes(&[0x0a, 0xc1]));
        bytes.extend(mpi_bytes(&[20]));
        bytes.extend([0xff; 16]);

        let err = RsaPrivateKey::from_mpi_bytes(&bytes).unwrap_err();

        assert!(matches!(err, Error::InvalidRsaPrivateKeyFormat));
    }

    #[test]
    fn private_key_rejects_invalid_components() {
        let mut bytes = Vec::new();
        bytes.extend(mpi_bytes(&[1]));
        bytes.extend(mpi_bytes(&[53]));
        bytes.extend(mpi_bytes(&[0x0a, 0xc1]));
        bytes.extend(mpi_bytes(&[20]));

        let err = RsaPrivateKey::from_mpi_bytes(&bytes).unwrap_err();

        assert!(matches!(err, Error::InvalidRsaPrivateKeyFormat));
    }

    #[test]
    fn decrypt_rejects_empty_or_out_of_range_ciphertext() {
        let key = RsaPrivateKey {
            p: BigUint::from(61u8),
            q: BigUint::from(53u8),
            d: BigUint::from(2753u16),
            u: BigUint::from(20u8),
            e: BigUint::from(17u8),
        };

        assert!(matches!(key.decrypt(&[]), Err(Error::InvalidRsaInput)));
        assert!(matches!(
            key.decrypt(&(61u16 * 53).to_be_bytes()),
            Err(Error::InvalidRsaInput)
        ));
    }

    #[test]
    fn blinded_decrypt_matches_rsa_plaintext() {
        let key = RsaPrivateKey {
            p: BigUint::from(61u8),
            q: BigUint::from(53u8),
            d: BigUint::from(2753u16),
            u: BigUint::from(20u8),
            e: BigUint::from(17u8),
        };

        for _ in 0..16 {
            assert_eq!(key.decrypt(&2557u16.to_be_bytes()).unwrap(), [42]);
        }
    }
}
