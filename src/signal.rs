use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

pub type F = GoldilocksField;
pub type Digest = [F; 4];       // Digest is 4 field elements
pub type C = PoseidonGoldilocksConfig;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;   // Plonky2 proof struct with extension 2

#[derive(Debug, Clone)]
// Signal contains a nullifier and a plonky proof
pub struct Signal {
    pub nullifier: Digest,
    pub proof: PlonkyProof,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::field_types::Field;
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    use crate::access_set::AccessSet;
    use crate::signal::{Digest, F};

    #[test]
    fn test_semaphore() -> Result<()> {
        // bitwise left shift op that calculates 2^20=1.048.576, i.e. shift 1 bit 20 times to the left
        let n = 1 << 20;
        
        // generate some private keys ~1000000
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_arr()).collect();
        
        // Derive Pks that consists in the hash of the Sk and some 0s
        // public_keys is a vector of vectors. For each private key we have a public key
        // Every pk is the poseidon hash H(sk, [0,0,0,0]), i.e. padding
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();

        let access_set = AccessSet(MerkleTree::new(public_keys, 0));    // Compute the access set

        let i = 12;                                 // Generate a proof for the 12-th private key
        let topic = F::rand_arr();   // generate a random topic

        let (signal, vd) = access_set.make_signal(private_keys[i], topic, i)?;  // make the signal
        access_set.verify_signal(topic, signal, &vd)           // verify the signal
    }
}
