use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;
use anyhow::{Ok, Result};
use plonky2::field::field_types::Field;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::time::Instant;

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

fn main() -> Result<()> {
    use plonky2_semaphore::access_set::AccessSet;
    use plonky2_semaphore::signal::{Digest, F};

    // bitwise left shift op that calculates 2^20=1.048.576, i.e. shift 1 bit 20 times to the left
    let n = 1 << 20;
        
    // generate some private keys ~1000000
    // A sk is a vector of 4 field elements [a, b , c, d]
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

    // Print the digest in a readable format
    println!("private key[0]: {:?}", private_keys.get(0));
    println!("public key[0]: {:?}", public_keys.get(0));

    // Access Set is a Merkle tree with public_keys as leaves
    // leaves must be a Vec<Vec<F>>
    let access_set = AccessSet(MerkleTree::new(public_keys, 0));

    // Prove that the 12-th private key is in the tree
    let i = 12;
    let topic: [F; 4] = F::rand_arr();   // generate a random topic

    println!("topic: {:?}", topic);

    // Prover: make the signal and the verifier circuit data
    let now = Instant::now();
    let (signal, vd) = access_set.make_signal(private_keys[i], topic, i)?;
    let time_prove = now.elapsed();

    // Verifier: verify the signal
    // Proof: "I show you that PK=12 have voted for this topic given the nullifier you have"
    let now = Instant::now();
    access_set.verify_signal(topic, signal, &vd).unwrap();
    let time_verify = now.elapsed();
    
    println!(
        "time_prove={time_prove:?} time_verify={time_verify:?}"
    );

    Ok(())
}