use anyhow::Result;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::signal::{Digest, Signal, C, F}; // Import constant values from Signal crate

// AccessSet is a wrapper around a merkle tree (the leaves are the Pks)
pub struct AccessSet(pub MerkleTree<F, PoseidonHash>);

impl AccessSet {

    // Verify the signal
    // 1. Compute the public inputs for the proof. It generates a vector of public inputs by collecting elements
    // from different sources. Chained iterator to collect data. The public inputs are:
    // 1.1. Merkle root of the access set (self) -> self.0.cap.0.iter().flat_map(|h| h.elements) extracts the "cap" of the merkle root
    // "cap": holds merkle root data 
    // 1.2. Nullifier (signal.nullifier)
    // 1.3. Topic (topic)
    pub fn verify_signal(
        &self,
        topic: Digest,
        signal: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,   //PLONK artifact to pre-process polynomials; it is a "verifier key" to verify the proof 
    ) -> Result<()> {
        let public_inputs: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal.nullifier)
            .chain(topic)
            .collect();

        // Verify the proof and the public inputs
        verifier_data.verify(ProofWithPublicInputs {
            proof: signal.proof,
            public_inputs,
        })
    }

    // Issue a new signal to the Access Set
    // nullifier = H(sk, topic)
    // signal = nullifier + ZKP
    // ZKP -> I issued a signal with the pk at index i that has been nullified
    pub fn make_signal(
        &self,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
    ) -> Result<(Signal, VerifierCircuitData<F, C, 2>)> {
        
        // nullifier is the hash of a private key and a topic
        let nullifier = PoseidonHash::hash_no_pad(&[private_key, topic].concat()).elements;
        
        // Plonky2 setup
        // 1. Circuit config that allows recursion and zk to hide the secret key
        // 2. Circuit builder: is how you build a circuit in plonky2; all the gadgets in plonky2 are methods of this builder
        // 3. Partial witness: The witness in PLONK is basically a table; you don't have to fill all the wires/cells in the table manually;
        // partial witness will partially fill the table with values and then the proving system will take care of generating the rest of the values
        // using the gadgets; pw will just fill the data needed in the circuit
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        // I want to define a circuit for the semaphore verification to get the ZKP
        let targets = self.semaphore_circuit(&mut builder);
        self.fill_semaphore_targets(&mut pw, private_key, topic, public_key_index, targets);

        // Build the circuit and generate the proof with witness
        let data = builder.build();
        let proof = data.prove(pw)?;

        Ok((
            Signal {
                nullifier,
                proof: proof.proof,
            },
            data.to_verifier_data(),
        ))
    }
}
