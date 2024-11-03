use plonky2::field::field_types::Field;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::access_set::AccessSet;
use crate::signal::{Digest, F};

pub struct SemaphoreTargets {
    merkle_root: HashOutTarget,
    topic: [Target; 4],
    merkle_proof: MerkleProofTarget,
    private_key: [Target; 4],
    public_key_index: Target,
}

impl AccessSet {

    // AccessSet is a binary merkle tree with n leaves, where n=2^h
    // Being power of 2, h indicates the height of the tree
    // the binary representation of 2^h will always be a 1000.. ; where 0s indicate the power of 2 (thus h)
    // example: 2^h = 8 -> (binary) 1000 -> h=3
    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn semaphore_circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> SemaphoreTargets {

        // #### 1 - Define virtual targets which are inputs in the circuit gates ####

        // Register public inputs as virtual, i.e. will be instantiated later on
        // 1. Merkle root (is a hash)
        // 2. Nullifier (is a hash)
        // 3. Topic
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        let nullifier = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier.elements);
        let topic: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();    // Tell the circuti to create 4 targets for that purpose and convert Vec<Target> into an array [Target; 4]
        builder.register_public_inputs(&topic);

        // Merkle proof (opening)
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),   //note: add_virtual_hashes returns a Vec<HashOutTarget> because it is an opening
        };

        // Targets needed to verify the Merkle proof.
        let private_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap(); // 4 sk targets
        let public_key_index = builder.add_virtual_target();    // one pk index
        // Need the bits of the index: in the merkle proof verification your hash is on the left/right depending on the bit of the index
        // so you need to split this index into bits to understand lfet/right
        // gadget: split_le (little endindian) takes an integer (public_key_index) and num_bits (in a merkle path is the height)
        // example: 8 leaves, you have index from [0,..7] -> binary from [000, .., 111]
        let public_key_index_bits = builder.split_le(public_key_index, self.tree_height());
        let zero = builder.zero();

        // #### 2 - Define circuit gates and wires

        // Gate 1: Verify the merkle proof

        // 1. leaf_data: private key + 4 zeros concatenated
        // 2. leaf_index_bits: The index bits for that specific leaf
        // 3. merkle_cap: it is the merkle root wrapped in a MerkleCapTarget
        // 4. proof: Merkle proof for that specific leaf wrt root
        builder.verify_merkle_proof::<PoseidonHash>(                //specify hash function
            [private_key, [zero; 4]].concat(),
            &public_key_index_bits,
            &MerkleCapTarget(vec![merkle_root]),
            &merkle_proof,
        );

        // Gate 2: Check nullifier, which is a Digest of size 4.
        // Use the hash_n_to_hash_no_pad gadget that allows hashing any vector of size n without padding
        let should_be_nullifier =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>([private_key, topic].concat()); // it is important to specify which hash function has been used
        
        // Connect wires -- nullifier is Digest of size 4 and should be a nullifier
        for i in 0..4 {
            builder.connect(nullifier.elements[i], should_be_nullifier.elements[i]);
        }

        // Return all these targets
        SemaphoreTargets {
            merkle_root,
            topic,
            merkle_proof,
            private_key,
            public_key_index,
        }
    }

    // Set the partial witness targets
    pub fn fill_semaphore_targets(
        &self,
        pw: &mut PartialWitness<F>,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
        targets: SemaphoreTargets,
    ) {
        let SemaphoreTargets {
            merkle_root,
            topic: topic_target,
            merkle_proof: merkle_proof_target,
            private_key: private_key_target,
            public_key_index: public_key_index_target,
        } = targets;

        // Set the targets 
        pw.set_hash_target(merkle_root, self.0.cap.0[0]);
        pw.set_targets(&private_key_target, &private_key); // private_key is some field elements (Digest 4) and I can set them one-by-one here
        pw.set_targets(&topic_target, &topic);
        pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        );

        let merkle_proof = self.0.prove(public_key_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h);
        }
    }
}
