use crate::ahp::indexer::*;
use crate::ahp::prover::ProverMsg;
use crate::Vec;
use core::marker::PhantomData;
use poly_commit::{BatchLCProof, PolynomialCommitment};
use snarkos_models::{curves::PrimeField, gadgets::r1cs::ConstraintSynthesizer};
use snarkos_utilities::bytes::{FromBytes, ToBytes};
use std::io;

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// The universal public parameters for the argument system.
pub type UniversalSRS<F, PC> = <PC as PolynomialCommitment<F>>::UniversalParams;

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// Verification key for a specific index (i.e., R1CS matrices).
pub struct IndexVerifierKey<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>>
{
    /// Stores information about the size of the index, as well as its field of
    /// definition.
    pub index_info: IndexInfo<F, C>,
    /// Commitments to the indexed polynomials.
    pub index_comms: Vec<PC::Commitment>,
    /// The verifier key for this index, trimmed from the universal SRS.
    pub verifier_key: PC::VerifierKey,
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> FromBytes
    for IndexVerifierKey<F, PC, C>
{
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let index_info = IndexInfo::<F, C>::read(&mut reader)?;
        let index_comms_len = u64::read(&mut reader)?;
        let index_comms = (0..index_comms_len)
            .map(|_| PC::Commitment::read(&mut reader))
            .collect::<io::Result<Vec<_>>>()?;
        let verifier_key = PC::VerifierKey::read(&mut reader)?;
        Ok(Self {
            index_info,
            index_comms,
            verifier_key,
        })
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> ToBytes
    for IndexVerifierKey<F, PC, C>
{
    fn write<W: io::Write>(&self, mut w: W) -> io::Result<()> {
        self.index_info.write(&mut w)?;
        (self.index_comms.len() as u64).write(&mut w)?;
        self.index_comms.write(&mut w)?;
        self.verifier_key.write(&mut w)
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Default
    for IndexVerifierKey<F, PC, C>
{
    fn default() -> Self {
        unimplemented!();
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Clone
    for IndexVerifierKey<F, PC, C>
{
    fn clone(&self) -> Self {
        Self {
            index_comms: self.index_comms.clone(),
            index_info: self.index_info.clone(),
            verifier_key: self.verifier_key.clone(),
        }
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>>
    IndexVerifierKey<F, PC, C>
{
    /// Iterate over the commitments to indexed polynomials in `self`.
    pub fn iter(&self) -> impl Iterator<Item = &PC::Commitment> {
        self.index_comms.iter()
    }
}

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// Proving key for a specific index (i.e., R1CS matrices).
pub struct IndexProverKey<
    'a,
    F: PrimeField,
    PC: PolynomialCommitment<F>,
    C: ConstraintSynthesizer<F>,
> {
    /// The index verifier key.
    pub index_vk: IndexVerifierKey<F, PC, C>,
    /// The randomness for the index polynomial commitments.
    pub index_comm_rands: Vec<PC::Randomness>,
    /// The index itself.
    pub index: Index<'a, F, C>,
    /// The committer key for this index, trimmed from the universal SRS.
    pub committer_key: PC::CommitterKey,
}

impl<'a, F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Clone
    for IndexProverKey<'a, F, PC, C>
where
    PC::Commitment: Clone,
{
    fn clone(&self) -> Self {
        Self {
            index_vk: self.index_vk.clone(),
            index_comm_rands: self.index_comm_rands.clone(),
            index: self.index.clone(),
            committer_key: self.committer_key.clone(),
        }
    }
}

impl<'a, F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> FromBytes
    for IndexProverKey<'a, F, PC, C>
{
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let index_vk = IndexVerifierKey::<F, PC, C>::read(&mut reader)?;
        let index_comm_rands = Vec::<PC::Randomness>::read(&mut reader)?;
        let index = Index::<'a, F, C>::read(&mut reader)?;
        let committer_key = PC::CommitterKey::read(&mut reader)?;
        Ok(Self {
            index_vk,
            index_comm_rands,
            index,
            committer_key,
        })
    }
}

impl<'a, F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> ToBytes
    for IndexProverKey<'a, F, PC, C>
{
    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.index_vk.write(&mut writer)?;
        self.index_comm_rands.write(&mut writer)?;
        self.index.write(&mut writer)?;
        self.committer_key.write(&mut writer)
    }
}

impl<'a, F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Default
    for IndexProverKey<'a, F, PC, C>
{
    fn default() -> Self {
        unimplemented!();
    }
}

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// A zkSNARK proof.
pub struct Proof<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> {
    /// Commitments to the polynomials produced by the AHP prover.
    pub commitments: Vec<Vec<PC::Commitment>>,
    /// Evaluations of these polynomials.
    pub evaluations: Vec<F>,
    /// The field elements sent by the prover.
    pub prover_messages: Vec<ProverMsg<F>>,
    /// An evaluation proof from the polynomial commitment.
    pub pc_proof: BatchLCProof<F, PC>,
    #[doc(hidden)]
    constraint_system: PhantomData<C>,
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Clone
    for Proof<F, PC, C>
{
    fn clone(&self) -> Self {
        Proof::<F, PC, C> {
            commitments: self.commitments.clone(),
            evaluations: self.evaluations.clone(),
            prover_messages: self.prover_messages.clone(),
            pc_proof: self.pc_proof.clone(),
            constraint_system: PhantomData,
        }
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> std::fmt::Debug
    for Proof<F, PC, C>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof").finish()
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Proof<F, PC, C> {
    /// Construct a new proof.
    pub fn new(
        commitments: Vec<Vec<PC::Commitment>>,
        evaluations: Vec<F>,
        prover_messages: Vec<ProverMsg<F>>,
        pc_proof: BatchLCProof<F, PC>,
    ) -> Self {
        Self {
            commitments,
            evaluations,
            prover_messages,
            pc_proof,
            constraint_system: PhantomData,
        }
    }

    /// Prints information about the size of the proof.
    pub fn print_size_info(&self) {
        use poly_commit::{PCCommitment, PCProof};

        let size_of_fe_in_bytes = F::zero().into_repr().as_ref().len() * 8;
        let mut num_comms_without_degree_bounds = 0;
        let mut num_comms_with_degree_bounds = 0;
        let mut size_bytes_comms_without_degree_bounds = 0;
        let mut size_bytes_comms_with_degree_bounds = 0;
        let mut size_bytes_proofs = 0;
        for c in self.commitments.iter().flat_map(|c| c) {
            if !c.has_degree_bound() {
                num_comms_without_degree_bounds += 1;
                size_bytes_comms_without_degree_bounds += c.size_in_bytes();
            } else {
                num_comms_with_degree_bounds += 1;
                size_bytes_comms_with_degree_bounds += c.size_in_bytes();
            }
        }

        let proofs: Vec<PC::Proof> = self.pc_proof.proof.clone().into();
        let num_proofs = proofs.len();
        for proof in &proofs {
            size_bytes_proofs += proof.size_in_bytes();
        }

        let num_evals = self.evaluations.len();
        let evals_size_in_bytes = num_evals * size_of_fe_in_bytes;
        let num_prover_messages: usize = self
            .prover_messages
            .iter()
            .map(|v| v.field_elements.len())
            .sum();
        let prover_msg_size_in_bytes = num_prover_messages * size_of_fe_in_bytes;
        let arg_size = size_bytes_comms_with_degree_bounds
            + size_bytes_comms_without_degree_bounds
            + size_bytes_proofs
            + prover_msg_size_in_bytes
            + evals_size_in_bytes;
        let stats = format!(
            "Argument size in bytes: {}\n\n\
             Number of commitments without degree bounds: {}\n\
             Size (in bytes) of commitments without degree bounds: {}\n\
             Number of commitments with degree bounds: {}\n\
             Size (in bytes) of commitments with degree bounds: {}\n\n\
             Number of evaluation proofs: {}\n\
             Size (in bytes) of evaluation proofs: {}\n\n\
             Number of evaluations: {}\n\
             Size (in bytes) of evaluations: {}\n\n\
             Number of field elements in prover messages: {}\n\
             Size (in bytes) of prover message: {}\n",
            arg_size,
            num_comms_without_degree_bounds,
            size_bytes_comms_without_degree_bounds,
            num_comms_with_degree_bounds,
            size_bytes_comms_with_degree_bounds,
            num_proofs,
            size_bytes_proofs,
            num_evals,
            evals_size_in_bytes,
            num_prover_messages,
            prover_msg_size_in_bytes,
        );
        add_to_trace!(|| "Statistics about proof", || stats);
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> FromBytes
    for Proof<F, PC, C>
{
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let commitments = Vec::<Vec<PC::Commitment>>::read(&mut reader)?;
        let evaluations = Vec::<F>::read(&mut reader)?;
        let prover_messages = Vec::<ProverMsg<F>>::read(&mut reader)?;
        let pc_proof = BatchLCProof::<F, PC>::read(&mut reader)?;
        Ok(Self {
            commitments,
            evaluations,
            prover_messages,
            pc_proof,
            constraint_system: PhantomData,
        })
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> ToBytes
    for Proof<F, PC, C>
{
    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.commitments.write(&mut writer)?;
        self.evaluations.write(&mut writer)?;
        self.prover_messages.write(&mut writer)?;
        self.pc_proof.write(&mut writer)
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>, C: ConstraintSynthesizer<F>> Default
    for Proof<F, PC, C>
{
    fn default() -> Self {
        unimplemented!();
    }
}
