use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_groth16::{Proof, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use core::ops::Deref;

use crate::emsm::dual_lpn::DualLPNInstance;
use crate::emsm::emsm::{decrypt, encrypt, EmsmPublicParams, PreprocessedCommitments};
use crate::emsm::malicious::{
    malicious_decrypt, malicious_encrypt, MaliciousDecryptState, MaliciousEncrypted, MaliciousError,
};

/// Server-aided proving key: wraps the standard Groth16 proving key with
/// EMSM parameters for each of the 5 MSMs.
pub struct ServerAidedProvingKey {
    pub pk: ProvingKey<Bn254>,
    pub emsm_h: EmsmPublicParams<G1>,
    pub emsm_l: EmsmPublicParams<G1>,
    pub emsm_a: EmsmPublicParams<G1>,
    pub emsm_b_g1: EmsmPublicParams<G1>,
    pub emsm_b_g2: EmsmPublicParams<G2>,
    pub pre_h: PreprocessedCommitments<G1>,
    pub pre_l: PreprocessedCommitments<G1>,
    pub pre_a: PreprocessedCommitments<G1>,
    pub pre_b_g1: PreprocessedCommitments<G1>,
    pub pre_b_g2: PreprocessedCommitments<G2>,
}

impl ServerAidedProvingKey {
    pub fn setup<R: Rng>(pk: ProvingKey<Bn254>, rng: &mut R) -> Self {
        let emsm_h = EmsmPublicParams::<G1>::new(pk.h_query.clone(), rng);
        let pre_h = emsm_h.preprocess();

        let emsm_l = EmsmPublicParams::<G1>::new(pk.l_query.clone(), rng);
        let pre_l = emsm_l.preprocess();

        let num_pub = pk.vk.gamma_abc_g1.len();

        let a_witness: Vec<G1Affine> = pk.a_query[num_pub..].to_vec();
        let emsm_a = EmsmPublicParams::<G1>::new(a_witness, rng);
        let pre_a = emsm_a.preprocess();

        let b_g1_witness: Vec<G1Affine> = pk.b_g1_query[num_pub..].to_vec();
        let emsm_b_g1 = EmsmPublicParams::<G1>::new(b_g1_witness, rng);
        let pre_b_g1 = emsm_b_g1.preprocess();

        let b_g2_witness: Vec<G2Affine> = pk.b_g2_query[num_pub..].to_vec();
        let emsm_b_g2 = EmsmPublicParams::<G2>::new(b_g2_witness, rng);
        let pre_b_g2 = emsm_b_g2.preprocess();

        Self {
            pk,
            emsm_h,
            emsm_l,
            emsm_a,
            emsm_b_g1,
            emsm_b_g2,
            pre_h,
            pre_l,
            pre_a,
            pre_b_g1,
            pre_b_g2,
        }
    }
}

/// Client-side state kept during proving (between encrypt and decrypt).
pub struct ClientDecryptionState {
    pub r: Fr,
    pub s: Fr,
    pub lpn_h: DualLPNInstance<Fr>,
    pub lpn_l: DualLPNInstance<Fr>,
    pub lpn_a: DualLPNInstance<Fr>,
    pub lpn_b_g1: DualLPNInstance<Fr>,
    pub lpn_b_g2: DualLPNInstance<Fr>,
    pub num_instance_variables: usize,
    pub full_assignment: Vec<Fr>,
}

/// Data sent to the server: 5 masked scalar vectors.
pub struct EncryptedRequest {
    pub v_h: Vec<Fr>,
    pub v_l: Vec<Fr>,
    pub v_a: Vec<Fr>,
    pub v_b_g1: Vec<Fr>,
    pub v_b_g2: Vec<Fr>,
}

/// Server's response: 5 MSM results.
pub struct ServerResponse {
    pub em_h: G1,
    pub em_l: G1,
    pub em_a: G1,
    pub em_b_g1: G1,
    pub em_b_g2: G2,
}

/// Client encrypt: synthesize circuit, extract witness, compute QAP, mask vectors.
pub fn client_encrypt<QAP: R1CSToQAP, C: ConstraintSynthesizer<Fr>, R: Rng>(
    sapk: &ServerAidedProvingKey,
    circuit: C,
    rng: &mut R,
) -> Result<(EncryptedRequest, ClientDecryptionState), anyhow::Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove { construct_matrices: true });
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    let num_instance_variables = cs.num_instance_variables();

    // Use arkworks' own QAP witness map to compute h polynomial
    let h_poly = QAP::witness_map::<Fr, GeneralEvaluationDomain<Fr>>(cs.clone())?;

    // Get the full assignment from the constraint system
    let cs_inner = cs.borrow().unwrap();
    let prover = cs_inner.deref();
    let instance = prover.instance_assignment.clone();
    let witness = prover.witness_assignment.clone();
    let mut full_assignment = instance.clone();
    full_assignment.extend_from_slice(&witness);
    drop(cs_inner);

    // Random blinding factors for zero-knowledge
    let r = Fr::rand(rng);
    let s = Fr::rand(rng);

    // Mask h polynomial
    let h_scalars = pad_or_trim(&h_poly, sapk.emsm_h.generators.len());
    let (v_h, lpn_h) = encrypt(&sapk.emsm_h, &h_scalars, rng);

    // Mask witness scalars for l_query
    let l_scalars = pad_or_trim(&witness, sapk.emsm_l.generators.len());
    let (v_l, lpn_l) = encrypt(&sapk.emsm_l, &l_scalars, rng);

    // Mask witness scalars for a_query (witness portion only)
    let a_scalars = pad_or_trim(&witness, sapk.emsm_a.generators.len());
    let (v_a, lpn_a) = encrypt(&sapk.emsm_a, &a_scalars, rng);

    // Mask witness scalars for b_g1 and b_g2 (independent LPN instances)
    let b_g1_scalars = pad_or_trim(&witness, sapk.emsm_b_g1.generators.len());
    let (v_b_g1, lpn_b_g1) = encrypt(&sapk.emsm_b_g1, &b_g1_scalars, rng);

    let b_g2_scalars = pad_or_trim(&witness, sapk.emsm_b_g2.generators.len());
    let (v_b_g2, lpn_b_g2) = encrypt(&sapk.emsm_b_g2, &b_g2_scalars, rng);

    let request = EncryptedRequest {
        v_h,
        v_l,
        v_a,
        v_b_g1,
        v_b_g2,
    };

    let state = ClientDecryptionState {
        r,
        s,
        lpn_h,
        lpn_l,
        lpn_a,
        lpn_b_g1,
        lpn_b_g2,
        num_instance_variables,
        full_assignment,
    };

    Ok((request, state))
}

/// Server evaluate: compute 5 MSMs on masked vectors.
pub fn server_evaluate(
    sapk: &ServerAidedProvingKey,
    request: &EncryptedRequest,
) -> Result<ServerResponse, anyhow::Error> {
    let em_h = sapk.emsm_h.server_computation(&request.v_h)?;
    let em_l = sapk.emsm_l.server_computation(&request.v_l)?;
    let em_a = sapk.emsm_a.server_computation(&request.v_a)?;
    let em_b_g1 = sapk.emsm_b_g1.server_computation(&request.v_b_g1)?;
    let em_b_g2 = sapk.emsm_b_g2.server_computation(&request.v_b_g2)?;

    Ok(ServerResponse {
        em_h,
        em_l,
        em_a,
        em_b_g1,
        em_b_g2,
    })
}

/// Client decrypt: unmask server results and assemble the Groth16 proof.
pub fn client_decrypt(
    sapk: &ServerAidedProvingKey,
    response: &ServerResponse,
    state: &ClientDecryptionState,
) -> Proof<Bn254> {
    let h_msm = decrypt(response.em_h, &state.lpn_h, &sapk.pre_h);
    let l_msm = decrypt(response.em_l, &state.lpn_l, &sapk.pre_l);
    let a_witness_msm = decrypt(response.em_a, &state.lpn_a, &sapk.pre_a);
    let b_g1_witness_msm = decrypt(response.em_b_g1, &state.lpn_b_g1, &sapk.pre_b_g1);
    let b_g2_witness_msm: G2 = decrypt(response.em_b_g2, &state.lpn_b_g2, &sapk.pre_b_g2);

    // Compute the public-input portions locally
    let num_pub = state.num_instance_variables;
    let public_inputs = &state.full_assignment[1..num_pub]; // skip "1" constant

    // A: public input contribution
    let mut a_pub = G1::zero();
    for (i, &input) in public_inputs.iter().enumerate() {
        if !input.is_zero() {
            a_pub += sapk.pk.a_query[i + 1] * input;
        }
    }
    // a_query[0] * 1 (the constant)
    let a_const: G1 = sapk.pk.a_query[0].into();
    a_pub += a_const;

    // B: public input contribution (G1 and G2)
    let mut b_g1_pub = G1::zero();
    let mut b_g2_pub = G2::zero();
    for (i, &input) in public_inputs.iter().enumerate() {
        if !input.is_zero() {
            b_g1_pub += sapk.pk.b_g1_query[i + 1] * input;
            b_g2_pub += sapk.pk.b_g2_query[i + 1] * input;
        }
    }
    let b_g1_const: G1 = sapk.pk.b_g1_query[0].into();
    let b_g2_const: G2 = sapk.pk.b_g2_query[0].into();
    b_g1_pub += b_g1_const;
    b_g2_pub += b_g2_const;

    // Assemble proof components
    // pi_a = alpha + a_pub + a_witness + r * delta_g1
    let alpha: G1 = sapk.pk.vk.alpha_g1.into();
    let delta_g1: G1 = sapk.pk.delta_g1.into();
    let g_a: G1 = alpha + a_pub + a_witness_msm + delta_g1 * state.r;

    // pi_b (G2) = beta_g2 + b_g2_pub + b_g2_witness + s * delta_g2
    let beta_g2: G2 = sapk.pk.vk.beta_g2.into();
    let delta_g2: G2 = sapk.pk.vk.delta_g2.into();
    let g_b: G2 = beta_g2 + b_g2_pub + b_g2_witness_msm + delta_g2 * state.s;

    // pi_b in G1 (for pi_c computation)
    let beta_g1: G1 = sapk.pk.beta_g1.into();
    let g_b_g1: G1 = beta_g1 + b_g1_pub + b_g1_witness_msm + delta_g1 * state.s;

    // pi_c = h_msm + l_msm + s*g_a + r*g_b_g1 - r*s*delta_g1
    let g_c: G1 =
        h_msm + l_msm + g_a * state.s + g_b_g1 * state.r - delta_g1 * (state.r * state.s);

    Proof {
        a: g_a.into_affine(),
        b: g_b.into_affine(),
        c: g_c.into_affine(),
    }
}

// ─── Malicious-secure variants ───────────────────────────────────────────────
// These use double-query EMSM (main + check) per MSM so that a cheating server
// is detected with overwhelming probability.

/// Data sent to the server in malicious mode: 10 masked vectors (5 main + 5 check).
pub struct MaliciousEncryptedRequest {
    pub h: MaliciousEncrypted<Fr>,
    pub l: MaliciousEncrypted<Fr>,
    pub a: MaliciousEncrypted<Fr>,
    pub b_g1: MaliciousEncrypted<Fr>,
    pub b_g2: MaliciousEncrypted<Fr>,
}

/// Client-side state for malicious-secure proving.
pub struct MaliciousClientState {
    pub r: Fr,
    pub s: Fr,
    pub ds_h: MaliciousDecryptState<Fr>,
    pub ds_l: MaliciousDecryptState<Fr>,
    pub ds_a: MaliciousDecryptState<Fr>,
    pub ds_b_g1: MaliciousDecryptState<Fr>,
    pub ds_b_g2: MaliciousDecryptState<Fr>,
    pub num_instance_variables: usize,
    pub full_assignment: Vec<Fr>,
}

/// Server response in malicious mode: 10 MSM results (5 main + 5 check).
pub struct MaliciousServerResponse {
    pub em_h: G1,
    pub em_h_ck: G1,
    pub em_l: G1,
    pub em_l_ck: G1,
    pub em_a: G1,
    pub em_a_ck: G1,
    pub em_b_g1: G1,
    pub em_b_g1_ck: G1,
    pub em_b_g2: G2,
    pub em_b_g2_ck: G2,
}

/// Malicious-secure client encrypt: double-query per MSM.
pub fn malicious_client_encrypt<QAP: R1CSToQAP, C: ConstraintSynthesizer<Fr>, R: Rng>(
    sapk: &ServerAidedProvingKey,
    circuit: C,
    rng: &mut R,
) -> Result<(MaliciousEncryptedRequest, MaliciousClientState), anyhow::Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove { construct_matrices: true });
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    let num_instance_variables = cs.num_instance_variables();
    let h_poly = QAP::witness_map::<Fr, GeneralEvaluationDomain<Fr>>(cs.clone())?;

    let cs_inner = cs.borrow().unwrap();
    let prover = cs_inner.deref();
    let instance = prover.instance_assignment.clone();
    let witness = prover.witness_assignment.clone();
    let mut full_assignment = instance.clone();
    full_assignment.extend_from_slice(&witness);
    drop(cs_inner);

    let r = Fr::rand(rng);
    let s = Fr::rand(rng);

    let h_scalars = pad_or_trim(&h_poly, sapk.emsm_h.generators.len());
    let (enc_h, ds_h) = malicious_encrypt(&sapk.emsm_h, &h_scalars, rng);

    let l_scalars = pad_or_trim(&witness, sapk.emsm_l.generators.len());
    let (enc_l, ds_l) = malicious_encrypt(&sapk.emsm_l, &l_scalars, rng);

    let a_scalars = pad_or_trim(&witness, sapk.emsm_a.generators.len());
    let (enc_a, ds_a) = malicious_encrypt(&sapk.emsm_a, &a_scalars, rng);

    let b_g1_scalars = pad_or_trim(&witness, sapk.emsm_b_g1.generators.len());
    let (enc_b_g1, ds_b_g1) = malicious_encrypt(&sapk.emsm_b_g1, &b_g1_scalars, rng);

    let b_g2_scalars = pad_or_trim(&witness, sapk.emsm_b_g2.generators.len());
    let (enc_b_g2, ds_b_g2) = malicious_encrypt(&sapk.emsm_b_g2, &b_g2_scalars, rng);

    let request = MaliciousEncryptedRequest {
        h: enc_h,
        l: enc_l,
        a: enc_a,
        b_g1: enc_b_g1,
        b_g2: enc_b_g2,
    };

    let state = MaliciousClientState {
        r,
        s,
        ds_h,
        ds_l,
        ds_a,
        ds_b_g1,
        ds_b_g2,
        num_instance_variables,
        full_assignment,
    };

    Ok((request, state))
}

/// Malicious-secure server evaluate: compute 10 MSMs (5 main + 5 check).
pub fn malicious_server_evaluate_groth16(
    sapk: &ServerAidedProvingKey,
    request: &MaliciousEncryptedRequest,
) -> Result<MaliciousServerResponse, anyhow::Error> {
    let (em_h, em_h_ck) = (
        sapk.emsm_h.server_computation(&request.h.masked)?,
        sapk.emsm_h.server_computation(&request.h.masked_check)?,
    );
    let (em_l, em_l_ck) = (
        sapk.emsm_l.server_computation(&request.l.masked)?,
        sapk.emsm_l.server_computation(&request.l.masked_check)?,
    );
    let (em_a, em_a_ck) = (
        sapk.emsm_a.server_computation(&request.a.masked)?,
        sapk.emsm_a.server_computation(&request.a.masked_check)?,
    );
    let (em_b_g1, em_b_g1_ck) = (
        sapk.emsm_b_g1.server_computation(&request.b_g1.masked)?,
        sapk.emsm_b_g1.server_computation(&request.b_g1.masked_check)?,
    );
    let (em_b_g2, em_b_g2_ck) = (
        sapk.emsm_b_g2.server_computation(&request.b_g2.masked)?,
        sapk.emsm_b_g2.server_computation(&request.b_g2.masked_check)?,
    );

    Ok(MaliciousServerResponse {
        em_h,
        em_h_ck,
        em_l,
        em_l_ck,
        em_a,
        em_a_ck,
        em_b_g1,
        em_b_g1_ck,
        em_b_g2,
        em_b_g2_ck,
    })
}

/// Malicious-secure client decrypt: verify consistency checks, unmask, assemble proof.
/// Returns `MaliciousError::ConsistencyCheckFailed` if the server tampered with any MSM.
pub fn malicious_client_decrypt(
    sapk: &ServerAidedProvingKey,
    response: &MaliciousServerResponse,
    state: &MaliciousClientState,
) -> Result<Proof<Bn254>, MaliciousError> {
    let h_msm = malicious_decrypt(response.em_h, response.em_h_ck, &state.ds_h, &sapk.pre_h)?;
    let l_msm = malicious_decrypt(response.em_l, response.em_l_ck, &state.ds_l, &sapk.pre_l)?;
    let a_witness_msm =
        malicious_decrypt(response.em_a, response.em_a_ck, &state.ds_a, &sapk.pre_a)?;
    let b_g1_witness_msm = malicious_decrypt(
        response.em_b_g1,
        response.em_b_g1_ck,
        &state.ds_b_g1,
        &sapk.pre_b_g1,
    )?;
    let b_g2_witness_msm: G2 = malicious_decrypt(
        response.em_b_g2,
        response.em_b_g2_ck,
        &state.ds_b_g2,
        &sapk.pre_b_g2,
    )?;

    // Assemble proof (same logic as semi-honest client_decrypt)
    let num_pub = state.num_instance_variables;
    let public_inputs = &state.full_assignment[1..num_pub];

    let mut a_pub = G1::zero();
    for (i, &input) in public_inputs.iter().enumerate() {
        if !input.is_zero() {
            a_pub += sapk.pk.a_query[i + 1] * input;
        }
    }
    let a_const: G1 = sapk.pk.a_query[0].into();
    a_pub += a_const;

    let mut b_g1_pub = G1::zero();
    let mut b_g2_pub = G2::zero();
    for (i, &input) in public_inputs.iter().enumerate() {
        if !input.is_zero() {
            b_g1_pub += sapk.pk.b_g1_query[i + 1] * input;
            b_g2_pub += sapk.pk.b_g2_query[i + 1] * input;
        }
    }
    let b_g1_const: G1 = sapk.pk.b_g1_query[0].into();
    let b_g2_const: G2 = sapk.pk.b_g2_query[0].into();
    b_g1_pub += b_g1_const;
    b_g2_pub += b_g2_const;

    let alpha: G1 = sapk.pk.vk.alpha_g1.into();
    let delta_g1: G1 = sapk.pk.delta_g1.into();
    let g_a: G1 = alpha + a_pub + a_witness_msm + delta_g1 * state.r;

    let beta_g2: G2 = sapk.pk.vk.beta_g2.into();
    let delta_g2: G2 = sapk.pk.vk.delta_g2.into();
    let g_b: G2 = beta_g2 + b_g2_pub + b_g2_witness_msm + delta_g2 * state.s;

    let beta_g1: G1 = sapk.pk.beta_g1.into();
    let g_b_g1: G1 = beta_g1 + b_g1_pub + b_g1_witness_msm + delta_g1 * state.s;

    let g_c: G1 =
        h_msm + l_msm + g_a * state.s + g_b_g1 * state.r - delta_g1 * (state.r * state.s);

    Ok(Proof {
        a: g_a.into_affine(),
        b: g_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// Adjust a vector to exactly `target_len` by zero-padding or trimming.
/// Logs a warning if the lengths don't match, since this may indicate a setup misconfiguration.
fn pad_or_trim(v: &[Fr], target_len: usize) -> Vec<Fr> {
    if v.len() != target_len {
        tracing::warn!(
            "pad_or_trim: vector length {} != target {}, adjusting",
            v.len(),
            target_len
        );
    }
    if v.len() >= target_len {
        v[..target_len].to_vec()
    } else {
        let mut padded = v.to_vec();
        padded.resize(target_len, Fr::zero());
        padded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::circuit::CubeCircuit;
    use ark_groth16::r1cs_to_qap::LibsnarkReduction;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_server_aided_groth16_e2e() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        // Standard Groth16 setup
        let circuit_for_setup = CubeCircuit::<Fr> { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng)
            .expect("setup failed");

        // Create server-aided proving key
        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

        // Client: encrypt (x = 3, so y = 3^3 + 3 + 5 = 35)
        let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
        let (request, state) =
            client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).expect("encrypt failed");

        // Server: evaluate 5 MSMs
        let response = server_evaluate(&sapk, &request).expect("server evaluate failed");

        // Client: decrypt and assemble proof
        let proof = client_decrypt(&sapk, &response, &state);

        // Verify the proof
        let public_inputs = vec![Fr::from(35u64)];
        let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
            .expect("verification failed");
        assert!(valid, "Server-aided Groth16 proof should verify!");
    }

    #[test]
    fn test_malicious_server_aided_groth16_e2e() {
        let mut rng = ChaCha20Rng::seed_from_u64(77);

        let circuit_for_setup = CubeCircuit::<Fr> { x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng)
            .expect("setup failed");

        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

        let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
        let (request, state) =
            malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng)
                .expect("encrypt failed");

        let response = malicious_server_evaluate_groth16(&sapk, &request)
            .expect("server evaluate failed");

        let proof = malicious_client_decrypt(&sapk, &response, &state)
            .expect("consistency check should pass for honest server");

        let public_inputs = vec![Fr::from(35u64)];
        let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
            .expect("verification failed");
        assert!(valid, "Malicious-secure server-aided Groth16 proof should verify!");
    }

    #[test]
    fn test_malicious_server_aided_detects_tampering() {
        let mut rng = ChaCha20Rng::seed_from_u64(88);

        let circuit_for_setup = CubeCircuit::<Fr> { x: None };
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng)
            .expect("setup failed");

        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

        let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
        let (request, state) =
            malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng)
                .expect("encrypt failed");

        let mut response = malicious_server_evaluate_groth16(&sapk, &request)
            .expect("server evaluate failed");

        // Tamper with one MSM result
        response.em_h += G1::rand(&mut rng);

        let result = malicious_client_decrypt(&sapk, &response, &state);
        assert!(result.is_err(), "Should detect tampered MSM result");
    }
}
