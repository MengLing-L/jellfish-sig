// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_377::{Bls12_377, Fr as Fr377};
use ark_bls12_381::{Bls12_381, Fr as Fr381};
use ark_ed_on_bn254::EdwardsConfig as Param254;
use ark_ec::{
    twisted_edwards::{Affine, TECurveConfig as Config},
    AffineRepr,
};
use ark_bn254::{Bn254, Fr as Fr254};
use ark_bw6_761::{Fr as Fr761, BW6_761};
use ark_ff::PrimeField;
use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
    PlonkType,
};
use jf_primitives::{signatures::schnorr::{KeyPair, VerKey, Signature}, constants::CS_ID_SCHNORR, circuit::signature::schnorr::{SignatureHelperGadget, SignatureGadget}, rescue::RescueParameter};
use jf_relation::{Circuit, PlonkCircuit, Arithmetization, errors::CircuitError, Variable};
use std::time::Instant;

const NUM_REPETITIONS: usize = 50;
const NUM_GATES_LARGE: usize = 131072;
const NUM_GATES_SMALL: usize = 8192;

pub fn build_verify_sig_circuit<F, P>(
    vk: &VerKey<P>,
    msg: &[F],
    sig: &Signature<P>,
) -> Result<PlonkCircuit<F>, CircuitError>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
    let vk_var = circuit.create_signature_vk_variable(vk)?;
    let sig_var = circuit.create_signature_variable(sig)?;
    let msg_var: Vec<Variable> = msg
        .iter()
        .map(|m| circuit.create_variable(*m))
        .collect::<Result<Vec<_>, CircuitError>>()?;
    SignatureGadget::<F, P>::verify_signature(&mut circuit, &vk_var, &msg_var, &sig_var)?;
    Ok(circuit)
}

fn gen_circuit_for_bench<F, P>(
    num_gates: usize,
    plonk_type: PlonkType,
) -> Result<PlonkCircuit<F>, PlonkError> 
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    // let range_bit_len = 8;
    // let mut cs: PlonkCircuit<F> = match plonk_type {
    //     PlonkType::TurboPlonk => PlonkCircuit::new_turbo_plonk(),
    //     PlonkType::UltraPlonk => PlonkCircuit::new_ultra_plonk(range_bit_len),
    // };
    // let a = cs.create_variable(F::from(3u32))?;
    // let b = cs.create_variable(F::from(3u32))?;
    // let c = cs.create_variable(F::from(3u32))?;
    // let d= cs.create_variable(F::from(3u32))?;
    // let wire = [a, b, c, d];
    // let q_lc = [F::one(), F::one(), F::one(), F::one()];
    // let q_mul = [F::one(), F::one()];
    // let q_hash = [F::one(), F::one(), F::one(), F::one()];
    // let q_eqq = F::one();
    // for _ in 0..num_gates {
    //     cs.turbo(&wire, &q_lc, &q_mul, &q_hash, q_eqq)?;
    // }
    // let mut a = cs.zero();
    // for _ in 0..num_gates - 10 {
    //     a = cs.add(a, cs.one())?;
    // }
    let mut rng = jf_utils::test_rng();
    let keypair = KeyPair::<P>::generate(&mut rng);
    let vk = keypair.ver_key_ref();
    let msg: Vec<F> = (0..20).map(|i| F::from(i as u64)).collect();
    let mut msg_bad = msg.clone();
    msg_bad[0] = F::from(2u64);
    let sig = keypair.sign(&msg, CS_ID_SCHNORR);
    vk.verify(&msg, &sig, CS_ID_SCHNORR).unwrap();

    // Test `verify_signature()`
    // Good path
    let mut circuit: PlonkCircuit<F> = build_verify_sig_circuit(vk, &msg, &sig)?;
    //Finalize the circuit.
    assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    circuit.finalize_for_arithmetization()?;

    // println!("{:?}",cs.srs_size());

    Ok(circuit)
}

macro_rules! plonk_prove_bench {
    ($bench_curve:ty, $bench_field:ty, $bench_plonk_type:expr, $num_gates:expr) => {
        let rng = &mut jf_utils::test_rng();
        // let cs = gen_circuit_for_bench::<$bench_field>($num_gates, $bench_plonk_type).unwrap();
        let cs = gen_circuit_for_bench::<_, Param254>($num_gates, $bench_plonk_type).unwrap(); 

        let max_degree = cs.srs_size().unwrap();
        let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

        let (pk, _) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

        let start = Instant::now();

        for _ in 0..NUM_REPETITIONS {
            let _ = PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(
                rng, &cs, &pk, None,
            )
            .unwrap();
        }

        println!(
            "{} times proving time for {}, {}: {} s",
            // stringify!($bench_curve),
            NUM_REPETITIONS,
            "signature",
            stringify!($bench_plonk_type),
            // start.elapsed().as_nanos() / NUM_REPETITIONS as u128 / $num_gates  as u128
            // start.elapsed().as_secs() / NUM_REPETITIONS  as u64
            start.elapsed().as_secs()  as u64
        );
    };
}

fn bench_prove() {
    plonk_prove_bench!(Bn254, Fr381, PlonkType::TurboPlonk, NUM_GATES_LARGE);
}

macro_rules! plonk_verify_bench {
    ($bench_curve:ty, $bench_field:ty, $bench_plonk_type:expr, $num_gates:expr) => {
        let rng = &mut jf_utils::test_rng();
        let cs = gen_circuit_for_bench::<_, Param254>($num_gates, $bench_plonk_type).unwrap();

        let max_degree = $num_gates + 2;
        let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

        let (pk, vk) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

        let proof =
            PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None)
                .unwrap();

        let start = Instant::now();

        for _ in 0..NUM_REPETITIONS {
            let _ =
                PlonkKzgSnark::<$bench_curve>::verify::<StandardTranscript>(&vk, &[], &proof, None)
                    .unwrap();
        }

        println!(
            "{} times verifying time for {}, {}: {} ns",
            // stringify!($bench_curve),
            NUM_REPETITIONS,
            "signature",
            stringify!($bench_plonk_type),
            // start.elapsed().as_nanos() / NUM_REPETITIONS as u128
            // start.elapsed().as_nanos() / NUM_REPETITIONS  as u128
            start.elapsed().as_nanos()  as u128
        );
    };
}

fn bench_verify() {
    plonk_verify_bench!(Bn254, Fr254, PlonkType::TurboPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(Bls12_377, Fr377, PlonkType::TurboPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(Bn254, Fr254, PlonkType::TurboPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(BW6_761, Fr761, PlonkType::TurboPlonk, NUM_GATES_SMALL);
    // plonk_verify_bench!(Bls12_381, Fr381, PlonkType::UltraPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(Bls12_377, Fr377, PlonkType::UltraPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(Bn254, Fr254, PlonkType::UltraPlonk, NUM_GATES_LARGE);
    // plonk_verify_bench!(BW6_761, Fr761, PlonkType::UltraPlonk, NUM_GATES_SMALL);
}

// macro_rules! plonk_batch_verify_bench {
//     ($bench_curve:ty, $bench_field:ty, $bench_plonk_type:expr, $num_proofs:expr) => {
//         let rng = &mut jf_utils::test_rng();
//         let cs = gen_circuit_for_bench::<_, Param254>(1024, $bench_plonk_type).unwrap();

//         let max_degree = 2046;
//         let srs = PlonkKzgSnark::<$bench_curve>::universal_setup(max_degree, rng).unwrap();

//         let (pk, vk) = PlonkKzgSnark::<$bench_curve>::preprocess(&srs, &cs).unwrap();

//         let proof =
//             PlonkKzgSnark::<$bench_curve>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None)
//                 .unwrap();

//         let vks = vec![&vk; $num_proofs];
//         let pub_input = vec![];
//         let public_inputs_ref = vec![&pub_input[..]; $num_proofs];
//         let proofs_ref = vec![&proof; $num_proofs];

//         let start = Instant::now();

//         for _ in 0..NUM_REPETITIONS {
//             let _ = PlonkKzgSnark::<$bench_curve>::batch_verify::<StandardTranscript>(
//                 &vks,
//                 &public_inputs_ref[..],
//                 &proofs_ref,
//                 &vec![None; vks.len()],
//             )
//             .unwrap();
//         }

//         println!(
//             "batch verifying time for {}, {}, {} proofs: {} ns/proof",
//             stringify!($bench_curve),
//             stringify!($bench_plonk_type),
//             stringify!($num_proofs),
//             start.elapsed().as_nanos() / NUM_REPETITIONS as u128 / $num_proofs as u128
//         );
//     };
// }

// fn bench_batch_verify() {
//     plonk_batch_verify_bench!(Bls12_381, Fr381, PlonkType::TurboPlonk, 1000);
//     // plonk_batch_verify_bench!(Bls12_377, Fr377, PlonkType::TurboPlonk, 1000);
//     // plonk_batch_verify_bench!(Bn254, Fr254, PlonkType::TurboPlonk, 1000);
//     // plonk_batch_verify_bench!(BW6_761, Fr761, PlonkType::TurboPlonk, 1000);
//     // plonk_batch_verify_bench!(Bls12_381, Fr381, PlonkType::UltraPlonk, 1000);
//     // plonk_batch_verify_bench!(Bls12_377, Fr377, PlonkType::UltraPlonk, 1000);
//     // plonk_batch_verify_bench!(Bn254, Fr254, PlonkType::UltraPlonk, 1000);
//     // plonk_batch_verify_bench!(BW6_761, Fr761, PlonkType::UltraPlonk, 1000);
// }

fn main() {
    bench_prove();
    bench_verify();
    // bench_batch_verify();
}
