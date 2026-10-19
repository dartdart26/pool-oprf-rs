//! The OPRF report, then the VOPRF report. `cargo bench --bench oprf --
//! voprf` runs the VOPRF report only.

use bincode::Options;
use pool_oprf::online::{blind_eval, finalize, finalize_batch, request, request_batch};
use pool_oprf::preprocessing::{
    ClientState, ServerState, preproc_client, preproc_client_voprf, preproc_server, tau_for,
};
use pool_oprf::server::OprfServer;
use pool_oprf::voprf::{MAX_VOPRF_BATCH_EVALUATIONS, VerifiedKey};
use pool_prf::params::{DELTA, H_ROWS, N, RUNS_PER_EVALUATION};
use pool_prf::prf::{SecretKey, evaluate};
use pool_voprf::plonky3::Plonky3;
use pool_voprf::plonky3::commitments::key::KeyCommitment;
use pool_voprf::plonky3::commitments::mask_sum::{self, MaskSumCommitment};
use pool_voprf::plonky3::commitments::masks::{self, MasksCommitment};
use pool_voprf::plonky3::commitments::pad;
use pool_voprf::statements::preprocessing::PreprocessingStatement;
use pool_voprf::traits::ProofSystem;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;
use std::time::{Duration, Instant};

const TAG: &[u8] = b"tag";

const EVALUATIONS: usize = 1 << 13;
const TAU: usize = tau_for(EVALUATIONS);

/// Evaluations per batch, and how many batches, for the batched figure.
const BATCH: usize = 100;
const BATCH_ROUNDS: usize = 10;

/// Evaluations sent one per request, without batching - the first few are
/// not measured.
const UNBATCHED_EVALUATIONS: usize = 1000;
const WARMUP: usize = 100;

/// Evaluations of each VOPRF preprocessing measured.
const VOPRF_EVALUATIONS: [usize; 2] = [1, 10];

/// VOPRF evaluations sent one per request, without batching, out of the larger
/// VOPRF preprocessing. The rest of it is one batch.
const VOPRF_UNBATCHED_EVALUATIONS: usize = 2;

fn micros(total: Duration, iterations: usize) -> f64 {
    total.as_secs_f64() * 1e6 / iterations as f64
}

fn us(total: Duration, iterations: usize) -> String {
    let value = micros(total, iterations);
    if value < 10.0 {
        format!("{value:.2} us")
    } else {
        format!("{value:.0} us")
    }
}

fn ms(total: Duration, iterations: usize) -> String {
    format!("{:.0} ms", total.as_secs_f64() * 1e3 / iterations as f64)
}

fn kb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

/// One line of the report: label on the left, figure on the right.
fn row(label: impl std::fmt::Display, value: impl std::fmt::Display) {
    println!("{label:<38}{value:>14}");
}

/// The size cryprot-net would put on the wire, from the codec it uses.
fn wire_bytes<T: serde::Serialize>(value: &T) -> usize {
    bincode::options()
        .with_big_endian()
        .with_varint_encoding()
        .serialized_size(value)
        .unwrap() as usize
}

/// One preprocessing run over a local connection, timed end to end. A VOPRF
/// if `pk` is given.
///
/// Both sides run concurrently on the same machine, so this is wall time for
/// the pair.
fn preprocess(
    sk: &SecretKey,
    pk: Option<&VerifiedKey>,
    tau: usize,
    seed: u64,
) -> (Duration, ClientState, ServerState) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut client_rng = StdRng::seed_from_u64(seed);

        let start = Instant::now();
        let client = async {
            match pk {
                Some(pk) => preproc_client_voprf(&mut client_conn, pk, tau, &mut client_rng).await,
                None => preproc_client(&mut client_conn, tau, &mut client_rng).await,
            }
        };
        let (client_state, server_state) =
            tokio::try_join!(client, preproc_server(&mut server_conn, sk, tau)).unwrap();
        (start.elapsed(), client_state, server_state)
    })
}

type Preprocessing = PreprocessingStatement<KeyCommitment, MasksCommitment, MaskSumCommitment>;

/// Prove and verify `π_preproc` of a random statement with `evaluations`
/// evaluations. Its cost depends only on the number of evaluations. Returns
/// the prove time, the verify time and the proof size.
fn preprocessing_proof(evaluations: usize) -> (Duration, Duration, usize) {
    let (statement, witness): (Preprocessing, _) =
        pool_voprf::testing::random_preprocessing(1, evaluations);
    let system = Plonky3::new();

    let start = Instant::now();
    let proof = system.prove(&statement, &witness).unwrap();
    let prove = start.elapsed();

    let start = Instant::now();
    system.verify(&statement, &proof).unwrap();
    (prove, start.elapsed(), wire_bytes(&proof))
}

/// The VOPRF report: setup, preprocessing at each of [`VOPRF_EVALUATIONS`]
/// and the online phase out of the larger one.
fn voprf_report(sk: &SecretKey) {
    let server = OprfServer::new(sk.clone());
    let start = Instant::now();
    let (pk, setup_proof) = server.public_key().unwrap();
    let setup_prove = start.elapsed();
    let start = Instant::now();
    let pk = VerifiedKey::verify(pk, &setup_proof).unwrap();
    let setup_verify = start.elapsed();

    println!();
    row("VOPRF setup", "measured");
    row("  π_setup prove", ms(setup_prove, 1));
    row("  π_setup verify", ms(setup_verify, 1));
    row(
        "  π_setup",
        format!("{:.1} kB", kb(wire_bytes(&setup_proof))),
    );

    // What the preprocessing adds per evaluation, from commitments to zeros:
    // every commitment has the same size.
    let c = masks::commit(&[0; RUNS_PER_EVALUATION], 0);
    let d = pad::commit(0, 0);
    let m = mask_sum::commit(&[0; RUNS_PER_EVALUATION], 0);
    println!();
    row("VOPRF preprocessing messages", "per eval");
    row("  c", format!("{:.1} kB", kb(wire_bytes(&vec![[c; 2]; N]))));
    row(
        "  d",
        format!("{:.1} kB", kb(wire_bytes(&vec![[d; DELTA]; H_ROWS]))),
    );
    row("  m", format!("{} B", wire_bytes(&m)));

    let mut states = None;
    for evaluations in VOPRF_EVALUATIONS {
        let tau = tau_for(evaluations);
        let (plain, _, _) = preprocess(sk, None, tau, 30);
        let (voprf, client_state, server_state) = preprocess(sk, Some(&pk), tau, 31);
        let (prove, verify, bytes) = preprocessing_proof(evaluations);
        println!();
        row(
            format!(
                "VOPRF preprocessing, {evaluations} evaluation{}",
                if evaluations == 1 { "" } else { "s" }
            ),
            "measured",
        );
        row("  OPRF (both sides)", ms(plain, 1));
        row("  VOPRF (both sides)", ms(voprf, 1));
        row("  π_preproc prove", ms(prove, 1));
        row("  π_preproc verify", ms(verify, 1));
        row("  π_preproc", format!("{:.1} kB", kb(bytes)));
        states = Some((client_state, server_state));
    }
    let (mut client_state, mut server_state) = states.expect("a VOPRF preprocessing");

    let mut req_time = Duration::ZERO;
    let mut eval_time = Duration::ZERO;
    let mut fin_time = Duration::ZERO;
    let (mut request_bytes, mut response_bytes) = (0, 0);
    for i in 0..VOPRF_UNBATCHED_EVALUATIONS {
        let x = format!("voprf-{i}");

        let start = Instant::now();
        let (req, fin) = request(&mut client_state, TAG, x.as_bytes()).unwrap();
        req_time += start.elapsed();

        let start = Instant::now();
        let resp = blind_eval(&mut server_state, sk, &req).unwrap();
        eval_time += start.elapsed();

        let start = Instant::now();
        black_box(finalize(&fin, &resp).unwrap());
        fin_time += start.elapsed();

        request_bytes = wire_bytes(&req);
        response_bytes = wire_bytes(&resp);
    }

    let inputs: Vec<String> = (0..MAX_VOPRF_BATCH_EVALUATIONS)
        .map(|i| format!("voprf-batch-{i}"))
        .collect();
    let start = Instant::now();
    let (req, fin) = request_batch(&mut client_state, TAG, &inputs).unwrap();
    let mut batch_client = start.elapsed();
    let start = Instant::now();
    let resp = blind_eval(&mut server_state, sk, &req).unwrap();
    let batch_server = start.elapsed();
    let start = Instant::now();
    black_box(finalize_batch(&fin, &resp).unwrap());
    batch_client += start.elapsed();
    let batch_bytes = wire_bytes(&req) + wire_bytes(&resp);

    println!();
    row("VOPRF online, per evaluation", "measured");
    row("  Request", us(req_time, VOPRF_UNBATCHED_EVALUATIONS));
    row(
        "  BlindEval, with π_online prove",
        ms(eval_time, VOPRF_UNBATCHED_EVALUATIONS),
    );
    row(
        "  Finalize, with π_online verify",
        ms(fin_time, VOPRF_UNBATCHED_EVALUATIONS),
    );
    row("  request message", format!("{:.1} kB", kb(request_bytes)));
    row(
        "  response message, with π_online",
        format!("{:.1} kB", kb(response_bytes)),
    );
    println!();
    row(
        format!("VOPRF batched, {MAX_VOPRF_BATCH_EVALUATIONS} per request"),
        "per eval",
    );
    row("  client", ms(batch_client, MAX_VOPRF_BATCH_EVALUATIONS));
    row("  server", ms(batch_server, MAX_VOPRF_BATCH_EVALUATIONS));
    row(
        "  communication",
        format!(
            "{:.1} kB",
            kb(batch_bytes) / MAX_VOPRF_BATCH_EVALUATIONS as f64
        ),
    );
    println!();
}

fn main() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));

    if std::env::args().any(|arg| arg == "voprf") {
        voprf_report(&sk);
        return;
    }

    let (one_eval, _, _) = preprocess(&sk, None, tau_for(1), 10);

    let (preproc, mut client_state, mut server_state) = preprocess(&sk, None, TAU, 20);

    // The plaintext PRF.
    let start = Instant::now();
    for i in 0..UNBATCHED_EVALUATIONS {
        black_box(evaluate(&sk, TAG, format!("input-{i}").as_bytes()));
    }
    let plaintext = start.elapsed();

    let mut req_time = Duration::ZERO;
    let mut eval_time = Duration::ZERO;
    let mut fin_time = Duration::ZERO;
    let (mut request_bytes, mut response_bytes) = (0, 0);

    for i in 0..UNBATCHED_EVALUATIONS {
        let x = format!("input-{i}");

        let start = Instant::now();
        let (req, fin) = request(&mut client_state, TAG, x.as_bytes()).unwrap();
        let this_req = start.elapsed();

        let start = Instant::now();
        let resp = blind_eval(&mut server_state, &sk, &req).unwrap();
        let this_eval = start.elapsed();

        let start = Instant::now();
        let out = finalize(&fin, &resp).unwrap();
        let this_fin = start.elapsed();

        black_box(out);
        if i == WARMUP {
            request_bytes = wire_bytes(&req);
            response_bytes = wire_bytes(&resp);
        }
        if i >= WARMUP {
            req_time += this_req;
            eval_time += this_eval;
            fin_time += this_fin;
        }
    }
    let measured = UNBATCHED_EVALUATIONS - WARMUP;

    let mut batch_client = Duration::ZERO;
    let mut batch_server = Duration::ZERO;
    let mut batch_bytes = 0;
    for round in 0..BATCH_ROUNDS {
        let inputs: Vec<String> = (0..BATCH).map(|i| format!("batch-{round}-{i}")).collect();

        let start = Instant::now();
        let (req, fin) = request_batch(&mut client_state, TAG, &inputs).unwrap();
        batch_client += start.elapsed();

        let start = Instant::now();
        let resp = blind_eval(&mut server_state, &sk, &req).unwrap();
        batch_server += start.elapsed();

        let start = Instant::now();
        let outs = finalize_batch(&fin, &resp).unwrap();
        batch_client += start.elapsed();

        batch_bytes = wire_bytes(&req) + wire_bytes(&resp);
        black_box(outs);
    }
    let batched = BATCH * BATCH_ROUNDS;

    let client_us = micros(req_time, measured) + micros(fin_time, measured);
    let server_us = micros(eval_time, measured);

    println!();
    println!("Pool OPRF - (n, p, q) = (482, 2^8, 2^12), 128 bits of output and security");
    println!("{measured} measured evaluations, {batched} batched, out of tau = {TAU}");
    println!(
        "preprocessing OT: {}",
        if cfg!(feature = "silent-ot") {
            "silent"
        } else {
            "KOS15 extension"
        }
    );
    println!();
    row("online", "measured");
    row(
        "  client (Request + Finalize)",
        format!("{client_us:.0} us"),
    );
    row("  server (BlindEval)", format!("{server_us:.0} us"));
    row(
        "  communication",
        format!("{:.1} kB", kb(request_bytes + response_bytes)),
    );
    println!();
    row("  Request", us(req_time, measured));
    row("  Finalize", us(fin_time, measured));
    row("  request message", format!("{:.1} kB", kb(request_bytes)));
    row(
        "  response message",
        format!("{:.1} kB", kb(response_bytes)),
    );
    println!();
    row(
        "plaintext PRF (no OT, no blinding)",
        us(plaintext, UNBATCHED_EVALUATIONS),
    );
    println!();
    row(format!("batched, {BATCH} per request"), "per eval");
    row("  client", us(batch_client, batched));
    row("  server", us(batch_server, batched));
    row(
        "  communication",
        format!("{:.1} kB", kb(batch_bytes) / BATCH as f64),
    );
    println!();
    row("preprocessing (both sides)", "measured");
    row(
        format!("  1 evaluation, tau = {} (setup-bound)", tau_for(1)),
        format!("{:.0} ms", one_eval.as_secs_f64() * 1e3),
    );
    row(
        format!("  {EVALUATIONS} evaluations, tau = {TAU}"),
        format!("{:.2} s", preproc.as_secs_f64()),
    );
    row("  per evaluation", us(preproc, EVALUATIONS));
    println!();
    println!(
        "At tau = {} the OT extension's fixed cost - base OTs and the",
        tau_for(1)
    );
    println!("connection itself - dominates, so that row measures setup, not");
    println!("preprocessing. The tau = {TAU} row is the one to read.");

    voprf_report(&sk);
}
