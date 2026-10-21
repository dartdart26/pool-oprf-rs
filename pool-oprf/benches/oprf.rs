//! The OPRF report, then the VOPRF report. `cargo bench --bench oprf --
//! voprf` runs the VOPRF report only.

use bincode::Options;
use pool_oprf::online::{blind_eval, finalize, finalize_batch, request, request_batch};
use pool_oprf::preprocessing::{
    ClientState, ServerState, preproc_client, preproc_client_voprf, preproc_server, tau_for,
};
use pool_oprf::server::OprfServer;
use pool_oprf::voprf::VerifiedKey;
use pool_prf::params::{
    DELTA, H_ROWS, LAMBDA_BITS, LOG_DELTA, LOG_P, LOG_Q, N, RUNS_PER_EVALUATION,
};
use pool_prf::prf::{SecretKey, evaluate};
use pool_voprf::plonky3::Plonky3;
use pool_voprf::plonky3::commitments::key::KeyCommitment;
use pool_voprf::plonky3::commitments::mask_sum::{self, MaskSumCommitment};
use pool_voprf::plonky3::commitments::masks::{self, MasksCommitment};
use pool_voprf::plonky3::commitments::pad;
use pool_voprf::statements::online::OnlineStatement;
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

/// Evaluations of the VOPRF report's online phase: all of the larger
/// preprocessing.
const VOPRF_ONLINE_EVALUATIONS: usize = VOPRF_EVALUATIONS[1];

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

/// `us` below a millisecond, `ms` from there.
fn us_or_ms(total: Duration, iterations: usize) -> String {
    if micros(total, iterations) < 1000.0 {
        us(total, iterations)
    } else {
        ms(total, iterations)
    }
}

fn kb(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

/// One line of the report: label on the left, figure on the right.
fn row(label: impl std::fmt::Display, value: impl std::fmt::Display) {
    println!("{label:<38}{value:>14}");
}

/// One line of the VOPRF report: label, then the OPRF figure, then the VOPRF
/// figure. The OPRF figure is blank for what only the VOPRF has.
fn row2(
    label: impl std::fmt::Display,
    oprf: impl std::fmt::Display,
    voprf: impl std::fmt::Display,
) {
    println!("{label:<38}{oprf:>14}{voprf:>14}");
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

type Online = OnlineStatement<KeyCommitment, MaskSumCommitment, pad::PadCommitment>;

/// Prove and verify `π_online` of a random statement. Its cost does not
/// depend on the statement. Returns the prove time and the verify time.
fn online_proof() -> (Duration, Duration) {
    let (statement, witness): (Online, _) = pool_voprf::testing::random_online(1);
    let system = Plonky3::new();

    let start = Instant::now();
    let proof = system.prove(&statement, &witness).unwrap();
    let prove = start.elapsed();

    let start = Instant::now();
    system.verify(&statement, &proof).unwrap();
    (prove, start.elapsed())
}

/// What the VOPRF report measures online, out of one preprocessing.
struct OnlinePhase {
    request: Duration,
    blind_eval: Duration,
    finalize: Duration,
    response_bytes: usize,
}

/// [`VOPRF_ONLINE_EVALUATIONS`] evaluations, one per request.
fn online(
    sk: &SecretKey,
    mut client_state: ClientState,
    mut server_state: ServerState,
) -> OnlinePhase {
    let mut request_time = Duration::ZERO;
    let mut eval_time = Duration::ZERO;
    let mut fin_time = Duration::ZERO;
    let mut response_bytes = 0;
    for i in 0..VOPRF_ONLINE_EVALUATIONS {
        let x = format!("voprf-{i}");

        let start = Instant::now();
        let (req, fin) = request(&mut client_state, TAG, x.as_bytes()).unwrap();
        request_time += start.elapsed();

        let start = Instant::now();
        let resp = blind_eval(&mut server_state, sk, &req).unwrap();
        eval_time += start.elapsed();

        let start = Instant::now();
        black_box(finalize(&fin, &resp).unwrap());
        fin_time += start.elapsed();

        response_bytes = wire_bytes(&resp);
    }

    OnlinePhase {
        request: request_time,
        blind_eval: eval_time,
        finalize: fin_time,
        response_bytes,
    }
}

/// The CPU model, from /proc/cpuinfo on Linux.
fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("model name"))
                .and_then(|rest| rest.split_once(':'))
                .map(|(_, name)| name.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".to_string())
}

/// Total memory, from /proc/meminfo on Linux.
fn memory() -> String {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| {
            let kib: u64 = info
                .lines()
                .find_map(|line| line.strip_prefix("MemTotal:"))?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()?;
            Some(format!("{:.1} GiB", kib as f64 / (1024.0 * 1024.0)))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// What the VOPRF report runs with.
fn voprf_parameters() {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let fri = pool_voprf::plonky3::fri_parameters(());
    println!();
    println!(
        "Pool VOPRF - λ = {LAMBDA_BITS}, (n, p, q) = ({N}, 2^{LOG_P}, 2^{LOG_Q}), Δ = {DELTA}"
    );
    println!(
        "1 evaluation: {RUNS_PER_EVALUATION} runs of {LOG_P}-bit output each, leading to {}-bit output",
        RUNS_PER_EVALUATION * LOG_P as usize
    );
    println!(
        "OT: ML-KEM-768 base OT, {}, 1-out-of-Δ OT from {LOG_DELTA} binary OTs",
        if cfg!(feature = "silent-ot") {
            "silent OT extension"
        } else {
            "IKNP extension with the KOS15 check"
        }
    );
    println!(
        "proofs: Plonky3 STARK over BabyBear, degree-{} extension, Poseidon2",
        pool_voprf::plonky3::CHALLENGE_DIMENSION
    );
    println!(
        "FRI: blowup {}, {} queries, proof of work {}-bit commit, {}-bit batch, {}-bit query, hiding",
        1 << fri.log_blowup,
        fri.num_queries,
        fri.commit_proof_of_work_bits,
        fri.batch_proof_of_work_bits,
        fri.query_proof_of_work_bits
    );
    println!(
        "machine: {}, {threads} threads, {} memory",
        cpu_model(),
        memory()
    );
}

/// The VOPRF report, next to the OPRF: setup, preprocessing at each of
/// [`VOPRF_EVALUATIONS`] and the online phase out of the larger one.
fn voprf_report(sk: &SecretKey) {
    voprf_parameters();

    let server = OprfServer::new(sk.clone());
    let start = Instant::now();
    let (pk, setup_proof) = server.public_key().unwrap();
    let setup_prove = start.elapsed();
    let start = Instant::now();
    let pk = VerifiedKey::verify(pk, &setup_proof).unwrap();
    let setup_verify = start.elapsed();

    println!();
    row2("setup", "", "measured");
    row2("  π_setup prove", "", ms(setup_prove, 1));
    row2("  π_setup verify", "", ms(setup_verify, 1));
    row2(
        "  π_setup",
        "",
        format!("{:.1} kB", kb(wire_bytes(&setup_proof))),
    );

    // What the preprocessing adds per evaluation, from commitments to zeros:
    // every commitment has the same size.
    let c = masks::commit(&[0; RUNS_PER_EVALUATION], 0);
    let d = pad::commit(0, 0);
    let m = mask_sum::commit(&[0; RUNS_PER_EVALUATION], 0);
    println!();
    row2("preprocessing, added VOPRF messages", "", "per evaluation");
    row2(
        "  c",
        "",
        format!("{:.1} kB", kb(wire_bytes(&vec![[c; 2]; N]))),
    );
    row2(
        "  d",
        "",
        format!("{:.1} kB", kb(wire_bytes(&vec![[d; DELTA]; H_ROWS]))),
    );
    row2("  m", "", format!("{} B", wire_bytes(&m)));

    let mut states = None;
    for evaluations in VOPRF_EVALUATIONS {
        let tau = tau_for(evaluations);
        let (oprf_time, oprf_client, oprf_server) = preprocess(sk, None, tau, 30);
        let (voprf_time, voprf_client, voprf_server) = preprocess(sk, Some(&pk), tau, 31);
        let (prove, verify, bytes) = preprocessing_proof(evaluations);
        println!();
        row2(
            format!(
                "preprocessing, {evaluations} evaluation{}",
                if evaluations == 1 { "" } else { "s" }
            ),
            "OPRF",
            "VOPRF",
        );
        row2("  time (end to end)", ms(oprf_time, 1), ms(voprf_time, 1));
        // The VOPRF's end-to-end time includes proving and verifying
        // π_preproc.
        row2("    incl. π_preproc prove", "", ms(prove, 1));
        row2("    incl. π_preproc verify", "", ms(verify, 1));
        row2("  π_preproc", "", format!("{:.1} kB", kb(bytes)));
        states = Some((oprf_client, oprf_server, voprf_client, voprf_server));
    }
    let (oprf_client, oprf_server, voprf_client, voprf_server) = states.expect("a preprocessing");
    let oprf = online(sk, oprf_client, oprf_server);
    let voprf = online(sk, voprf_client, voprf_server);

    let n = VOPRF_ONLINE_EVALUATIONS;
    println!();
    row2("online, per evaluation", "OPRF", "VOPRF");
    row2(
        "  Request",
        us_or_ms(oprf.request, n),
        us_or_ms(voprf.request, n),
    );
    // The VOPRF's BlindEval proves π_online and its Finalize verifies it:
    // those, measured on their own, sit under each.
    let (prove, verify) = online_proof();
    row2(
        "  BlindEval",
        us_or_ms(oprf.blind_eval, n),
        us_or_ms(voprf.blind_eval, n),
    );
    row2("    incl. π_online prove", "", ms(prove, 1));
    row2(
        "  Finalize",
        us_or_ms(oprf.finalize, n),
        us_or_ms(voprf.finalize, n),
    );
    row2("    incl. π_online verify", "", ms(verify, 1));
    // A VOPRF response is the OPRF response with π_online added.
    row2(
        "  π_online",
        "",
        format!("{:.1} kB", kb(voprf.response_bytes - oprf.response_bytes)),
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
