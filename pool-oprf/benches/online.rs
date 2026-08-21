use bincode::Options;
use pool_oprf::online::{blind_eval, finalize, finalize_batch, request, request_batch};
use pool_oprf::preprocessing::{ClientState, ServerState, preproc_client, preproc_server, tau_for};
use pool_prf::prf::{SecretKey, evaluate};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;
use std::time::{Duration, Instant};

const TAG: &[u8] = b"tag";

const EVALUATIONS: usize = 1 << 13;
const TAU: usize = tau_for(EVALUATIONS);

/// Evaluations per batch, and how many batches, for the batched figure.
const BATCH: usize = 100;
const BATCH_ROUNDS: usize = 10;

/// Evaluations made one at a time - the first few are not measured.
const SINGLE_ROUNDS: usize = 1000;
const WARMUP: usize = 100;

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

/// One preprocessing run over a local connection, timed end to end.
///
/// Both sides run concurrently on the same machine, so this is wall time for
/// the pair.
fn preprocess(sk: &SecretKey, tau: usize, seed: u64) -> (Duration, ClientState, ServerState) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (mut server_conn, mut client_conn) = cryprot_net::testing::local_conn().await.unwrap();
        let mut client_rng = StdRng::seed_from_u64(seed);

        let start = Instant::now();
        let (client_state, server_state) = tokio::try_join!(
            preproc_client(&mut client_conn, tau, &mut client_rng),
            preproc_server(&mut server_conn, sk, tau),
        )
        .unwrap();
        (start.elapsed(), client_state, server_state)
    })
}

fn main() {
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(1));

    let (one_eval, _, _) = preprocess(&sk, tau_for(1), 10);

    let (preproc, mut client_state, mut server_state) = preprocess(&sk, TAU, 20);

    // The plaintext PRF.
    let start = Instant::now();
    for i in 0..SINGLE_ROUNDS {
        black_box(evaluate(&sk, TAG, format!("input-{i}").as_bytes()));
    }
    let plaintext = start.elapsed();

    let mut req_time = Duration::ZERO;
    let mut eval_time = Duration::ZERO;
    let mut fin_time = Duration::ZERO;
    let (mut request_bytes, mut response_bytes) = (0, 0);

    for i in 0..SINGLE_ROUNDS {
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
    let measured = SINGLE_ROUNDS - WARMUP;

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
            "IKNP extension"
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
        us(plaintext, SINGLE_ROUNDS),
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
    println!();
}
