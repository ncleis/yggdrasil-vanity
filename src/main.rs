use std::{
    sync::{atomic::AtomicU8, mpsc, Arc, Mutex},
    thread, time,
};

use chrono::{SecondsFormat, Utc};
use clap::Parser;
use handler::handle_keypair;
use rand::RngCore;
use rayon::prelude::*;
use regex::Regex;

mod gpu;
mod handler;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// OpenCL thread count
    #[arg(short, long, default_value_t = 1024 * 1024)]
    threads: usize,

    /// OpenCL local work size
    #[arg(short, long)]
    local_work_size: Option<usize>,

    /// OpenCL global work size
    #[arg(short, long)]
    global_work_size: Option<usize>,

    /// OpenCL platform index
    #[arg(short, long, default_value_t = 0)]
    platform_idx: usize,

    /// OpenCL device index
    #[arg(short, long, default_value_t = 0)]
    device_idx: usize,

    /// Regex pattern to search
    #[arg(short, long)]
    regexes: Option<Vec<String>>,

    /// Log hashrate every N seconds
    #[arg(short, long, default_value_t = 10)]
    log_interval: u64,
}

fn main() {
    let args = Args::parse();

    let regexes = match args.regexes {
        Some(r) => r,
        None => vec![String::from("")],
    };
    let compiled_regexes: Vec<_> = regexes.iter().map(|r| Regex::new(r).unwrap()).collect();

    let pubkeys = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let next_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let current_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));

    let mut gpu = gpu::Gpu::new(gpu::GpuOptions {
        platform_idx: args.platform_idx,
        device_idx: args.device_idx,
        threads: args.threads,
        local_work_size: args.local_work_size,
        global_work_size: args.global_work_size,
    })
    .unwrap();

    let (start_write_compute_tx, start_write_compute_rx) = mpsc::channel::<()>();
    let (seeds_wrote_tx, seeds_wrote_rx) = mpsc::channel::<()>();
    let (start_keys_read_tx, start_keys_read_rx) = mpsc::channel::<()>();
    let (keys_read_tx, pubkeys_read_rx) = mpsc::channel::<()>();

    let _gpu_thread = {
        let seeds = next_seeds.clone();
        let pubkeys = pubkeys.clone();
        thread::spawn(move || loop {
            keys_read_tx.send(()).unwrap();
            start_write_compute_rx.recv().unwrap();

            gpu.write_seeds(&seeds.lock().unwrap()).unwrap();
            seeds_wrote_tx.send(()).unwrap();

            gpu.compute().unwrap();

            start_keys_read_rx.recv().unwrap();
            gpu.read_keys(&mut pubkeys.lock().unwrap()).unwrap();
        })
    };

    let max_leading_zeros: Vec<AtomicU8> = (0..(compiled_regexes.len()))
        .map(|_| AtomicU8::new(0))
        .collect();
    let mut first_run = true;

    gen_random_seeds(&mut next_seeds.lock().unwrap());

    let mut start = time::Instant::now();
    let mut iters = 0u64;

    loop {
        start_write_compute_tx.send(()).unwrap();

        pubkeys_read_rx.recv().unwrap();
        if !first_run {
            handle_keypairs(
                &current_seeds.lock().unwrap(),
                &pubkeys.lock().unwrap(),
                &regexes,
                &compiled_regexes,
                &max_leading_zeros,
            );
        }
        start_keys_read_tx.send(()).unwrap();

        gen_random_seeds(&mut current_seeds.lock().unwrap());
        seeds_wrote_rx.recv().unwrap();
        std::mem::swap(
            &mut *current_seeds.lock().unwrap(),
            &mut *next_seeds.lock().unwrap(),
        );

        iters += args.threads as u64;
        let elapsed = start.elapsed();
        if !first_run && elapsed.as_secs() > args.log_interval {
            let hashrate = iters as f64 / elapsed.as_secs_f64() / 1_000_000.0;
            eprintln!(
                "{} Hashrate: {:.2} MH/s",
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                hashrate
            );
            start = time::Instant::now();
            iters = 0;
        }
        if first_run {
            first_run = false;
        }
    }
}

fn handle_keypairs(
    seeds: &[u8],
    pubkeys: &[u8],
    regex_sources: &[String],
    regexes: &[Regex],
    max_leading_zeros: &[AtomicU8],
) {
    pubkeys
        .par_chunks_exact(32)
        .zip(seeds.par_chunks_exact(32))
        .for_each(|(pk, seed)| handle_keypair(seed, pk, regex_sources, regexes, max_leading_zeros));
}

fn gen_random_seeds(seeds: &mut [u8]) {
    seeds.par_chunks_exact_mut(128 * 1024).for_each(|seed| {
        rand::thread_rng().fill_bytes(seed);
    })
}
