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

    let pubkeys = Arc::new(Mutex::new(vec![0xFF; 32 * args.threads]));
    let new_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let current_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));

    let mut gpu = gpu::Gpu::new(gpu::GpuOptions {
        platform_idx: args.platform_idx,
        device_idx: args.device_idx,
        threads: args.threads,
        local_work_size: args.local_work_size,
        global_work_size: args.global_work_size,
    })
    .unwrap();

    let (gpu_tx, gpu_rx) = mpsc::channel::<()>();
    let (cpu_tx, cpu_rx) = mpsc::channel::<()>();
    let _gpu_thread = {
        let seeds = current_seeds.clone();
        let pubkeys = pubkeys.clone();
        thread::spawn(move || loop {
            gpu_rx.recv().unwrap();

            gpu.write_seeds(&seeds.lock().unwrap()).unwrap();
            cpu_tx.send(()).unwrap();

            gpu.compute().unwrap();

            gpu_rx.recv().unwrap();
            gpu.read_keys(&mut pubkeys.lock().unwrap()).unwrap();
        })
    };

    let max_leading_zeros: Vec<AtomicU8> = (0..(compiled_regexes.len()))
        .map(|_| AtomicU8::new(0))
        .collect();
    let mut first_run = true;

    gen_random_seeds(&mut new_seeds.lock().unwrap());

    let mut start = time::Instant::now();
    let mut iters = 0u64;

    loop {
        // start seeds writing and pubkeys computing
        gpu_tx.send(()).unwrap();

        // handle already generated pubkeys
        if !first_run {
            handle_keypairs(
                &current_seeds.lock().unwrap(),
                &pubkeys.lock().unwrap(),
                &regexes,
                &compiled_regexes,
                &max_leading_zeros,
            );
        } else {
            first_run = false;
        }

        // allow gpu to read generated keys
        gpu_tx.send(()).unwrap();

        // generate new seeds
        gen_random_seeds(&mut current_seeds.lock().unwrap());

        // wait for GPU to finish writing seeds and swap them
        cpu_rx.recv().unwrap();
        std::mem::swap(
            &mut current_seeds.lock().unwrap(),
            &mut new_seeds.lock().unwrap(),
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
