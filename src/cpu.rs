use std::{
    fs,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread, time,
};

use chrono::{SecondsFormat, Utc};
use rand::RngCore;
use rayon::prelude::*;
use regex::Regex;

use crate::{handler::handle_keypair, Args};

pub fn run_cpu(
    args: &Args,
    regexes: &[String],
    compiled_regexes: Vec<Regex>,
    csv_file: &Option<Mutex<fs::File>>,
) {
    let generated = Arc::new(AtomicU64::new(0));
    let max_leading_zeros: Vec<AtomicU8> = (0..(regexes.len())).map(|_| AtomicU8::new(0)).collect();

    let stats_thread = {
        let log_interval = args.log_interval;
        let generated = generated.clone();

        thread::spawn(move || {
            let mut start = time::Instant::now();

            loop {
                thread::sleep(time::Duration::from_secs(log_interval));

                let hashrate = generated.swap(0, Ordering::AcqRel) as f64
                    / start.elapsed().as_secs_f64()
                    / 1_000_000.0;
                start = time::Instant::now();
                eprintln!(
                    "{} Hashrate: {:.3} MH/s",
                    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                    hashrate
                );
            }
        })
    };

    rayon::iter::repeat(()).for_each(|_| {
        let mut rng = rand::thread_rng();

        for _ in 0..64 * 1024 {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            let kp = ed25519_dalek::SigningKey::from_bytes(&seed);
            let binding = kp.verifying_key();
            let public = binding.as_bytes();
            handle_keypair(
                &seed,
                public,
                regexes,
                &compiled_regexes,
                &max_leading_zeros,
                csv_file,
            );
        }

        generated.fetch_add(64 * 1024, Ordering::AcqRel);
    });

    stats_thread.join().unwrap();
}
