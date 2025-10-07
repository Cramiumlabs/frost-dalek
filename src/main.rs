#[cfg(not(feature = "std"))]
compile_error!("This module requires heap. Enable `std` features.");

use std::boxed::Box;
use std::io::{self, Write};

use rand::rngs::OsRng;

use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, Parameters,
    Participant, SignatureAggregator,
};

const PAGE_SIZE: usize = 4096; // 4 KB per page

fn main() {
    #[cfg(all(feature = "force-alloc", feature="fixed-heap"))]
    frost_dalek::init_heap();

    println!("Custom allocator ready. Each page = {} bytes", PAGE_SIZE);
    println!("Choose mode:");
    println!("  1) Memory allocation test");
    println!("  2) FROST test");
    println!("  q) Quit");

    loop {
        print!("\nMode> ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input.eq_ignore_ascii_case("q") {
            println!("Exiting...");
            break;
        }

        match input {
            "1" => memory_test(),
            "2" => {
                // Get n and t from user input
                print!("Enter n (total number of participants): ");
                io::stdout().flush().unwrap();
                let mut n_input = String::new();
                io::stdin().read_line(&mut n_input).unwrap();
                let n: u32 = match n_input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input for n. Please enter a valid u32 number.");
                        continue;
                    }
                };

                print!("Enter t (threshold number of signers): ");
                io::stdout().flush().unwrap();
                let mut t_input = String::new();
                io::stdin().read_line(&mut t_input).unwrap();
                let t: u32 = match t_input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input for t. Please enter a valid u32 number.");
                        continue;
                    }
                };

                // Validate that t <= n
                if t > n {
                    println!("Error: t must be less than or equal to n.");
                    continue;
                }
                if n == 0 || t == 0 {
                    println!("Error: n and t must be greater than 0.");
                    continue;
                }

                frost_test(n, t);
            }
            _ => println!("Invalid choice, enter 1, 2, or q."),
        }
    }
}

fn memory_test() {
    println!("Enter number of pages to allocate (or 'q' to quit).");
    loop {
        print!("Pages> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input.eq_ignore_ascii_case("q") {
            break;
        }

        let pages: usize = match input.parse() {
            Ok(n) => n,
            Err(_) => {
                println!("Please enter a valid number.");
                continue;
            }
        };

        let size = pages * PAGE_SIZE;
        println!("Trying to allocate {} pages = {} bytes", pages, size);

        {
            #[cfg(feature = "force-alloc")]
            print_heap_stats("Before allocating data:");
            let data = Box::new(vec![0u8; size]);
            #[cfg(feature = "force-alloc")]
            print_heap_stats("After allocating data:");
            println!("Allocated {} bytes, now dropping it...", data.capacity());
        }
        #[cfg(feature = "force-alloc")]
        print_heap_stats("Total mem after releasing:");
    }
}

fn frost_test(n: u32, t: u32) {
    let mut rng = OsRng;
    let params = Parameters { n, t };

    let mut participants: Vec<Participant> = Vec::new();
    let mut coeffs_vec = Vec::new();

    for i in 1..=n {
        let (p, coeffs) = Participant::new(&params, i, &mut rng);
        participants.push(p);
        coeffs_vec.push(coeffs);
    }

    let mut dkg_states = Vec::new();
    let mut secret_shares_all: Vec<Vec<_>> = Vec::new();

    for i in 0..n as usize {
        let mut others: Vec<Participant> = participants
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();

        let state = DistributedKeyGeneration::<_>::new(
            &params,
            &participants[i].index,
            &coeffs_vec[i],
            &mut others,
        )
        .unwrap();

        let shares = state.their_secret_shares().unwrap().clone();
        dkg_states.push(state);
        secret_shares_all.push(shares);
    }

    let mut round2_states = Vec::new();
    for i in 0..n as usize {
        let mut my_shares = Vec::new();
        for j in 0..n as usize {
            if i == j {
                continue;
            }
            // Each "j" participant has distributed shares, pick the one for "i"
            // The index depends on whether i comes before or after j in the list
            let share_index = if i < j { i } else { i - 1 };
            let share = secret_shares_all[j][share_index].clone();
            my_shares.push(share);
        }
        let state2 = dkg_states[i].clone().to_round_two(my_shares).unwrap();
        round2_states.push(state2);
    }

    let mut secret_keys = Vec::new();
    let mut group_key_opt = None;
    for i in 0..n as usize {
        let (group_key, sk) = round2_states[i]
            .clone()
            .finish(participants[i].public_key().unwrap())
            .unwrap();
        secret_keys.push(sk);
        if group_key_opt.is_none() {
            group_key_opt = Some(group_key);
        }
    }
    let group_key = group_key_opt.unwrap();

    // === Signing ===
    let context = b"GENERIC CONTEXT";
    let message = b"Generalized FROST test message";

    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

    let mut signer_indices = Vec::new();
    for i in 0..t as usize {
        let (pub_coms, sec_coms) = generate_commitment_share_lists(&mut OsRng, (i + 1) as u32, 1);
        aggregator.include_signer(
            (i + 1) as u32,
            pub_coms.commitments[0],
            (&secret_keys[i]).into(),
        );
        signer_indices.push((i, sec_coms));
    }

    let signers = aggregator.get_signers();
    let message_hash = compute_message_hash(&context[..], &message[..]);

    // Each signer creates a partial signature
    let mut partial_signatures = Vec::new();
    for (i, mut sec_coms) in signer_indices {
        let partial = secret_keys[i]
            .sign(&message_hash, &group_key, &mut sec_coms, 0, signers)
            .unwrap();
        partial_signatures.push(partial);
    }

    for partial in partial_signatures {
        aggregator.include_partial_signature(partial);
    }

    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();
    let verification_result = threshold_signature.verify(&group_key, &message_hash);

    println!(
        "FROST(n={}, t={}): signature verification = {}",
        n,
        t,
        verification_result.is_ok()
    );
}
#[cfg(feature = "force-alloc")]
fn print_heap_stats(prefix: &str) {
    let (size, used, free) = frost_dalek::heap_stats();
    println!(
        "{} Heap size = {} bytes, used = {} bytes, free = {} bytes",
        prefix, size, used, free
    );
}
