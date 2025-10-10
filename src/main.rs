#[cfg(not(feature = "std"))]
compile_error!("This module requires heap. Enable `std` features.");

use std::boxed::Box;
use std::io::{self, Write};

use curve25519_dalek::digest::crypto_common::Key;
use frost_dalek::protocol::PreSigning;
use rand::rngs::OsRng;

use frost_dalek;

const PAGE_SIZE: usize = 4096; // 4 KB per page

use std::mem;

fn main() {
    #[cfg(all(feature = "force-alloc", feature = "fixed-heap"))]
    frost_dalek::init_heap();

    println!(
        "Size of MyStruct: {} bytes",
        mem::size_of::<frost_dalek::Signer>()
    );

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
    use frost_dalek::protocol::{Keygen, Party, Signing};

    let mut rng = OsRng;

    println!("\n=== FROST Protocol Test Using protocol::Party ===");
    println!("Parameters: n={}, t={}", n, t);

    // Create parties
    println!("\n[Step 1] Creating {} parties...", n);
    let mut parties: Vec<Party> = Vec::new();
    for i in 1..=n {
        match Party::new(i, t, n) {
            Ok(party) => {
                println!("  Party {} created successfully", i);
                parties.push(party);
            }
            Err(e) => {
                println!("  Error creating party {}: {:?}", i, e);
                return;
            }
        }
    }

    // === Keygen Phase ===
    println!("\n[Step 2] Keygen Phase - Round 1: Generating commitments...");
    let mut messages: Vec<Vec<frost_dalek::keygen::Participant>> = vec![Vec::new(); n as usize];

    for (i, party) in parties.iter_mut().enumerate() {
        let message1 = party.generate_keygen_message1(&mut rng);
        println!("  Party {} generated commitment", i + 1);

        // Broadcast to all other parties
        for j in 0..n as usize {
            if i != j {
                messages[j].push(message1.clone());
            }
        }
    }

    println!("\n[Step 3] Keygen Phase - Round 2: Processing commitments and generating shares...");
    let mut all_shares: Vec<Vec<frost_dalek::keygen::SecretShare>> = Vec::new();

    for (i, party) in parties.iter_mut().enumerate() {
        match party.handle_keygen_message1(messages[i].clone()) {
            Ok(shares) => {
                println!(
                    "  Party {} processed commitments and generated {} shares",
                    i + 1,
                    shares.len()
                );
                all_shares.push(shares);
            }
            Err(e) => {
                println!("  Error in party {} round 1: {:?}", i + 1, e);
                return;
            }
        }
    }

    println!("\n[Step 4] Keygen Phase - Round 3: Distributing and processing shares...");
    for i in 0..n as usize {
        let mut my_shares = Vec::new();
        for j in 0..n as usize {
            if i == j {
                continue;
            }
            let share_index = if i < j { i } else { i - 1 };
            my_shares.push(all_shares[j][share_index].clone());
        }

        match parties[i].handle_keygen_message2(my_shares) {
            Ok(_) => {
                println!("  Party {} completed keygen", i + 1);
            }
            Err(e) => {
                println!("  Error in party {} round 2: {:?}", i + 1, e);
                return;
            }
        }
    }

    // Verify keygen completion
    println!("\n[Step 5] Verifying keygen completion...");
    for (i, party) in parties.iter().enumerate() {
        if party.is_keygen_complete() {
            println!("  Party {} keygen complete ✓", i + 1);
        } else {
            println!("  Party {} keygen NOT complete ✗", i + 1);
            return;
        }
    }

    let _group_key = parties[0].get_group_key().unwrap().clone();
    println!("\n  Group key established successfully!");

    // === Signing Phase ===
    println!(
        "\n[Step 6] Signing Phase: Generating commitments for {} signers...",
        t
    );
    let message = b"Test message for FROST threshold signature";
    println!("  Message: {:?}", String::from_utf8_lossy(message));

    let mut commitment_lists = Vec::new();
    for i in 0..t as usize {
        match parties[i].generate_presigning_data(1, &mut rng) {
            Ok((pub_coms, sec_coms)) => {
                println!("  Party {} generated commitment data", i + 1);
                commitment_lists.push((i, pub_coms, sec_coms));
            }
            Err(e) => {
                println!("  Error generating commitment for party {}: {:?}", i + 1, e);
                return;
            }
        }
    }

    println!("\n[Step 7] Prepare signers vector");
    let mut signers: Vec<frost_dalek::Signer> = Vec::new();
    for (i, pub_coms, _) in &commitment_lists {
        let signer = frost_dalek::signature::Signer {
            participant_index: (*i + 1) as u32,
            published_commitment_share: pub_coms.commitments[0],
            public_key: parties[*i].get_secret_share().unwrap().into(),
        };
        signers.push(signer);
    }

    println!("\n[Step 8] Generating partial signatures...");
    let mut partial_signatures = Vec::new();
    for (i, _, mut sec_coms) in commitment_lists {
        // Clone signers to avoid borrow checker issues
        match parties[i].sign(message, &mut sec_coms, 0, &signers) {
            Ok(partial) => {
                println!("  Party {} created partial signature", i + 1);
                partial_signatures.push(partial);
            }
            Err(e) => {
                println!("  Error signing for party {}: {:?}", i + 1, e);
                return;
            }
        }
    }

    println!("\n[Step 9] Combining partial signatures...");
    match parties[0].combine_partial_signatures(message, partial_signatures) {
        Ok((_threshold_signature, verified)) => {
            println!("\n=== FROST Test Results ===");
            println!("Threshold signature created successfully!");
            println!(
                "Signature verification: {}",
                if verified { "✓ PASSED" } else { "✗ FAILED" }
            );
            println!("Parameters: n={}, t={}", n, t);

            if verified {
                println!("\n🎉 FROST protocol test completed successfully!");
            }
        }
        Err(e) => {
            println!("  Error combining signatures: {:?}", e);
        }
    }
}

#[cfg(feature = "force-alloc")]
fn print_heap_stats(prefix: &str) {
    let (size, used, free) = frost_dalek::heap_stats();
    println!(
        "{} Heap size = {} bytes, used = {} bytes, free = {} bytes",
        prefix, size, used, free
    );
}
