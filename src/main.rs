use std::io::{self, Write};
use std::boxed::Box;

const PAGE_SIZE: usize = 4096; // 4 KB per page

#[cfg(feature = "force-alloc")]
fn main() {
    frost_dalek::init_heap();

    println!("Custom allocator ready. Each page = {} bytes", PAGE_SIZE);
    println!("Enter number of pages to allocate (or 'q' to quit).");

    loop {
        print!("\n");
        print!(" --------------------------------------------------- ");
        print!("\n");
        print!("Pages> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            println!("Exiting...");
            break;
        }

        let pages: usize = match input.parse() {
            Ok(n) => n,
            Err(_) => {
                println!("Please enter a valid number or 'q' to quit.");
                continue;
            }
        };

        let size = pages * PAGE_SIZE;
        println!("Trying to allocate {} pages = {} bytes", pages, size);

        {
            print_heap_stats("Before allocating data:");
            let data = Box::new(vec![0u8; size]); // allocated inside scope
            print_heap_stats("After allocating data:");
            println!("Allocated {} bytes, now dropping it...", data.capacity());
        }

        print_heap_stats("Total mem after releasing:");
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


#[cfg(not(any(feature = "alloc", feature = "force-alloc")))]
fn main() {
    eprintln!("This example requires `alloc` or `force-alloc` feature.");
}
