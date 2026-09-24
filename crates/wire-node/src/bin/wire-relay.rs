fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = wire_relay::run(&args) {
        eprintln!("relay: {e}");
        std::process::exit(1);
    }
}
