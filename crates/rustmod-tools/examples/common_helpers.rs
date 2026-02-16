use rustmod_tools::common::parse_bool;

fn main() {
    for sample in ["true", "0", "on", "off", "yes", "no"] {
        println!("{sample} => {:?}", parse_bool(sample));
    }
}
