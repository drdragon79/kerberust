use clap::Parser;
use kerberust::arguments::*;

fn main() {
    let cli = Arguments::parse();

    match cli.mode {
        Mode::Userbrute(args) => {
            todo!()
        }
        Mode::Stringtokey(args) => {
            todo!()
        }
        Mode::Asktgt(args) => {
            todo!()
        }
    }
}
