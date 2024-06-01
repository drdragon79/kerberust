use clap::Parser;
use kerberust::arguments::*;
use kerberust::helpers::BANNER;

fn main() {
    let cli = Arguments::parse();

    println!("{}", BANNER);

    match cli.mode {
        Mode::Userbrute(args) => {
            kerberust::userbrute::start(args);
        }
        Mode::Stringtokey(args) => {
            kerberust::stringtokey::start(args);
        }
        Mode::Asktgt(args) => {
            kerberust::asktgt::start(args);
        }
    }
}
