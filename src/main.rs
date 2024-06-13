use clap::Parser;
use kerberust::arguments::*;
use kerberust::helpers::BANNER;

fn main() {
    let cli = Arguments::parse();

    if !cli.nobanner {
        println!("{}", BANNER);
    }

    match cli.mode {
        Mode::Userenum(args) => {
            kerberust::userenum::start(args);
        }
        Mode::Stringtokey(args) => {
            kerberust::stringtokey::start(args);
        }
    }
}
