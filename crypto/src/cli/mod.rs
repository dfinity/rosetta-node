//! Command line for crypto component.
//! Subcommands are used to direct work to subcomponents.
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString, ToString};
mod clib;
pub mod csp;

#[derive(EnumString, EnumIter, ToString)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Lib,
    Csp,
    Idkm,
}

fn help_str() -> String {
    Command::iter().fold("Subcommands:\n".to_string(), |accumulator, next| {
        format!("{}{}\n", accumulator, next.to_string())
    })
}

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [] => Err((help_str(), 1)),
        _ => {
            let command = Command::from_str(&args[0]).map_err(|_| {
                (
                    format!("Unsupported subcommand '{}'.\n{}", args[0], help_str()),
                    1,
                )
            })?;
            let args = &args[1..];
            match command {
                Command::Lib => clib::main(args),
                Command::Csp => csp::main(args),
                _ => unimplemented!(),
            }
        }
    }
}
