//! A module to handle command line arguments for authz deltas.

use ic_base_types::{CanisterId, PrincipalId};
use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;
use strum_macros::EnumString;

/// An argument for an authz delta. Designed for user-friendly parsing and
/// formatting.
///
/// Format: <canister-id>?:<method_name>[><]<caller_principal>?
///
/// This format was chosen to be unambiguous: semicolon (:) and the two angle
/// brackets (> and <) never appear inside a principal id.
///
/// : is simply used as a separator.
/// < means "add to authorization list"
/// > means "remove from authorization list"
#[derive(PartialEq, Eq, Clone)]
pub struct AuthzDeltaArg {
    pub canister_id: Option<CanisterId>,
    pub method_name: String,
    pub op: Op,
    pub caller_id: Option<PrincipalId>,
}

impl fmt::Display for AuthzDeltaArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}{}{}",
            self.canister_id.map_or_else(String::new, |c| c.to_string()),
            self.method_name,
            self.op.to_string(),
            self.caller_id.map_or_else(String::new, |p| p.to_string())
        )
    }
}
impl fmt::Debug for AuthzDeltaArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// Regex for the canister to affect, with a captured group named 'canister'.
const CANISTER_RE: &str = "(?P<canister>[^:><]*)";

/// Regex for the method name to affect, with a captured group named 'method'.
const METHOD_RE: &str = "(?P<method>.*)";

/// Regex for the operation (authorize/deauthorize), with a captured group named
/// 'op'.
const OP_RE: &str = "(?P<op>[><])";

/// Regex for the caller to be (de)authorized,  with a captured group named
/// 'caller'.
const CALLER_RE: &str = "(?P<caller>[^:><]*)";

lazy_static! {
    /// The compiled regex to parse the an auth delta argument.
    static ref RE: Regex =
        Regex::new(format!("{}:{}{}{}", CANISTER_RE, METHOD_RE, OP_RE, CALLER_RE).as_str())
            .unwrap();
}

impl std::str::FromStr for AuthzDeltaArg {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let captures = RE.captures(input).ok_or_else(|| {
            format!(
                "The input string '{}' cannot be parsed as a authz delta.

                The expected format is: <canister?>:<method_name><op><caller?>, where

                  <canister_id?> is the optional canister to affect, in principal text format. If absent, it is implicit.
                  <method_name> is the method for which to change the authorizations.
                  <op> is either '<' to add an authorized caller or '>' to remove one.
                  <caller?> is the optional caller to authorize or de-authorize. If absent, it is implicit.

                 Example:
                 'rwlgt-iiaaa-aaaaa-aaaaa-cai:atomic_mutate<2vxsx-fae' means 'Insert 2vxsx-fae into the list of authorized callers of method atomic_mutate of canister rwlgt-iiaaa-aaaaa-aaaaa-cai'.
                ",
                input
            )
        })?;
        let canister_id = match captures.name("canister")
            .expect("Despite getting a regex match, there is no capture for the canister. That is thought to be impossible").as_str() {
            "" => None,
            s => Some(CanisterId::from_str(s)
                .map_err(|e| format!("Interpreted '{}' as the canister to be modified, but that is not a legal canister id because: {}", s, e))?)
        };
        let caller_id = match captures.name("caller")
            .expect("Despite getting a regex match, there is no capture for the caller. That is thought to be impossible").as_str(){
            "" => None,
           s => Some(PrincipalId::from_str(s)
                .map_err(|e| format!("Interpreted '{}' as the caller to be (de?)authorize, but that is not a legal principal id because: {}", s, e))?)
        };
        let op_str =  captures.name("op").expect("Despite getting a regex match, there is no capture for the operation (< or >). That is thought to be impossible").as_str();
        let op = Op::from_str(op_str).map_err(|e| format!("Interpreted '{}' as the operation, but it's not legal. It should be either < (authorize) or > (deauthorize). The underlying error is: {}.", op_str, e))?;
        let method_name =  captures.name("method").expect("Despite getting a regex match, there is no capture for the method name. That is thought to be impossible").as_str().to_string();

        Ok(AuthzDeltaArg {
            canister_id,
            method_name,
            op,
            caller_id,
        })
    }
}

#[derive(EnumString, PartialEq, Eq, Clone, Copy, strum_macros::Display)]
pub enum Op {
    #[strum(serialize = "<")]
    Authorize,

    #[strum(serialize = ">")]
    Deauthorize,
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use std::str::FromStr;

    #[test]
    pub fn test_parsing_no_match() {
        assert_matches!(AuthzDeltaArg::from_str("nqhdqf"),
        Err(s) if s.to_lowercase().contains("expected format is: <canister?>:<method_name><op><caller?>"));
        assert_matches!(AuthzDeltaArg::from_str(""),
        Err(s) if s.to_lowercase().contains("expected format is: <canister?>:<method_name><op><caller?>"));
        assert_matches!(AuthzDeltaArg::from_str(":"),
        Err(s) if s.to_lowercase().contains("expected format is: <canister?>:<method_name><op><caller?>"));
        assert_matches!(AuthzDeltaArg::from_str(">"),
        Err(s) if s.to_lowercase().contains("expected format is: <canister?>:<method_name><op><caller?>"));
        assert_matches!(AuthzDeltaArg::from_str("<"),
        Err(s) if s.to_lowercase().contains("expected format is: <canister?>:<method_name><op><caller?>"));
    }

    #[test]
    pub fn test_parsing_ok() {
        for canister_id in &[
            None,
            Some(CanisterId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()),
        ] {
            for method_name in &["", "foo", "with space", "💩🤮", ":", ">", "<"] {
                for op in &[Op::Deauthorize, Op::Authorize] {
                    for caller_id in &[None, Some(PrincipalId::from_str("2vxsx-fae").unwrap())] {
                        let delta = AuthzDeltaArg {
                            canister_id: *canister_id,
                            method_name: (*method_name).to_string(),
                            op: *op,
                            caller_id: *caller_id,
                        };
                        let str = delta.to_string();
                        assert_eq!(AuthzDeltaArg::from_str(str.as_str()).unwrap(), delta);
                    }
                }
            }
        }
    }

    #[test]
    pub fn test_parsing_bad_canister_id() {
        assert_matches!(AuthzDeltaArg::from_str("notaprincipal:method_name>"),
        Err(s) if s.to_lowercase().contains("not a legal canister id"));
        assert_matches!(AuthzDeltaArg::from_str("notaprincipal:method_name>2vxsx-fae"),
        Err(s) if s.to_lowercase().contains("not a legal canister id"));
        assert_matches!(AuthzDeltaArg::from_str("notaprincipal:method_name<"),
        Err(s) if s.to_lowercase().contains("not a legal canister id"));
        assert_matches!(AuthzDeltaArg::from_str("notaprincipal:method_name<2vxsx-fae"),
        Err(s) if s.to_lowercase().contains("not a legal canister id"));
    }

    #[test]
    pub fn test_parsing_bad_caller() {
        assert_matches!(AuthzDeltaArg::from_str(":method_name>notaprincipal"),
        Err(s) if s.to_lowercase().contains("not a legal principal id"));
        assert_matches!(AuthzDeltaArg::from_str(":method_name<notaprincipal"),
        Err(s) if s.to_lowercase().contains("not a legal principal id"));
        assert_matches!(AuthzDeltaArg::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai:method_name>notaprincipal"),
        Err(s) if s.to_lowercase().contains("not a legal principal id"));
        assert_matches!(AuthzDeltaArg::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai:method_name<notaprincipal"),
        Err(s) if s.to_lowercase().contains("not a legal principal id"));
    }
}
