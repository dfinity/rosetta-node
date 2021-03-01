// Tests for known vulnerabilities of crypto implementations,
// based on Project Wycheproof (https://github.com/google/wycheproof)
use openssl::sha::sha256;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use crate::crypto_lib::basic_sig::ecdsa;
use std::convert::TryFrom;

#[test]
fn wycheproof_ecdsa_p256_sha256_p1363() {
    let wycheproof =
        load_tests("test_resources/ecdsa/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json")
            .unwrap();
    wycheproof.type_check();
    assert!(wycheproof.run_tests());
}

fn load_tests(file_path: &str) -> Result<Wycheproof, Box<dyn Error>> {
    let path = {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(file_path);
        path
    };
    let file = File::open(path)?;
    let wycheproof = serde_json::from_reader(BufReader::new(file))?;
    Ok(wycheproof)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Wycheproof {
    algorithm: String,
    #[allow(dead_code)]
    generatorVersion: String,
    #[allow(dead_code)]
    numberOfTests: u32,
    #[allow(dead_code)]
    header: Vec<String>,
    notes: HashMap<String, String>,
    schema: String,
    testGroups: Vec<TestGroup>,
}

impl Wycheproof {
    fn type_check(&self) {
        assert_eq!(self.algorithm, "ECDSA");
        assert_eq!(self.schema, "ecdsa_p1363_verify_schema.json");
        for group in &self.testGroups {
            group.type_check();
        }
    }

    fn run_tests(&self) -> bool {
        let mut result = true;
        for group in &self.testGroups {
            result &= group.run_tests(&self.notes);
        }
        result
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestGroup {
    key: Key,
    #[allow(dead_code)]
    keyDer: String, // hex
    #[allow(dead_code)]
    keyPem: String,
    sha: String,
    r#type: String,
    tests: Vec<TestCase>,
}

impl TestGroup {
    fn type_check(&self) {
        self.key.type_check();
        assert_eq!(self.sha, "SHA-256");
        assert_eq!(self.r#type, "EcdsaP1363Verify");
        for test in &self.tests {
            test.type_check();
        }
    }

    fn run_tests(&self, notes: &HashMap<String, String>) -> bool {
        let pk = match ecdsa::api::public_key_from_der(&hex::decode(&self.keyDer).unwrap()) {
            Err(_) => None,
            Ok(pk) => Some(pk),
        };
        let mut result = true;
        for test in &self.tests {
            let case_result = test.run_test(&pk, notes);
            result &= case_result;
        }
        result
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Key {
    curve: String,
    keySize: u32,
    r#type: String,
    uncompressed: String,
    #[allow(dead_code)]
    wx: String,
    #[allow(dead_code)]
    wy: String,
}

impl Key {
    fn type_check(&self) {
        assert_eq!(self.curve, "secp256r1");
        assert_eq!(self.keySize, 256);
        assert_eq!(self.r#type, "EcPublicKey");
        assert_eq!(self.uncompressed.len(), 130);
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
enum TestResult {
    valid,
    invalid,
    acceptable,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct TestCase {
    tcId: u32,
    comment: String,
    msg: String,
    sig: String, // hex
    result: TestResult,
    flags: Vec<String>,
}

impl TestCase {
    fn type_check(&self) {
        // Nothing to do.
    }

    fn print(&self, notes: &HashMap<String, String>, error_msg: &str) {
        println!("Test case #{} => {}", self.tcId, error_msg);
        println!("    {}", self.comment);
        println!("    result = {:?}", self.result);
        for f in &self.flags {
            println!(
                "    flag {} = {}",
                f,
                notes.get(f).map_or("unknown flag", |x| &x)
            );
        }
    }

    fn run_test(
        &self,
        pk: &Option<ecdsa::types::PublicKeyBytes>,
        notes: &HashMap<String, String>,
    ) -> bool {
        match pk {
            None => {
                let pass = match self.result {
                    TestResult::invalid | TestResult::acceptable => true,
                    TestResult::valid => false,
                };
                if !pass {
                    self.print(notes, "Invalid public key");
                }
                pass
            }
            Some(pk) => {
                let msg = hex::decode(&self.msg).unwrap();
                let sig = hex::decode(&self.sig).unwrap();
                match ecdsa::types::SignatureBytes::try_from(sig) {
                    Err(e) => {
                        let pass = match self.result {
                            TestResult::invalid | TestResult::acceptable => true,
                            TestResult::valid => false,
                        };
                        if !pass {
                            self.print(notes, "Invalid IEEE P1363 encoding for the signature");
                            println!("    {:?}", e);
                        }
                        pass
                    }
                    Ok(sig_bytes) => {
                        let msg_hash = sha256(&msg);
                        let verified = ecdsa::api::verify(&sig_bytes, &msg_hash, &pk).is_ok();
                        let pass = match self.result {
                            TestResult::acceptable => true,
                            TestResult::valid => verified,
                            TestResult::invalid => !verified,
                        };
                        if !pass {
                            self.print(
                                notes,
                                &format!(
                                    "Expected {:?} result, but the signature verification was {}",
                                    self.result, verified
                                ),
                            );
                        }
                        pass
                    }
                }
            }
        }
    }
}
