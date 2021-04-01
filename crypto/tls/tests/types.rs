use ic_crypto_tls::TlsPemParsingError;
use ic_crypto_tls::{generate_tls_keys, TlsPublicKeyCert};

const NOT_AFTER: &str = "20701231235959Z";

mod tls_public_key_cert {
    use super::*;

    #[test]
    fn should_create_certificate_from_valid_pem() {
        let (cert, _sk) = generate_tls_keys("some common name", NOT_AFTER);
        let cert_pem = cert.to_pem().unwrap();

        let cert = TlsPublicKeyCert::new_from_pem(cert_pem.clone()).unwrap();

        assert_eq!(cert_pem, cert.to_pem().unwrap());
    }

    #[test]
    fn should_return_error_if_pem_empty() {
        let empty_pem = Vec::new();

        let error = TlsPublicKeyCert::new_from_pem(empty_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Expecting: CERTIFICATE")
        ));
    }

    #[test]
    fn should_return_error_if_pem_malformed() {
        let malformed_pem = vec![42u8; 5];

        let error = TlsPublicKeyCert::new_from_pem(malformed_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Expecting: CERTIFICATE")
        ));
    }
}

mod tls_private_key {
    use super::*;
    use ic_crypto_tls::TlsPrivateKey;

    #[test]
    fn should_create_private_key_from_valid_pem() {
        let (_cert, private_key) = generate_tls_keys("some common name", NOT_AFTER);
        let private_key_pem = private_key.to_pem().unwrap();

        let private_key = TlsPrivateKey::new_from_pem(private_key_pem.clone()).unwrap();

        assert_eq!(private_key_pem, private_key.to_pem().unwrap());
    }

    #[test]
    fn should_return_error_if_pem_empty() {
        let empty_pem = Vec::new();

        let error = TlsPrivateKey::new_from_pem(empty_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Expecting: ANY PRIVATE KEY")
        ));
    }

    #[test]
    fn should_return_error_if_pem_malformed() {
        let malformed_pem = vec![42u8; 5];

        let error = TlsPrivateKey::new_from_pem(malformed_pem).unwrap_err();

        assert!(matches!(error, TlsPemParsingError { internal_error }
            if internal_error.contains("Expecting: ANY PRIVATE KEY")
        ));
    }
}