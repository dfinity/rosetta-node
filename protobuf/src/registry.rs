use crate::import_mod;

import_mod!("registry", canister, v1, "canister.v1");
import_mod!("registry", crypto, v1, "crypto.v1");
import_mod!("registry", node, v1, "node.v1", {
    use super::ConnectionEndpoint;
    use std::convert::TryFrom;
    use std::fmt;
    use std::net::IpAddr;
    use std::net::SocketAddr;

    impl TryFrom<ConnectionEndpoint> for SocketAddr {
        type Error = String;

        fn try_from(ce: ConnectionEndpoint) -> Result<Self, Self::Error> {
            let port = u16::try_from(ce.port)
                .map_err(|e| format!("'{}' does not convert to u16: {}", ce.port, e.to_string()))?;
            let ip_addr = ce
                .ip_addr
                .parse::<IpAddr>()
                .map_err(|e| format!("'{}' does not parse: {}", ce.ip_addr, e.to_string()))?;
            Ok(SocketAddr::new(ip_addr, port))
        }
    }

    impl fmt::Display for ConnectionEndpoint {
        /// Does not perform any sanity checking of the data -- that can fail,
        /// and std::fmt::Error provides no mechanism to communicate the details
        /// of the failure.
        ///
        /// If you want sanity checking, get a `SocketAddr` using
        /// `SocketAddr::try_from(connection_endpoint)` and if that is Ok then
        /// format that.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if self.ip_addr.contains("::") {
                write!(f, "[{}]:{}", self.ip_addr, self.port)
            } else {
                write!(f, "{}:{}", self.ip_addr, self.port)
            }
        }
    }

    #[cfg(test)]
    mod test_try_from {
        use super::*;

        #[test]
        fn ok_ipv4() {
            let ce = ConnectionEndpoint {
                ip_addr: "127.0.0.1".into(),
                port: 80,
            };
            let sa = match SocketAddr::try_from(ce) {
                Ok(sa) => sa,
                Err(error) => panic!(error),
            };
            assert!(sa.is_ipv4(), "expected ipv4 result");
            assert_eq!(sa.port(), 80);
            assert_eq!(sa.to_string(), "127.0.0.1:80");
        }

        #[test]
        fn ok_ipv6() {
            let ce = ConnectionEndpoint {
                ip_addr: "::1".into(),
                port: 80,
            };
            let sa = match SocketAddr::try_from(ce) {
                Ok(sa) => sa,
                Err(error) => panic!(error),
            };
            assert!(sa.is_ipv6(), "expected ipv6 result");
            assert_eq!(sa.port(), 80);
            assert_eq!(sa.to_string(), "[::1]:80");
        }

        #[test]
        fn bad_port_too_high() {
            let ce = ConnectionEndpoint {
                ip_addr: "127.0.0.1".into(),
                port: 65536,
            };
            assert!(
                SocketAddr::try_from(ce).is_err(),
                "65535 is the maximum port number"
            );
        }

        #[test]
        fn bad_ip_addr() {
            let ce = ConnectionEndpoint {
                ip_addr: "256.0.0.1".into(),
                port: 80,
            };
            assert!(
                SocketAddr::try_from(ce).is_err(),
                "256.0.0.1 should not have parsed"
            );
        }
    }

    #[cfg(test)]
    mod test_fmt {
        use super::*;

        #[test]
        fn ok_looks_like_ipv6() {
            let ce = ConnectionEndpoint {
                ip_addr: "::1".into(),
                port: 80,
            };
            assert_eq!(ce.to_string(), "[::1]:80");
        }

        #[test]
        fn ok_looks_like_ipv4() {
            let ce = ConnectionEndpoint {
                ip_addr: "127.0.0.1".into(),
                port: 80,
            };
            assert_eq!(ce.to_string(), "127.0.0.1:80");
        }
    }
});
import_mod!("registry", replica_version, v1, "replica_version.v1");
import_mod!("registry", routing_table, v1, "routing_table.v1");
import_mod!("registry", subnet, v1, "subnet.v1");
