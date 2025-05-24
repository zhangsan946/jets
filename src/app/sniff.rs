use super::config::{DestOverrideOption, Sniffing};
use std::collections::HashSet;

#[derive(Debug, Eq, PartialEq)]
pub enum SniffResult {
    Http(String),
    Tls(String),
    Other,
}

#[derive(Clone, Debug)]
pub struct Sniffer {
    enabled: bool,
    dest_override: HashSet<DestOverrideOption>,
}

impl Sniffer {
    pub fn new(enabled: bool, dest_override_array: Vec<DestOverrideOption>) -> Self {
        let mut dest_override = HashSet::new();
        for item in dest_override_array {
            dest_override.insert(item);
        }

        Self {
            enabled,
            dest_override,
        }
    }
}

impl From<Sniffing> for Sniffer {
    fn from(value: Sniffing) -> Self {
        Self::new(value.enabled, value.dest_override)
    }
}

// Thanks to https://github.com/eycorsican/leaf/blob/49aa8f867751a9b45ee4e15aabab5a2499d2f1b6/leaf/src/common/sniff.rs#L51
impl Sniffer {
    pub fn sniff(&self, buf: &[u8]) -> SniffResult {
        if !self.enabled {
            return SniffResult::Other;
        }
        if self.dest_override.contains(&DestOverrideOption::Tls) {
            let result = self.sniff_tls_sni(buf);
            if result != SniffResult::Other {
                return result;
            }
        }
        if self.dest_override.contains(&DestOverrideOption::Http) {
            let result = self.sniff_http_host(buf);
            if result != SniffResult::Other {
                return result;
            }
        }
        SniffResult::Other
    }

    fn sniff_http_host(&self, buf: &[u8]) -> SniffResult {
        let bytes_str = String::from_utf8_lossy(buf);
        let parts: Vec<&str> = bytes_str.split("\r\n").collect();

        if parts.is_empty() {
            return SniffResult::Other;
        }

        let http_methods = [
            "get", "post", "head", "put", "delete", "options", "connect", "patch", "trace",
        ];
        let method_str = parts[0];

        let matched_method = http_methods
            .into_iter()
            .filter(|item| method_str.to_lowercase().contains(item))
            .count();

        if matched_method == 0 {
            return SniffResult::Other;
        }

        for (idx, &el) in parts.iter().enumerate() {
            if idx == 0 || el.is_empty() {
                continue;
            }
            let inner_parts: Vec<&str> = el.split(":").collect();
            if inner_parts.len() != 2 {
                continue;
            }
            if inner_parts[0].to_lowercase() == "host" {
                return SniffResult::Http(inner_parts[1].trim().to_string());
            }
        }

        SniffResult::Other
    }

    fn sniff_tls_sni(&self, buf: &[u8]) -> SniffResult {
        // https://tls.ulfheim.net/

        let sbuf = buf;
        if sbuf.len() < 5 {
            return SniffResult::Other;
        }
        // handshake record type
        if sbuf[0] != 0x16 {
            return SniffResult::Other;
        }
        // protocol version
        if sbuf[1] != 0x3 {
            return SniffResult::Other;
        }
        let header_len = u16::from_be_bytes(sbuf[3..5].try_into().unwrap()) as usize;
        if sbuf.len() < 5 + header_len {
            return SniffResult::Other;
        }
        let sbuf = &sbuf[5..5 + header_len];
        // ?
        if sbuf.len() < 42 {
            return SniffResult::Other;
        }
        let session_id_len = sbuf[38] as usize;
        if session_id_len > 32 || sbuf.len() < 39 + session_id_len {
            return SniffResult::Other;
        }
        let sbuf = &sbuf[39 + session_id_len..];
        if sbuf.len() < 2 {
            return SniffResult::Other;
        }
        let cipher_suite_bytes = u16::from_be_bytes(sbuf[..2].try_into().unwrap()) as usize;
        if sbuf.len() < 2 + cipher_suite_bytes {
            return SniffResult::Other;
        }
        let sbuf = &sbuf[2 + cipher_suite_bytes..];
        if sbuf.is_empty() {
            return SniffResult::Other;
        }
        let compression_method_bytes = sbuf[0] as usize;
        if sbuf.len() < 1 + compression_method_bytes {
            return SniffResult::Other;
        }
        let sbuf = &sbuf[1 + compression_method_bytes..];
        if sbuf.len() < 2 {
            return SniffResult::Other;
        }
        let extensions_bytes = u16::from_be_bytes(sbuf[..2].try_into().unwrap()) as usize;
        if sbuf.len() < 2 + extensions_bytes {
            return SniffResult::Other;
        }
        let mut sbuf = &sbuf[2..2 + extensions_bytes];
        while !sbuf.is_empty() {
            // extension + extension-specific-len
            if sbuf.len() < 4 {
                return SniffResult::Other;
            }
            let extension = u16::from_be_bytes(sbuf[..2].try_into().unwrap());
            let extension_len = u16::from_be_bytes(sbuf[2..4].try_into().unwrap()) as usize;
            sbuf = &sbuf[4..];
            if sbuf.len() < extension_len {
                return SniffResult::Other;
            }
            // extension "server name"
            if extension == 0x0 {
                let mut ebuf = &sbuf[..extension_len];
                if ebuf.len() < 2 {
                    return SniffResult::Other;
                }
                let entry_len = u16::from_be_bytes(ebuf[..2].try_into().unwrap()) as usize;
                ebuf = &ebuf[2..];
                if ebuf.len() < entry_len {
                    return SniffResult::Other;
                }
                // just make sure no oob
                if ebuf.is_empty() {
                    return SniffResult::Other;
                }
                let entry_type = ebuf[0];
                // type "DNS hostname"
                if entry_type == 0x0 {
                    ebuf = &ebuf[1..];
                    // just make sure no oob
                    if ebuf.len() < 2 {
                        return SniffResult::Other;
                    }
                    let hostname_len = u16::from_be_bytes(ebuf[..2].try_into().unwrap()) as usize;
                    ebuf = &ebuf[2..];
                    if ebuf.len() < hostname_len {
                        return SniffResult::Other;
                    }
                    return SniffResult::Tls(String::from_utf8_lossy(&ebuf[..hostname_len]).into());
                } else {
                    // TODO
                    // I assume there's only "DNS hostname" type
                    // in the the "server name" extension, should
                    // check if this is true later.
                    //
                    // I also assume there's only one entry in the
                    // "server name" extension list.
                    return SniffResult::Other;
                }
            } else {
                sbuf = &sbuf[extension_len..];
            }
        }
        SniffResult::Other
    }
}
