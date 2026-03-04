//! Rust-based vector generator for dns-vectors.json.
//! Produces the same JSON format as the C gen_vectors tool, using A records.

use serde::Serialize;
use slipstream_dns::{
    build_qname, encode_query, encode_response, QueryParams, Question, Rcode, ResponseParams,
    CLASS_IN, RR_A, RR_TXT,
};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

#[derive(Serialize)]
struct VectorFile {
    schema_version: u32,
    generated_by: &'static str,
    vectors: Vec<Vector>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    domain: String,
    id: u16,
    payload_len: usize,
    payload_hex: String,
    mode: String,
    expected_action: String,
    qname: String,
    query: Packet,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_ok: Option<ResponsePacket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_no_data: Option<ResponsePacket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_error: Option<ResponsePacket>,
}

#[derive(Serialize)]
struct Packet {
    packet_len: usize,
    packet_hex: String,
}

#[derive(Serialize)]
struct ResponsePacket {
    rcode: String,
    packet_len: usize,
    packet_hex: String,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let input_path = args.get(1).map(|s| s.as_str()).unwrap_or("vectors.txt");
    let vectors = parse_vectors(input_path)?;
    let output = serde_json::to_string_pretty(&VectorFile {
        schema_version: 2,
        generated_by: "slipstream-dns gen_vectors (Rust)",
        vectors,
    })
    .expect("serialize JSON");
    io::stdout().write_all(output.as_bytes())?;
    Ok(())
}

fn parse_vectors(path: &str) -> io::Result<Vec<Vector>> {
    let base = Path::new(path).parent().unwrap_or(Path::new("."));
    let path = if path.contains('/') {
        path.to_string()
    } else {
        format!("{}/{}", base.display(), path)
    };
    let file = fs::File::open(&path)?;
    let mut vectors = Vec::new();
    for (line_num, line) in io::BufReader::new(file).lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let v = parse_line(line, line_num + 1)?;
        vectors.push(v);
    }
    Ok(vectors)
}

fn parse_line(line: &str, _line_num: usize) -> io::Result<Vector> {
    let parts: Vec<&str> = line.splitn(8, ',').map(|s| s.trim()).collect();
    let name = parts
        .first()
        .ok_or_else(|| invalid("missing name"))?
        .to_string();
    let id = parse_hex_u16(parts.get(1).ok_or_else(|| invalid("missing id"))?)?;
    let domain = parts
        .get(2)
        .ok_or_else(|| invalid("missing domain"))?
        .to_string();
    let payload_hex = parts.get(3).unwrap_or(&"").to_string();
    let mode = parts.get(4).unwrap_or(&"normal").to_string();
    let qname_override = parts.get(5).filter(|s| !s.is_empty() && *s != &"-");
    let _error_rcode = parts.get(6).filter(|s| !s.is_empty() && *s != &"-");
    let raw_query_hex = parts.get(7).filter(|s| !s.is_empty() && *s != &"-");

    let mode_lower = mode.to_lowercase();
    let raw_mode = mode_lower == "raw_query_hex";
    let payload = if payload_hex == "-" || payload_hex.is_empty() {
        vec![]
    } else {
        decode_hex(&payload_hex)
    };
    let payload_len = payload.len();

    let (qtype, qdcount, is_query) = match mode_lower.as_str() {
        "non_a" => (RR_TXT, 1, true), // TXT query when A is expected -> error
        "qdcount_zero" => (RR_A, 0, true),
        "not_query" => (RR_A, 1, false),
        _ => (RR_A, 1, true),
    };

    let qname = if let Some(q) = qname_override {
        let mut q = q.to_string();
        if !q.ends_with('.') {
            q.push('.');
        }
        q
    } else if raw_mode {
        String::new()
    } else if payload_len > 0 {
        build_qname(&payload, &domain).map_err(|e| invalid(&e.to_string()))?
    } else {
        return Err(invalid("payload empty for normal mode"));
    };

    if !raw_mode
        && matches!(
            mode_lower.as_str(),
            "invalid_base32" | "suffix_mismatch" | "empty_subdomain"
        )
        && qname_override.is_none()
    {
        return Err(invalid("qname_override required for this mode"));
    }

    let query = if let Some(hex) = raw_query_hex {
        let bytes = decode_hex(hex);
        Packet {
            packet_len: bytes.len(),
            packet_hex: hex_encode(&bytes),
        }
    } else {
        let params = QueryParams {
            id,
            qname: &qname,
            qtype,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount,
            is_query,
        };
        let bytes = encode_query(&params).map_err(|e| invalid(&e.to_string()))?;
        Packet {
            packet_len: bytes.len(),
            packet_hex: hex_encode(&bytes),
        }
    };

    let question = Question {
        name: qname.clone(),
        qtype,
        qclass: CLASS_IN,
    };

    let emit_response_ok = payload_len > 0 && !raw_mode && mode_lower == "normal";
    let emit_response_no_data = !raw_mode;
    let emit_response_error = matches!(
        mode_lower.as_str(),
        "invalid_base32"
            | "suffix_mismatch"
            | "non_a"
            | "empty_subdomain"
            | "qdcount_zero"
            | "not_query"
    );

    let response_ok = if emit_response_ok {
        let encoded = encode_response(&ResponseParams {
            id,
            rd: true,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        })
        .map_err(|e| invalid(&e.to_string()))?;
        Some(ResponsePacket {
            rcode: "OK".to_string(),
            packet_len: encoded.len(),
            packet_hex: hex_encode(&encoded),
        })
    } else {
        None
    };

    let fallback_question = Question {
        name: qname.clone(),
        qtype: if qdcount == 0 { RR_A } else { qtype },
        qclass: CLASS_IN,
    };
    let resp_question = if qdcount > 0 {
        &question
    } else {
        &fallback_question
    };

    let response_no_data = if emit_response_no_data {
        let encoded = encode_response(&ResponseParams {
            id,
            rd: true,
            cd: false,
            question: resp_question,
            payload: None,
            rcode: None,
        })
        .map_err(|e| invalid(&e.to_string()))?;
        Some(ResponsePacket {
            rcode: "NAME_ERROR".to_string(),
            packet_len: encoded.len(),
            packet_hex: hex_encode(&encoded),
        })
    } else {
        None
    };

    let error_rcode = match mode_lower.as_str() {
        "invalid_base32" => Rcode::ServerFailure,
        "suffix_mismatch" | "non_a" | "empty_subdomain" => Rcode::NameError,
        "qdcount_zero" | "not_query" => Rcode::FormatError,
        _ => Rcode::NameError,
    };

    let response_error = if emit_response_error {
        let encoded = encode_response(&ResponseParams {
            id,
            rd: true,
            cd: false,
            question: resp_question,
            payload: None,
            rcode: Some(error_rcode),
        })
        .map_err(|e| invalid(&e.to_string()))?;
        Some(ResponsePacket {
            rcode: rcode_to_str(error_rcode).to_string(),
            packet_len: encoded.len(),
            packet_hex: hex_encode(&encoded),
        })
    } else {
        None
    };

    Ok(Vector {
        name,
        domain,
        id,
        payload_len,
        payload_hex: if payload_hex == "-" {
            String::new()
        } else {
            payload_hex
        },
        mode: if mode.is_empty() {
            "normal".to_string()
        } else {
            mode
        },
        expected_action: if raw_mode { "drop" } else { "reply" }.to_string(),
        qname,
        query,
        response_ok,
        response_no_data,
        response_error,
    })
}

fn rcode_to_str(r: Rcode) -> &'static str {
    match r {
        Rcode::Ok => "OK",
        Rcode::FormatError => "FORMAT_ERROR",
        Rcode::ServerFailure => "SERVER_FAILURE",
        Rcode::NameError => "NAME_ERROR",
    }
}

fn parse_hex_u16(s: &str) -> io::Result<u16> {
    let s = s.trim_start_matches("0x");
    u16::from_str_radix(s, 16).map_err(|_| invalid("invalid hex id"))
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return vec![];
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
