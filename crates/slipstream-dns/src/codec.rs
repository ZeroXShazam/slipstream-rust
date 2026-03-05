use crate::base32;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, RecordType, ResponseParams,
    EDNS_UDP_PAYLOAD, RR_A, RR_AAAA, RR_OPT, RR_TXT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let question = match parse_question(packet, header.offset) {
        Ok((question, _)) => question,
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if RecordType::from_qtype(question.qtype).is_none() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let payload = match base32::decode(&undotted) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::ServerFailure,
            })
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
    })
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let record_type = RecordType::from_qtype(params.question.qtype).unwrap_or(RecordType::A);
    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        ancount = match record_type {
            RecordType::A => {
                let total = 2 + payload_len;
                (total.div_ceil(4)) as u16
            }
            RecordType::Aaaa => {
                let total = 2 + payload_len;
                (total.div_ceil(16)) as u16
            }
            RecordType::Txt => {
                let total = 2 + payload_len;
                (total.div_ceil(255)) as u16
            }
        };
        let max_ancount = match record_type {
            RecordType::A => u16::MAX / 16,
            RecordType::Aaaa => u16::MAX / 24,
            RecordType::Txt => u16::MAX / 260,
        };
        if ancount > max_ancount {
            return Err(DnsError::new("payload too long"));
        }
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, ancount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if ancount > 0 {
        let payload = params.payload.unwrap_or(&[]);
        let len = payload.len();
        let total = 2 + len;

        match record_type {
            RecordType::A => {
                let padded_len = total.div_ceil(4) * 4;
                let mut buf = vec![0u8; padded_len];
                buf[0] = (len >> 8) as u8;
                buf[1] = (len & 0xFF) as u8;
                buf[2..2 + len].copy_from_slice(payload);

                for chunk in buf.chunks(4) {
                    out.extend_from_slice(&[0xC0, 0x0C]);
                    write_u16(&mut out, RR_A);
                    write_u16(&mut out, params.question.qclass);
                    write_u32(&mut out, 60);
                    write_u16(&mut out, 4);
                    out.extend_from_slice(chunk);
                }
            }
            RecordType::Aaaa => {
                let padded_len = total.div_ceil(16) * 16;
                let mut buf = vec![0u8; padded_len];
                buf[0] = (len >> 8) as u8;
                buf[1] = (len & 0xFF) as u8;
                buf[2..2 + len].copy_from_slice(payload);

                for chunk in buf.chunks(16) {
                    out.extend_from_slice(&[0xC0, 0x0C]);
                    write_u16(&mut out, RR_AAAA);
                    write_u16(&mut out, params.question.qclass);
                    write_u32(&mut out, 60);
                    write_u16(&mut out, 16);
                    out.extend_from_slice(chunk);
                }
            }
            RecordType::Txt => {
                let padded_len = total.div_ceil(255) * 255;
                let mut buf = vec![0u8; padded_len];
                buf[0] = (len >> 8) as u8;
                buf[1] = (len & 0xFF) as u8;
                buf[2..2 + len].copy_from_slice(payload);

                for chunk in buf.chunks(255) {
                    out.extend_from_slice(&[0xC0, 0x0C]);
                    write_u16(&mut out, RR_TXT);
                    write_u16(&mut out, params.question.qclass);
                    write_u32(&mut out, 60);
                    write_u16(&mut out, (chunk.len() + 1) as u16);
                    out.push(chunk.len() as u8);
                    out.extend_from_slice(chunk);
                }
            }
        }
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount == 0 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let mut out = Vec::new();
    for _ in 0..header.ancount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        let rrtype = read_u16(packet, offset)?;
        offset += 2;
        let _rrclass = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() {
            return None;
        }
        match rrtype {
            RR_A if rdlen == 4 => {
                out.extend_from_slice(&packet[offset..offset + rdlen]);
            }
            RR_AAAA if rdlen == 16 => {
                out.extend_from_slice(&packet[offset..offset + rdlen]);
            }
            RR_TXT if rdlen >= 1 => {
                let mut r = offset;
                while r < offset + rdlen {
                    let str_len = packet[r] as usize;
                    r += 1;
                    if r + str_len > offset + rdlen {
                        return None;
                    }
                    out.extend_from_slice(&packet[r..r + str_len]);
                    r += str_len;
                }
            }
            _ => return None,
        }
        offset += rdlen;
    }

    if out.len() < 2 {
        return None;
    }
    let len = ((out[0] as usize) << 8) | (out[1] as usize);
    if len > out.len() - 2 {
        return None;
    }
    Some(out[2..2 + len].to_vec())
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_response, encode_response};
    use crate::types::{Question, ResponseParams, CLASS_IN, RR_A, RR_AAAA, RR_TXT};

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_A,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        };
        assert!(encode_response(&params).is_err());
    }

    #[test]
    fn aaaa_round_trip() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_AAAA,
            qclass: CLASS_IN,
        };
        let payload = b"hello aaaa";
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(payload.as_slice()),
            rcode: None,
        };
        let encoded = encode_response(&params).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn txt_round_trip() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = b"hello txt";
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(payload.as_slice()),
            rcode: None,
        };
        let encoded = encode_response(&params).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
