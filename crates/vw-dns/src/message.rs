//! DNS wire-format helpers: query validation, synthesized answers, EDNS
//! hygiene (DNSSEC OK, Client Subnet stripping) and UDP size fitting.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::error::{DnsError, Result};

/// EDNS UDP payload size we advertise (DNS flag day 2020 recommendation).
pub const EDNS_UDP_SIZE: u16 = 1232;
/// Classic DNS UDP limit for clients that do not speak EDNS.
pub const LEGACY_UDP_SIZE: usize = 512;
/// Largest DNS message representable on a stream transport.
pub const MAX_MESSAGE: usize = u16::MAX as usize;

/// Parse and validate a client query: exactly one question, QR clear, opcode QUERY.
///
/// On failure returns the response code that should be sent back
/// (`FORMERR` / `NOTIMP`) together with the error.
pub fn parse_query(wire: &[u8]) -> std::result::Result<Message, (ResponseCode, DnsError)> {
    let msg = Message::from_vec(wire).map_err(|_| {
        (
            ResponseCode::FormErr,
            DnsError::Malformed("undecodable query"),
        )
    })?;
    if msg.message_type() != MessageType::Query {
        return Err((
            ResponseCode::FormErr,
            DnsError::Malformed("response sent as query"),
        ));
    }
    if msg.op_code() != OpCode::Query {
        return Err((
            ResponseCode::NotImp,
            DnsError::Malformed("unsupported opcode"),
        ));
    }
    if msg.queries().len() != 1 {
        return Err((
            ResponseCode::FormErr,
            DnsError::Malformed("query must carry exactly one question"),
        ));
    }
    if !msg.answers().is_empty() || !msg.name_servers().is_empty() {
        return Err((
            ResponseCode::FormErr,
            DnsError::Malformed("query carries answer records"),
        ));
    }
    Ok(msg)
}

/// Lower-case, dot-separated, no trailing dot rendering of a name's raw labels.
///
/// Labels are kept byte-for-byte (ASCII-lowercased), so this never fails and
/// matches what the Shield indexes.
pub fn name_key(name: &Name) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    for (i, label) in name.iter().enumerate() {
        if i > 0 {
            out.push(b'.');
        }
        out.extend(label.iter().map(|b| b.to_ascii_lowercase()));
    }
    out
}

/// Build an empty response skeleton for `query` with the given RCODE: same id,
/// question, RD and CD bits; RA set; EDNS echoed only if the client used it.
pub fn response_for(query: &Message, rcode: ResponseCode) -> Message {
    let mut r = Message::new();
    r.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(query.op_code())
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(true)
        .set_checking_disabled(query.checking_disabled())
        .set_response_code(rcode);
    r.add_queries(query.queries().iter().cloned());
    if let Some(e) = query.extensions().as_ref() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_UDP_SIZE);
        edns.set_dnssec_ok(e.flags().dnssec_ok);
        r.set_edns(edns);
    }
    r
}

/// Encode a message, mapping encoder failures to [`DnsError::Encode`].
pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec().map_err(|_| DnsError::Encode)
}

/// A well-formed error response for arbitrary (possibly garbage) query bytes.
///
/// Used when the query itself cannot be parsed: keeps the id when at least
/// two bytes are present so the client can match it.
pub fn error_for_raw(query_wire: &[u8], rcode: ResponseCode) -> Vec<u8> {
    if let Ok(q) = Message::from_vec(query_wire) {
        if let Ok(v) = encode(&response_for(&q, rcode)) {
            return v;
        }
    }
    let id = if query_wire.len() >= 2 {
        u16::from_be_bytes([query_wire[0], query_wire[1]])
    } else {
        0
    };
    let rd = query_wire.get(2).map(|b| b & 0x01).unwrap_or(0);
    let mut h = [0u8; 12];
    h[0..2].copy_from_slice(&id.to_be_bytes());
    h[2] = 0x80 | rd; // QR, opcode QUERY
    h[3] = 0x80 | (u16::from(rcode) as u8 & 0x0f); // RA + low RCODE bits
    h.to_vec()
}

/// Error response (SERVFAIL, REFUSED, ...) for a parsed query.
pub fn error_response(query: &Message, rcode: ResponseCode) -> Vec<u8> {
    encode(&response_for(query, rcode)).unwrap_or_else(|_| error_for_raw(&[], rcode))
}

/// Prepare the query we send upstream: random id, EDNS with DO=1 and our
/// payload size, EDNS Client Subnet removed, RD set.
pub fn prepare_upstream_query(query: &Message, id: u16) -> Result<Vec<u8>> {
    let mut q = Message::new();
    q.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_checking_disabled(query.checking_disabled());
    q.add_queries(query.queries().iter().cloned());
    let mut edns = Edns::new();
    if let Some(client) = query.extensions().as_ref() {
        // Keep the client's options except ECS (and anything we must not forward).
        for (code, opt) in client.options().as_ref() {
            if !matches!(code, EdnsCode::Subnet) {
                edns.options_mut().insert(opt.clone());
            }
        }
    }
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.set_max_payload(EDNS_UDP_SIZE);
    edns.set_dnssec_ok(true);
    q.set_edns(edns);
    encode(&q)
}

/// Remove an EDNS Client Subnet option from a message, returning true if one was present.
pub fn strip_ecs(msg: &mut Message) -> bool {
    match msg.extensions_mut() {
        Some(edns) if edns.option(EdnsCode::Subnet).is_some() => {
            edns.options_mut().remove(EdnsCode::Subnet);
            true
        }
        _ => false,
    }
}

/// Whether the response carries the Authenticated Data flag.
pub fn ad_flag(wire: &[u8]) -> bool {
    wire.len() >= 4 && wire[3] & 0x20 != 0
}

/// Verify that `response` answers `query` (QR set, same id, same question).
pub fn response_matches(query: &Message, response: &Message) -> bool {
    if response.message_type() != MessageType::Response || response.id() != query.id() {
        return false;
    }
    match (query.queries().first(), response.queries().first()) {
        (Some(q), Some(r)) => {
            q.query_type() == r.query_type()
                && q.query_class() == r.query_class()
                && name_key(q.name()) == name_key(r.name())
        }
        // Some servers omit the question on errors; accept only error rcodes then.
        (Some(_), None) => response.response_code() != ResponseCode::NoError,
        _ => false,
    }
}

fn is_dnssec_type(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
    )
}

/// Drop DNSSEC records that the client did not ask for (DO=0), RFC 4035 §3.2.1.
pub fn strip_dnssec(msg: &mut Message, qtype: RecordType) {
    let keep = |r: &Record| !is_dnssec_type(r.record_type()) || r.record_type() == qtype;
    msg.answers_mut().retain(keep);
    msg.name_servers_mut().retain(keep);
    msg.additionals_mut().retain(keep);
}

/// Cacheable TTL of a response: the minimum TTL of all records, or for
/// negative answers the SOA minimum (RFC 2308). `None` = do not cache.
pub fn cache_ttl(msg: &Message) -> Option<u32> {
    match msg.response_code() {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        _ => return None,
    }
    if msg.truncated() {
        return None;
    }
    let mut min: Option<u32> = None;
    for r in msg.answers() {
        min = Some(min.map_or(r.ttl(), |m| m.min(r.ttl())));
    }
    if msg.answers().is_empty() {
        // Negative answer: SOA in authority bounds the TTL.
        for r in msg.name_servers() {
            if let RData::SOA(soa) = r.data() {
                let t = r.ttl().min(soa.minimum());
                min = Some(min.map_or(t, |m| m.min(t)));
            }
        }
    }
    min
}

/// Decrement every record TTL by `elapsed` seconds (cache hits).
pub fn age_ttls(msg: &mut Message, elapsed: u32) {
    let age = |r: &mut Record| {
        let t = r.ttl().saturating_sub(elapsed);
        r.set_ttl(t);
    };
    msg.answers_mut().iter_mut().for_each(age);
    msg.name_servers_mut().iter_mut().for_each(age);
    msg.additionals_mut().iter_mut().for_each(age);
}

/// Clamp every TTL to `max` seconds.
pub fn clamp_ttls(msg: &mut Message, max: u32) {
    let clamp = |r: &mut Record| {
        if r.ttl() > max {
            r.set_ttl(max);
        }
    };
    msg.answers_mut().iter_mut().for_each(clamp);
    msg.name_servers_mut().iter_mut().for_each(clamp);
    msg.additionals_mut().iter_mut().for_each(clamp);
}

/// Shape an upstream answer for a specific client: client id, EDNS only if
/// the client used EDNS, DNSSEC records and AD only if the client asked.
pub fn finalize_for_client(resp: &mut Message, client: &Message) {
    resp.set_id(client.id());
    resp.set_recursion_desired(client.recursion_desired());
    resp.set_recursion_available(true);
    let client_do = client
        .extensions()
        .as_ref()
        .map(|e| e.flags().dnssec_ok)
        .unwrap_or(false);
    let qtype = client
        .queries()
        .first()
        .map(|q| q.query_type())
        .unwrap_or(RecordType::A);
    if !client_do {
        strip_dnssec(resp, qtype);
        // RFC 6840 §5.8: AD only when the query had DO or AD set.
        if !client.authentic_data() {
            resp.set_authentic_data(false);
        }
    }
    match client.extensions().as_ref() {
        Some(ce) => {
            let rcode_high = resp
                .extensions()
                .as_ref()
                .map(|e| e.rcode_high())
                .unwrap_or(0);
            let mut edns = Edns::new();
            edns.set_max_payload(EDNS_UDP_SIZE);
            edns.set_dnssec_ok(ce.flags().dnssec_ok);
            edns.set_rcode_high(rcode_high);
            resp.set_edns(edns);
        }
        None => {
            *resp.extensions_mut() = None;
        }
    }
}

/// Maximum UDP response size the client accepts (`cap` bounds it, e.g. the tunnel MTU).
pub fn client_udp_limit(client: &Message, cap: usize) -> usize {
    let advertised = client
        .extensions()
        .as_ref()
        .map(|e| e.max_payload() as usize)
        .unwrap_or(LEGACY_UDP_SIZE);
    advertised.clamp(LEGACY_UDP_SIZE, cap.max(LEGACY_UDP_SIZE))
}

/// Encode `msg` so that it fits in `limit` bytes: drop additional records,
/// then authority, then trailing answers with TC=1 (RFC 2181 §9).
pub fn encode_fitting(msg: &Message, limit: usize) -> Result<Vec<u8>> {
    let wire = encode(msg)?;
    if wire.len() <= limit {
        return Ok(wire);
    }
    let mut m = msg.clone();
    m.additionals_mut().clear();
    let wire = encode(&m)?;
    if wire.len() <= limit {
        return Ok(wire);
    }
    m.name_servers_mut().clear();
    let wire = encode(&m)?;
    if wire.len() <= limit {
        return Ok(wire);
    }
    m.set_truncated(true);
    while !m.answers().is_empty() {
        m.answers_mut().pop();
        let wire = encode(&m)?;
        if wire.len() <= limit {
            return Ok(wire);
        }
    }
    encode(&m)
}

/// Is this a class we resolve (IN, or ANY for compatibility)?
pub fn class_supported(class: DNSClass) -> bool {
    matches!(class, DNSClass::IN | DNSClass::ANY)
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use hickory_proto::op::Query;

    /// Build a query wire message.
    pub fn query(name: &str, qtype: RecordType, id: u16, edns: bool) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        if edns {
            let mut e = Edns::new();
            e.set_max_payload(1232);
            m.set_edns(e);
        }
        m.to_vec().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::query;
    use super::*;
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

    #[test]
    fn garbage_gets_formerr_with_id() {
        let r = error_for_raw(&[0xab, 0xcd, 0x01], ResponseCode::FormErr);
        let m = Message::from_vec(&r).unwrap();
        assert_eq!(m.id(), 0xabcd);
        assert_eq!(m.response_code(), ResponseCode::FormErr);
        assert_eq!(m.message_type(), MessageType::Response);
        let r = error_for_raw(&[], ResponseCode::ServFail);
        assert!(Message::from_vec(&r).is_ok());
    }

    #[test]
    fn upstream_query_has_do_and_no_ecs() {
        let mut m = Message::from_vec(&query("example.com.", RecordType::A, 7, true)).unwrap();
        m.extensions_mut()
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )));
        let w = prepare_upstream_query(&m, 99).unwrap();
        let p = Message::from_vec(&w).unwrap();
        assert_eq!(p.id(), 99);
        let e = p.extensions().as_ref().unwrap();
        assert!(e.flags().dnssec_ok);
        assert!(e.option(EdnsCode::Subnet).is_none());
        assert!(!strip_ecs(&mut p.clone()));
        assert!(strip_ecs(&mut m));
    }

    #[test]
    fn rejects_multi_question_and_responses() {
        let mut m = Message::from_vec(&query("a.example.", RecordType::A, 1, false)).unwrap();
        m.add_query(m.queries()[0].clone());
        assert!(parse_query(&m.to_vec().unwrap()).is_err());
        let mut r = Message::from_vec(&query("a.example.", RecordType::A, 1, false)).unwrap();
        r.set_message_type(MessageType::Response);
        assert!(parse_query(&r.to_vec().unwrap()).is_err());
    }

    #[test]
    fn fitting_truncates() {
        let q = Message::from_vec(&query("big.example.", RecordType::A, 1, false)).unwrap();
        let mut r = response_for(&q, ResponseCode::NoError);
        for i in 0..100u8 {
            r.add_answer(Record::from_rdata(
                Name::from_ascii("big.example.").unwrap(),
                60,
                RData::A(hickory_proto::rr::rdata::A::new(10, 0, 0, i)),
            ));
        }
        let w = encode_fitting(&r, 512).unwrap();
        assert!(w.len() <= 512);
        assert!(Message::from_vec(&w).unwrap().truncated());
    }
}
