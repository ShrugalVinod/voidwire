//! CNAME uncloaking and block-response synthesis.
//!
//! Trackers increasingly hide behind first-party subdomains
//! (`metrics.shop.example CNAME shop.tracker-vendor.net`). Checking only the
//! question name misses them, so every owner name and CNAME / ANAME target in
//! the answer chain is run through the Shield.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use vw_core::config::{BlockMode, ShieldCategory};

use crate::message::response_for;
use crate::shield::Shield;

/// TTL of synthesized block answers (short, so unblocking takes effect fast).
pub const BLOCK_TTL: u32 = 60;

/// Return the category of the first answer-chain name that the Shield blocks.
pub fn find_cloaked(shield: &Shield, response: &Message) -> Option<ShieldCategory> {
    for r in response.answers() {
        if let Some(c) = shield.check_name(r.name()) {
            return Some(c);
        }
        let target = match r.data() {
            RData::CNAME(c) => Some(&c.0),
            RData::ANAME(a) => Some(&a.0),
            _ => None,
        };
        if let Some(t) = target {
            if let Some(c) = shield.check_name(t) {
                return Some(c);
            }
        }
    }
    None
}

/// Synthesize the answer for a blocked query, preserving id and question.
///
/// * `ZeroIp`: `A 0.0.0.0` / `AAAA ::` (NOERROR, empty answer for other types)
/// * `Nxdomain`: RCODE 3
pub fn synthesize_block(query: &Message, mode: BlockMode) -> Message {
    match mode {
        BlockMode::Nxdomain => response_for(query, ResponseCode::NXDomain),
        BlockMode::ZeroIp => {
            let mut r = response_for(query, ResponseCode::NoError);
            if let Some(q) = query.queries().first() {
                let rdata = match q.query_type() {
                    RecordType::A => Some(RData::A(A::new(0, 0, 0, 0))),
                    RecordType::AAAA => Some(RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 0))),
                    _ => None,
                };
                if let Some(rd) = rdata {
                    let mut rec = Record::from_rdata(q.name().clone(), BLOCK_TTL, rd);
                    rec.set_dns_class(q.query_class());
                    r.add_answer(rec);
                }
            }
            r
        }
    }
}

/// If any name in `response`'s chain is blocked, return the category and the
/// synthesized replacement response for `query`.
pub fn uncloak(
    shield: &Shield,
    query: &Message,
    response: &Message,
    mode: BlockMode,
) -> Option<(ShieldCategory, Message)> {
    let cat = find_cloaked(shield, response)?;
    Some((cat, synthesize_block(query, mode)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::testutil::query;
    use hickory_proto::rr::rdata::CNAME;
    use hickory_proto::rr::Name;
    use vw_core::config::ShieldSettings;

    fn cloaked_response(q: &Message) -> Message {
        let mut r = response_for(q, ResponseCode::NoError);
        let n = |s: &str| Name::from_ascii(s).unwrap();
        r.add_answer(Record::from_rdata(
            n("metrics.shop.example."),
            300,
            RData::CNAME(CNAME(n("edge.cdn.example."))),
        ));
        r.add_answer(Record::from_rdata(
            n("edge.cdn.example."),
            300,
            RData::CNAME(CNAME(n("shop.eulerian.net.example-tracker.com."))),
        ));
        r.add_answer(Record::from_rdata(
            n("shop.eulerian.net.example-tracker.com."),
            300,
            RData::A(A::new(192, 0, 2, 7)),
        ));
        r
    }

    #[test]
    fn detects_tracker_deep_in_chain() {
        let st = ShieldSettings {
            custom_block: vec!["example-tracker.com".into()],
            ..Default::default()
        };
        let shield = Shield::new(&st);
        let q =
            Message::from_vec(&query("metrics.shop.example.", RecordType::A, 4242, true)).unwrap();
        let r = cloaked_response(&q);
        let (cat, blocked) = uncloak(&shield, &q, &r, BlockMode::ZeroIp).unwrap();
        assert_eq!(cat, ShieldCategory::Custom);
        assert_eq!(blocked.id(), 4242);
        assert_eq!(blocked.queries(), q.queries());
        match blocked.answers()[0].data() {
            RData::A(a) => assert_eq!(a.0, std::net::Ipv4Addr::UNSPECIFIED),
            other => panic!("unexpected {other:?}"),
        }
        assert!(blocked.answers()[0].ttl() <= BLOCK_TTL);

        let (_, nx) = uncloak(&shield, &q, &r, BlockMode::Nxdomain).unwrap();
        assert_eq!(nx.response_code(), ResponseCode::NXDomain);
        assert!(nx.answers().is_empty());
        assert_eq!(nx.id(), 4242);
    }

    #[test]
    fn clean_chain_passes() {
        let shield = Shield::new(&ShieldSettings::default());
        let q =
            Message::from_vec(&query("metrics.shop.example.", RecordType::A, 1, false)).unwrap();
        assert!(uncloak(&shield, &q, &cloaked_response(&q), BlockMode::ZeroIp).is_none());
    }

    #[test]
    fn aaaa_zero() {
        let q = Message::from_vec(&query("x.example.", RecordType::AAAA, 9, false)).unwrap();
        let r = synthesize_block(&q, BlockMode::ZeroIp);
        match r.answers()[0].data() {
            RData::AAAA(a) => assert_eq!(a.0, std::net::Ipv6Addr::UNSPECIFIED),
            other => panic!("unexpected {other:?}"),
        }
        let q = Message::from_vec(&query("x.example.", RecordType::TXT, 9, false)).unwrap();
        let r = synthesize_block(&q, BlockMode::ZeroIp);
        assert!(r.answers().is_empty());
        assert_eq!(r.response_code(), ResponseCode::NoError);
    }
}
