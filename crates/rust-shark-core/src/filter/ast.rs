use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    ProtocolPresent(ProtocolAtom),
    Comparison {
        field: FieldPath,
        op: CompareOp,
        value: FilterValue,
    },
    Contains {
        field: FieldPath,
        pattern: String,
    },
    /// Free-text substring match across a packet's summary fields. This is the
    /// fallback when the input is not a structured expression: typing any plain
    /// text keeps only packets whose summary contains it (case-insensitive).
    FreeText(String),
    /// Matches packets flagged by the live threat detector (any kind).
    Threat,
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAtom {
    Ethernet,
    Arp,
    Ip,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Dns,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath {
    pub path: String,
}

impl FieldPath {
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Integer(i64),
    IpAddr(IpAddr),
    Str(String),
}
