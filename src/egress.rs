//! Where this proxy is willing to *connect*, as opposed to what it is willing to
//! inject.
//!
//! The allowlist answers "may this secret reach that host". It is a check on
//! **names**, and names are not destinations. `evil.test` can have an `A` record
//! pointing at `169.254.169.254`, and a rule permitting `evil.test` would happily
//! let an agent read the cloud instance-metadata service — including, on a lot of
//! infrastructure, the role credentials that make the whole zero-knowledge story
//! moot. That is SSRF, and a proxy whose destination is chosen by an untrusted
//! agent is the textbook place for it.
//!
//! So every outbound connection also has to survive a check on the **address**:
//! private, loopback, link-local, and the other non-routable ranges are refused
//! unless the operator said otherwise.
//!
//! Four decisions shape this module.
//!
//! **1. Resolve once, connect to what we resolved.** The classic bypass is DNS
//! rebinding: the name resolves to a public address for the check and a private
//! one for the connection, because the checker and the connector each looked it
//! up. [`EgressResolver`] is installed as the HTTP client's own resolver, so the
//! addresses it returns are the addresses reqwest dials. There is no second
//! lookup to poison.
//!
//! **2. Literal addresses are checked separately.** A URL like
//! `http://169.254.169.254/latest/meta-data/` never consults a resolver at all,
//! so the data planes call [`Egress::check_literal`] before dispatch. Missing
//! this is how an IP-level control ends up protecting only the cases that were
//! already hard.
//!
//! **3. IPv4-mapped IPv6 is unwrapped before classification.** `::ffff:169.254.169.254`
//! is the metadata service wearing a hat, and a classifier that only knows about
//! `fc00::/7` waves it through. Same for NAT64's `64:ff9b::/96`.
//!
//! **4. A configured `[[route]] upstream` is exempt.** SSRF means *the attacker
//! chooses the destination*. A reverse-proxy route's upstream is written in this
//! deployment's own config by the person running it — it is not agent-chosen, and
//! refusing it would break every local and internal deployment to prevent an
//! attack that cannot happen there. Agent-chosen destinations (the whole forward
//! plane) get no such exemption; an operator who needs an internal one there says
//! so with `allow_cidr`, which is one explicit line in the place where it matters.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// The validated `[egress]` block.
#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Refuse connections to non-routable addresses. On by default.
    pub block_private: bool,
    /// Ranges the operator has declared reachable anyway.
    pub allow: Vec<Cidr>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            block_private: true,
            allow: Vec::new(),
        }
    }
}

/// Why a destination was refused. Carries the address so the log says which one —
/// an address is a destination, not a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// Every address the name resolved to was refused.
    Blocked {
        host: String,
        addr: IpAddr,
        kind: &'static str,
    },
    /// The name did not resolve at all.
    Unresolved { host: String, message: String },
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressError::Blocked { host, addr, kind } => write!(
                f,
                "{host} resolves to {addr}, which is {kind} — refusing to connect. \
                 If this destination is intended, add its range to [egress] allow_cidr"
            ),
            EgressError::Unresolved { host, message } => {
                write!(f, "could not resolve {host}: {message}")
            }
        }
    }
}

impl std::error::Error for EgressError {}

/// The egress gate: a policy plus the hosts this deployment's own config named.
#[derive(Debug)]
pub struct Egress {
    config: EgressConfig,
    /// Hosts written into this deployment's config as a reverse-proxy upstream.
    /// Exempt because the operator chose them; see the module comment.
    exempt: BTreeSet<String>,
}

impl Egress {
    pub fn new(config: EgressConfig, exempt: impl IntoIterator<Item = String>) -> Egress {
        Egress {
            config,
            exempt: exempt.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        }
    }

    /// A gate that permits everything — for tests and for `block_private = false`.
    pub fn permissive() -> Egress {
        Egress::new(
            EgressConfig {
                block_private: false,
                allow: Vec::new(),
            },
            [],
        )
    }

    pub fn is_enforcing(&self) -> bool {
        self.config.block_private
    }

    /// Is this host exempt from the address check?
    pub fn is_exempt(&self, host: &str) -> bool {
        self.exempt.contains(&host.to_ascii_lowercase())
    }

    /// May this address be connected to?
    pub fn permits_addr(&self, addr: IpAddr) -> Result<(), &'static str> {
        if !self.config.block_private {
            return Ok(());
        }
        // An explicit allow beats the classifier: the operator is describing
        // their own network, which we cannot infer.
        if self.config.allow.iter().any(|c| c.contains(addr)) {
            return Ok(());
        }
        match classify(addr) {
            Some(kind) => Err(kind),
            None => Ok(()),
        }
    }

    /// Check a destination whose host is (or may be) a literal address.
    ///
    /// Returns `Ok(())` for a hostname — that case is handled by
    /// [`EgressResolver`] at connect time, which is the only place that can both
    /// classify and pin the result.
    pub fn check_literal(&self, host: &str) -> Result<(), EgressError> {
        if self.is_exempt(host) {
            return Ok(());
        }
        let Some(addr) = parse_host_ip(host) else {
            return Ok(());
        };
        self.permits_addr(addr)
            .map_err(|kind| EgressError::Blocked {
                host: host.to_string(),
                addr,
                kind,
            })
    }

    /// Resolve `host:port` and keep only the addresses this gate permits.
    ///
    /// The returned addresses are the ones to connect to — resolving again would
    /// reopen the rebinding window this exists to close.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressError> {
        let exempt = self.is_exempt(host);

        let addrs: Vec<SocketAddr> = match parse_host_ip(host) {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| EgressError::Unresolved {
                    host: host.to_string(),
                    message: e.to_string(),
                })?
                .collect(),
        };

        if exempt || !self.config.block_private {
            return Ok(addrs);
        }

        // Remember the first refusal so the error can name a concrete address
        // rather than saying "nothing was allowed".
        let mut refused: Option<(IpAddr, &'static str)> = None;
        let permitted: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| match self.permits_addr(a.ip()) {
                Ok(()) => true,
                Err(kind) => {
                    refused.get_or_insert((a.ip(), kind));
                    false
                }
            })
            .collect();

        match (permitted.is_empty(), refused) {
            (true, Some((addr, kind))) => Err(EgressError::Blocked {
                host: host.to_string(),
                addr,
                kind,
            }),
            (true, None) => Err(EgressError::Unresolved {
                host: host.to_string(),
                message: "no addresses".into(),
            }),
            _ => Ok(permitted),
        }
    }
}

impl Egress {
    /// Build the gate this config describes.
    ///
    /// The exempt set is every `[[route]] upstream` host. Those are destinations
    /// the operator wrote down, not ones an agent picked, so the SSRF the rest of
    /// this module prevents cannot happen through them — and exempting them is
    /// what lets the check default to on without breaking every deployment whose
    /// upstream is a sidecar or an internal service.
    ///
    /// `[forward.host]` rules are deliberately *not* exempt. A host rule says an
    /// agent may reach that name; the name is still resolved at the agent's
    /// request, and an operator who needs an internal destination there names its
    /// range in `allow_cidr`.
    pub fn from_config(config: &crate::config::Config) -> Egress {
        Egress::new(
            config.egress.clone(),
            config.routes.iter().map(|r| r.host.clone()),
        )
    }
}

/// The HTTP client's resolver, so reqwest connects to exactly the addresses this
/// gate approved.
///
/// This is the anti-rebinding half of the design: a check that resolves the name
/// itself and then hands the *name* to the connector has checked one lookup and
/// connected on another.
pub struct EgressResolver {
    egress: Arc<Egress>,
}

impl EgressResolver {
    pub fn new(egress: Arc<Egress>) -> EgressResolver {
        EgressResolver { egress }
    }
}

impl reqwest::dns::Resolve for EgressResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let egress = self.egress.clone();
        Box::pin(async move {
            // Port 0: reqwest overwrites it with the request's own port. Only the
            // addresses matter here.
            let host = name.as_str().to_string();
            match egress.resolve(&host, 0).await {
                Ok(addrs) => {
                    let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
                    Ok(iter)
                }
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

/// A host string that is already an address, if it is one.
///
/// Accepts the bracketed form (`[::1]`) because that is how an IPv6 literal
/// appears in a URL authority.
pub fn parse_host_ip(host: &str) -> Option<IpAddr> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse().ok()
}

/// Why an address is not publicly routable, or `None` if it is.
///
/// Named rather than boolean so a refusal can say *which* rule caught it —
/// "link-local (cloud instance metadata)" sends someone to a very different place
/// than "loopback".
pub fn classify(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4 address wearing an IPv6 hat is still that IPv4 address.
            // `::ffff:169.254.169.254` reaches the metadata service exactly like
            // the bare form, and a v6-only classifier waves it through.
            if let Some(v4) = v6_as_v4(v6) {
                return classify_v4(v4);
            }
            classify_v6(v6)
        }
    }
}

fn classify_v4(a: Ipv4Addr) -> Option<&'static str> {
    let o = a.octets();
    if a.is_unspecified() || o[0] == 0 {
        return Some("the unspecified/this-network range");
    }
    if a.is_loopback() {
        return Some("loopback");
    }
    if a.is_link_local() {
        // The reason this module exists on most infrastructure.
        return Some("link-local (cloud instance metadata)");
    }
    if a.is_private() {
        return Some("a private network (RFC 1918)");
    }
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return Some("carrier-grade NAT space");
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some("IETF protocol assignment space");
    }
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return Some("documentation space");
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return Some("benchmarking space");
    }
    if a.is_multicast() {
        return Some("multicast");
    }
    if o[0] >= 240 {
        return Some("reserved space");
    }
    None
}

fn classify_v6(a: Ipv6Addr) -> Option<&'static str> {
    let s = a.segments();
    if a.is_unspecified() {
        return Some("the unspecified address");
    }
    if a.is_loopback() {
        return Some("loopback");
    }
    if s[0] & 0xfe00 == 0xfc00 {
        return Some("a unique-local network (fc00::/7)");
    }
    if s[0] & 0xffc0 == 0xfe80 {
        return Some("link-local");
    }
    if a.is_multicast() {
        return Some("multicast");
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Some("documentation space");
    }
    None
}

/// The IPv4 address inside an IPv4-mapped or NAT64-translated IPv6 address.
fn v6_as_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = a.segments();
    // ::ffff:a.b.c.d — IPv4-mapped.
    if s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return Some(Ipv4Addr::from(
            <[u8; 4]>::try_from(&a.octets()[12..16]).ok()?,
        ));
    }
    // ::a.b.c.d — deprecated IPv4-compatible, still routed by some stacks.
    if s[0..6] == [0, 0, 0, 0, 0, 0] && !a.is_unspecified() && !a.is_loopback() {
        return Some(Ipv4Addr::from(
            <[u8; 4]>::try_from(&a.octets()[12..16]).ok()?,
        ));
    }
    // 64:ff9b::/96 — the well-known NAT64 prefix.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::from(
            <[u8; 4]>::try_from(&a.octets()[12..16]).ok()?,
        ));
    }
    None
}

/// One `address/prefix` range from `[egress] allow_cidr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `10.0.0.0/8`, `192.168.1.5/32`, `fd00::/8`, or a bare address
    /// (treated as a single host).
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p
                    .parse()
                    .map_err(|_| format!("{text:?}: prefix length is not a number"))?;
                (a, Some(prefix))
            }
            None => (text, None),
        };
        let base: IpAddr = addr
            .parse()
            .map_err(|_| format!("{text:?}: {addr:?} is not an IP address"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(format!(
                "{text:?}: /{prefix} is longer than the {max} bits of an {} address",
                if base.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }
        Ok(Cidr { base, prefix })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(base), IpAddr::V4(a)) => {
                masked_eq(&base.octets(), &a.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(a)) => {
                masked_eq(&base.octets(), &a.octets(), self.prefix)
            }
            // An IPv4 range should still cover the mapped form of its addresses,
            // or `allow_cidr` would depend on which family the resolver happened
            // to return.
            (IpAddr::V4(_), IpAddr::V6(a)) => match v6_as_v4(a) {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// Do two addresses agree on their first `prefix` bits?
fn masked_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let bits = prefix % 8;
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    a[whole] & mask == b[whole] & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_metadata_endpoint_is_refused() {
        // The single address this module is most for.
        assert_eq!(
            classify(ip("169.254.169.254")),
            Some("link-local (cloud instance metadata)")
        );
    }

    #[test]
    fn private_and_loopback_ranges_are_refused() {
        for a in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(classify(ip(a)).is_some(), "{a} should be refused");
        }
    }

    #[test]
    fn public_addresses_are_permitted() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "104.18.0.1",
            "172.32.0.1",
            "2606:4700::1111",
        ] {
            assert_eq!(classify(ip(a)), None, "{a} should be allowed");
        }
    }

    #[test]
    fn ipv6_non_routable_ranges_are_refused() {
        for a in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"] {
            assert!(classify(ip(a)).is_some(), "{a} should be refused");
        }
    }

    #[test]
    fn an_ipv4_mapped_address_is_classified_as_its_ipv4() {
        // The bypass: `::ffff:169.254.169.254` is the metadata service, and a
        // classifier that only knows `fc00::/7` would forward to it.
        assert_eq!(
            classify(ip("::ffff:169.254.169.254")),
            Some("link-local (cloud instance metadata)")
        );
        assert_eq!(
            classify(ip("::ffff:10.0.0.1")),
            Some("a private network (RFC 1918)")
        );
        assert_eq!(classify(ip("::ffff:1.1.1.1")), None);
    }

    #[test]
    fn a_nat64_address_is_classified_as_its_ipv4() {
        assert_eq!(
            classify(ip("64:ff9b::169.254.169.254")),
            Some("link-local (cloud instance metadata)")
        );
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("11.0.0.1")));

        let host = Cidr::parse("192.168.1.5/32").unwrap();
        assert!(host.contains(ip("192.168.1.5")));
        assert!(!host.contains(ip("192.168.1.6")));

        // A bare address is a single host.
        let bare = Cidr::parse("172.17.0.1").unwrap();
        assert!(bare.contains(ip("172.17.0.1")));
        assert!(!bare.contains(ip("172.17.0.2")));

        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
    }

    #[test]
    fn an_ipv4_allow_range_covers_the_mapped_form() {
        // Otherwise `allow_cidr` would work or not depending on which family the
        // resolver happened to hand back.
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn a_prefix_that_cannot_exist_is_refused() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("fd00::/129").is_err());
        assert!(Cidr::parse("not-an-ip/8").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
    }

    #[test]
    fn an_allowed_range_beats_the_classifier() {
        let egress = Egress::new(
            EgressConfig {
                block_private: true,
                allow: vec![Cidr::parse("10.0.0.0/8").unwrap()],
            },
            [],
        );
        assert!(egress.permits_addr(ip("10.1.2.3")).is_ok());
        // Still refused: the operator named one range, not "private" in general.
        assert!(egress.permits_addr(ip("192.168.1.1")).is_err());
        assert!(egress.permits_addr(ip("169.254.169.254")).is_err());
    }

    #[test]
    fn a_configured_upstream_is_exempt() {
        // The reverse plane's destination is written by the operator, not chosen
        // by an agent — refusing it would break local and internal deployments to
        // prevent an attack that cannot happen there.
        let egress = Egress::new(EgressConfig::default(), ["127.0.0.1".to_string()]);
        assert!(egress.check_literal("127.0.0.1").is_ok());
        assert!(egress.check_literal("10.0.0.1").is_err());
    }

    #[test]
    fn exemption_is_case_insensitive() {
        let egress = Egress::new(EgressConfig::default(), ["Internal.Corp".to_string()]);
        assert!(egress.is_exempt("internal.corp"));
    }

    #[test]
    fn a_literal_destination_is_caught_without_any_dns() {
        // `http://169.254.169.254/latest/meta-data/` consults no resolver, so the
        // resolver-based half of this module would never see it.
        let egress = Egress::new(EgressConfig::default(), []);
        let err = egress.check_literal("169.254.169.254").unwrap_err();
        assert!(err.to_string().contains("instance metadata"), "{err}");
        assert!(err.to_string().contains("allow_cidr"), "{err}");
    }

    #[test]
    fn a_bracketed_ipv6_literal_is_parsed() {
        // How an IPv6 literal appears in a URL authority.
        let egress = Egress::new(EgressConfig::default(), []);
        assert!(egress.check_literal("[::1]").is_err());
        assert_eq!(parse_host_ip("[::1]"), Some(ip("::1")));
    }

    #[test]
    fn a_hostname_passes_the_literal_check_and_is_left_to_the_resolver() {
        let egress = Egress::new(EgressConfig::default(), []);
        assert!(egress.check_literal("api.example.com").is_ok());
    }

    #[test]
    fn disabling_the_gate_permits_everything() {
        let egress = Egress::permissive();
        assert!(egress.permits_addr(ip("169.254.169.254")).is_ok());
        assert!(egress.check_literal("127.0.0.1").is_ok());
        assert!(!egress.is_enforcing());
    }

    #[tokio::test]
    async fn resolving_a_literal_returns_it_when_permitted() {
        let egress = Egress::new(EgressConfig::default(), []);
        let addrs = egress.resolve("1.1.1.1", 443).await.unwrap();
        assert_eq!(addrs, vec![SocketAddr::new(ip("1.1.1.1"), 443)]);
    }

    #[tokio::test]
    async fn resolving_a_blocked_literal_names_the_address_and_the_reason() {
        let egress = Egress::new(EgressConfig::default(), []);
        let err = egress.resolve("169.254.169.254", 80).await.unwrap_err();
        assert_eq!(
            err,
            EgressError::Blocked {
                host: "169.254.169.254".into(),
                addr: ip("169.254.169.254"),
                kind: "link-local (cloud instance metadata)",
            }
        );
    }

    #[tokio::test]
    async fn localhost_resolves_but_is_refused_unless_exempt() {
        let egress = Egress::new(EgressConfig::default(), []);
        assert!(egress.resolve("localhost", 80).await.is_err());

        let exempt = Egress::new(EgressConfig::default(), ["localhost".to_string()]);
        assert!(exempt.resolve("localhost", 80).await.is_ok());
    }
}
