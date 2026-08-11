/* mymx — the words that are this service's own.
 *
 * The shared vocabulary (buttons, errors, severities, the names of the sibling
 * tools) lives in the service kit and is translated into all twelve languages
 * there. What follows is only what mymx needs on top of that.
 *
 * A language block that is absent falls back to English; `npm run check:i18n`
 * reports which languages are in that state and fails on one that is
 * half-finished. To add a language, copy OWN.en, translate the values, and
 * leave the keys alone. mydns/public/i18n.js has a completed Russian block to
 * work from. */
'use strict';

var OWN = {};

OWN.en = {
  title: 'Mail Check — SPF, DKIM, DMARC, MTA-STS and DANE for any domain',
  title_short: 'Mail Check',
  h1: 'Mail Check',
  subtitle: 'SPF expanded through every include and counted against the limit of ten, DMARC alignment and reporting, transport security checked on the wire',
  ph_host: 'example.com',
  hero_label: 'Domain being checked',
  empty_hint: 'Enter a domain name. The check expands the SPF record through every include, tries the DKIM selectors the large platforms use, reads the DMARC policy, fetches the MTA-STS policy over HTTPS, and opens read-only SMTP sessions to the mail servers. No message is ever sent.',

  /* ---- stages ---- */
  stage_resolve: 'looking up the mail servers',
  stage_mx: 'checking the MX set',
  stage_spf: 'expanding SPF',
  stage_dkim: 'looking for DKIM keys',
  stage_dmarc: 'reading the DMARC policy',
  stage_mtasts: 'fetching the MTA-STS policy',
  stage_dane: 'checking DANE',
  stage_starttls: 'talking to the mail servers',
  stage_grade: 'grading',

  /* ---- cards ---- */
  card_grade: 'Grade breakdown',
  card_mx: 'Mail servers',
  card_spf: 'SPF',
  card_spf_tree: 'SPF expansion',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Transport security',
  card_sessions: 'SMTP sessions',
  card_rdns: 'Reverse DNS',

  /* ---- grade components ---- */
  comp_authentication: 'Authentication',
  comp_transport: 'Transport',
  comp_hygiene: 'Hygiene',

  /* ---- row labels ---- */
  k_mx_count: 'MX records',
  k_null_mx: 'Null MX',
  k_ipv6_mx: 'Reachable over IPv6',
  k_spf_record: 'Record',
  k_spf_lookups: 'DNS lookups used',
  k_spf_voids: 'Void lookups',
  k_spf_policy: 'Default for everyone else',
  k_dkim_keys: 'Keys found',
  k_dkim_tried: 'Selectors tried',
  k_dkim_strongest: 'Strongest key',
  k_dmarc_policy: 'Policy',
  k_dmarc_subdomain: 'Subdomain policy',
  k_dmarc_percent: 'Applied to',
  k_dmarc_alignment: 'Alignment (DKIM / SPF)',
  k_dmarc_rua: 'Aggregate reports to',
  k_dmarc_ruf: 'Forensic reports to',
  k_dmarc_external: 'External reporting authorised',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Mode',
  k_mtasts_id: 'Policy id',
  k_mtasts_maxage: 'Cached for',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Servers covered',
  k_starttls: 'STARTTLS',
  k_port25: 'Outbound port 25',
  k_open_relay: 'Open relay',
  k_rdns_confirmed: 'Forward-confirmed',
  k_queries: 'Queries made',

  /* ---- table headings ---- */
  th_priority: 'Priority',
  th_host: 'Host',
  th_addresses: 'Addresses',
  th_port: 'Port',
  th_tls: 'TLS',
  th_banner: 'Banner',
  th_extensions: 'Announced',
  th_selector: 'Selector',
  th_key_type: 'Key',
  th_bits: 'Bits',
  th_state: 'State',
  th_address: 'Address',
  th_ptr: 'PTR',
  th_confirmed: 'Confirmed',
  th_term: 'Term',
  th_lookup: 'Lookup',

  /* ---- values ---- */
  pol_none: 'none — monitoring only',
  pol_quarantine: 'quarantine',
  pol_reject: 'reject',
  spfp_pass: 'pass (+all)',
  spfp_fail: 'reject (-all)',
  spfp_softfail: 'soft fail (~all)',
  spfp_neutral: 'neutral (?all)',
  spfp_redirect: 'delegated by redirect',
  spfterm_no_target: 'no target',
  spfterm_loop: 'loop — already visited',
  spfterm_lookup_failed: 'lookup failed',
  spfterm_no_spf_record: 'no SPF record there',

  stsmode_enforce: 'enforce',
  stsmode_testing: 'testing',
  stsmode_none: 'none',
  rdns_confirmed: 'confirmed',
  rdns_unconfirmed: 'does not resolve back',
  rdns_missing: 'no PTR',
  rdns_unknown: 'not checked',
  v_of_limit: '{used} of {limit}',
  v_percent: '{n}%',
  v_days_short: '{n}d',
  v_blocked_here: 'blocked from our network',
  v_no_selector_found: 'none of the {n} known selectors',

  /* ---- notes ---- */
  note_spf: 'RFC 7208 allows ten DNS-querying terms across the whole evaluation, following every include into every include. Past ten a receiver must return permerror — and a permerror means SPF does not apply at all, exactly as if there were no record.',
  note_dmarc: 'With p=none nothing is enforced: a message that fails both SPF and DKIM alignment is delivered as before. It is the right place to start and the wrong place to stay.',
  note_transport: 'STARTTLS is opportunistic, so a sender that is stripped of the offer simply continues in the clear. MTA-STS and DANE are what turn that into a guarantee.',
  note_sessions: 'Every session is read-only. The relay probe stops at RCPT TO and sends RSET; no DATA command is ever issued, so no message can be sent.',
  note_rdns: 'A PTR record proves nothing on its own — the owner of an address block can put any name there. What receivers check is whether that name resolves back to the same address.',

  /* ---- errors specific to this service ---- */
  err_smtp_timeout: 'The mail server did not answer in time.',
  err_smtp_network: 'The mail server could not be reached.',
  err_smtp_refused: 'The mail server refused the connection.',
  err_tls_failed: 'The TLS handshake with the mail server failed.',

  /* ---- what was not established ---- */
  inc_mx_lookup_failed: 'the MX records could not be read',
  inc_spf_lookup_failed: 'the SPF record could not be read',
  inc_dmarc_lookup_failed: 'the DMARC record could not be read',
  inc_port_25_unreachable_from_this_network: 'outbound port 25 is blocked where this service runs, so STARTTLS, DANE verification and the relay check could not be made',
  inc_not_every_mx_was_probed: 'only the highest-priority mail servers were connected to',

  /* ---- grade caps ---- */
  cap_open_relay: 'the server relays mail for strangers',
  cap_spf_authorises_everyone: 'SPF authorises the entire internet',
  cap_no_mail_servers: 'no mail servers',
  cap_mail_servers_unreachable: 'no mail server answered on port 25',
  cap_dane_mismatch: 'DANE does not match the certificate presented',
  cap_mtasts_policy_contradicts_dns: 'the MTA-STS policy omits a real mail server',
  cap_spf_over_the_lookup_limit: 'SPF is over the lookup limit',
  cap_spf_permerror: 'SPF is a permanent error',
  cap_dmarc_permerror: 'DMARC is a permanent error',
  cap_mail_in_the_clear: 'mail is accepted without encryption',
  cap_no_spf: 'no SPF record',
  cap_no_dmarc: 'no DMARC record',
  cap_starttls_broken: 'STARTTLS is offered and does not work',
  cap_dmarc_not_enforcing: 'DMARC enforces nothing',
  cap_no_reverse_dns: 'no confirmed reverse DNS',
  cap_spf_without_a_default: 'SPF has no default',
  cap_weak_dkim_key: 'a DKIM key that is too short',
  cap_dmarc_reports_go_nowhere: 'DMARC reports are not authorised',
  cap_mail_server_does_not_resolve: 'a mail server does not resolve',
  cap_scan_incomplete: 'the check was incomplete, so no grade was given',

  /* ---- findings: MX ---- */
  flag_null_mx: 'The domain declares that it handles no mail',
  fd_null_mx: 'A single MX at priority 0 pointing at the root is RFC 7505 for "this domain neither sends nor receives mail". Deliberate, and much better than having no MX at all — which makes senders fall back to the A record.',

  flag_no_mx: 'No MX records',
  fd_no_mx: 'Nothing says where mail for this domain should go, and there is no address to fall back to either, so mail simply cannot be delivered.',

  flag_no_mx_falls_back_to_a: 'No MX records, so senders fall back to the A record',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 tells a sender with no MX to try the address record. Mail for this domain will be delivered to whatever is listening on port 25 at the web server — which is rarely what anyone intended.',

  flag_duplicate_mx_host: 'The same host is listed twice',
  fd_duplicate_mx_host: 'One host appears at more than one priority. That is not redundancy; it is the same machine being tried twice.',

  flag_mx_does_not_resolve: 'A mail server name does not resolve',
  fd_mx_does_not_resolve: 'The MX names a host with no address records. Every sender that reaches this priority waits for the lookup, gets nothing, and moves on — delaying mail that should have arrived at once.',

  flag_mx_points_at_cname: 'An MX record points at an alias',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 requires an MX to name a host with address records, not a CNAME. Some senders cope, some refuse, and which ones do what changes over time.',

  flag_single_mx: 'Only one mail server',
  fd_single_mx: 'With one MX, any outage means senders queue and retry — for hours or days, depending on their own policy — and some of that mail will bounce.',

  flag_no_ipv6_mx: 'No mail server is reachable over IPv6',
  fd_no_ipv6_mx: 'Senders on IPv6-only networks reach this domain through a translator, if at all.',

  /* ---- findings: SPF ---- */
  flag_spf_missing: 'No SPF record',
  fd_spf_missing: 'Nothing says which servers may send mail as this domain, so nothing can be checked against. SPF is one TXT record and the single cheapest thing on this page.',

  flag_spf_multiple_records: 'More than one SPF record',
  fd_spf_multiple_records: 'RFC 7208 §4.5 makes two records a permanent error, and a permerror means no SPF result at all — the opposite of what adding the second record was meant to achieve. Merge them into one.',

  flag_spf_too_many_lookups: 'SPF needs more than ten DNS lookups',
  fd_spf_too_many_lookups: 'The limit in RFC 7208 §4.6.4 is ten querying terms across the whole evaluation, following every include into every include. Past it a receiver must return permerror, and SPF then does not apply — the record might as well not exist. This is easy to exceed by adding one more provider, and completely invisible from the record itself.',

  flag_spf_lookups_near_limit: 'SPF is close to the ten-lookup limit',
  fd_spf_lookups_near_limit: 'There is little headroom left. The next service added — or a change inside somebody else\'s include, which you do not control — will push it over.',

  flag_spf_too_many_void_lookups: 'Too many SPF lookups return nothing',
  fd_spf_too_many_void_lookups: 'RFC 7208 allows two lookups that resolve to nothing; beyond that it is a permanent error. Usually a leftover include for a service that is no longer used.',

  flag_spf_no_all: 'SPF has no default',
  fd_spf_no_all: 'Without an "all" mechanism or a redirect, a sender that matches nothing gets a neutral result — which is the same as having no opinion at all.',

  flag_spf_plus_all: 'SPF authorises the entire internet',
  fd_spf_plus_all: '"+all" says that any host anywhere may send as this domain. It is almost always a misunderstanding of the qualifier, and it is worse than having no SPF record, because it explicitly vouches for the forger.',

  flag_spf_neutral_all: 'SPF ends in ?all',
  fd_spf_neutral_all: '"?all" explicitly declines to say anything about senders that match nothing. Receivers treat it as no result.',

  flag_spf_softfail_all: 'SPF ends in ~all rather than -all',
  fd_spf_softfail_all: 'Soft fail asks receivers to accept but mark. It is the right setting while you are still finding out who sends on your behalf, and the thing to tighten once you know.',

  flag_spf_uses_ptr: 'SPF uses the ptr mechanism',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 deprecates ptr outright: it is slow, unreliable, and pushes work onto whoever runs the reverse zone. Some receivers ignore it entirely.',

  flag_spf_unknown_mechanism: 'SPF contains a term nothing understands',
  fd_spf_unknown_mechanism: 'An unrecognised mechanism is a permanent error under RFC 7208 §4.6.1, which discards the whole record. Usually a typo.',

  flag_spf_duplicate_redirect: 'More than one redirect modifier',
  fd_spf_duplicate_redirect: 'A second redirect makes the record a permanent error.',

  flag_spf_redirect_after_all: 'A redirect that can never be reached',
  fd_spf_redirect_after_all: 'The record has both an "all" mechanism and a redirect. "all" always matches, so evaluation stops there and the redirect is dead text.',

  flag_spf_record_long: 'The SPF record is long',
  fd_spf_record_long: 'Long records are split into several strings on the wire. That is fine in itself — receivers join them with nothing between — but it is where parsers that join them with a space start corrupting the record.',

  flag_spf_include_loop: 'An include points back at something already visited',
  fd_spf_include_loop: 'The expansion loops. A receiver stops at the lookup limit and returns a permanent error.',

  flag_spf_include_without_record: 'An include points at a domain with no SPF record',
  fd_spf_include_without_record: 'RFC 7208 §5.2 makes this a permanent error, not merely a wasted lookup. Usually a service that was removed at one end and not the other.',

  /* ---- findings: DKIM ---- */
  flag_dkim_no_known_selector: 'No DKIM key found at any selector we know',
  fd_dkim_no_known_selector: 'Selectors are chosen by whoever signs and are only visible in the header of a signed message, so they cannot be enumerated from outside. This is not proof that DKIM is missing — if you know your selector, pass it with ?selector= and the check becomes conclusive.',

  flag_dkim_key_revoked: 'A DKIM key has been revoked',
  fd_dkim_key_revoked: 'The record is published with an empty p=, which revokes the key. That is the correct way to retire one — and a record left in that state for months is usually a rollover nobody finished.',

  flag_dkim_key_malformed: 'A DKIM key cannot be parsed',
  fd_dkim_key_malformed: 'The p= value is not valid key material. Every signature made with it will fail verification.',

  flag_dkim_in_test_mode: 'A DKIM record is in test mode',
  fd_dkim_in_test_mode: 't=y tells receivers to treat a failed signature as though DKIM were not in use. It belongs in a rollout and nowhere else.',

  flag_dkim_key_too_short: 'A DKIM key is shorter than 1024 bits',
  fd_dkim_key_too_short: 'Below 1024 bits the signature is not meaningfully hard to forge, and many receivers ignore such keys outright.',

  flag_dkim_key_1024_bit: 'A DKIM key is 1024 bits',
  fd_dkim_key_1024_bit: 'Still accepted everywhere, and below current recommendations. 2048 is the normal size; the rollover is a new selector and a DNS record.',

  /* ---- findings: DMARC ---- */
  flag_dmarc_missing: 'No DMARC record',
  fd_dmarc_missing: 'Without DMARC, SPF and DKIM results are advisory: nothing ties them to the address a reader actually sees, and nothing tells receivers what to do when they fail.',

  flag_dmarc_inherited: 'DMARC is inherited from the parent domain',
  fd_dmarc_inherited: 'This name has no record of its own, so the organisational domain\'s policy applies — its sp= value if it has one, otherwise its p=.',

  flag_dmarc_multiple_records: 'More than one DMARC record',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: with more than one record the policy is discarded entirely, as if none had been published.',

  flag_dmarc_no_policy: 'The DMARC record has no p= tag',
  fd_dmarc_no_policy: 'p= is required. Without it the record is ignored.',

  flag_dmarc_invalid_policy: 'The DMARC policy is not a recognised value',
  fd_dmarc_invalid_policy: 'p= must be none, quarantine or reject. Anything else and receivers discard the record.',

  flag_dmarc_policy_none: 'DMARC enforces nothing',
  fd_dmarc_policy_none: 'p=none asks receivers to report and change nothing. A message that fails both SPF and DKIM alignment is delivered exactly as it would be without DMARC. It is the right way to start — and a great many domains have been sitting here for years believing they are protected.',

  flag_dmarc_policy_quarantine: 'DMARC quarantines rather than rejects',
  fd_dmarc_policy_quarantine: 'Failing mail goes to the junk folder rather than being refused. A reasonable step on the way to reject, and a place where forged mail is still reaching people.',

  flag_dmarc_subdomain_policy_none: 'Subdomains are exempt from the policy',
  fd_dmarc_subdomain_policy_none: 'sp=none leaves every subdomain — including ones that have never existed — available for spoofing, while the domain itself is protected.',

  flag_dmarc_partial_percentage: 'The policy applies to only some mail',
  fd_dmarc_partial_percentage: 'pct= below 100 tells receivers to apply the policy to that share of failing messages and treat the rest more leniently. Useful while rolling out, and a gap for as long as it is set.',

  flag_dmarc_no_reporting: 'No address for aggregate reports',
  fd_dmarc_no_reporting: 'Without rua= you get no reports, which means no way to find out who is sending as your domain or what would break if you tightened the policy.',

  flag_dmarc_external_reporting_unauthorised: 'The external report address has not authorised you',
  fd_dmarc_external_reporting_unauthorised: 'Reports are directed at another domain, and that domain does not publish the record that agrees to receive them (RFC 7489 §7.1). Conforming receivers send nothing. The DMARC record looks perfect and the reports never arrive — which is almost always put down to reports "taking a while".',

  /* ---- findings: MTA-STS and TLS-RPT ---- */
  flag_mtasts_missing: 'No MTA-STS policy',
  fd_mtasts_missing: 'STARTTLS is opportunistic: a sender that does not see the offer sends in the clear, and stripping the offer is easy for anyone between the two servers. MTA-STS publishes over HTTPS that this domain always speaks TLS, which makes that attack require breaking the web PKI instead.',

  flag_mtasts_multiple_records: 'More than one MTA-STS TXT record',
  fd_mtasts_multiple_records: 'Senders cannot tell which id is current, so the policy may not be refreshed when it changes.',

  flag_mtasts_no_id: 'The MTA-STS record has no id',
  fd_mtasts_no_id: 'The id is how a sender knows its cached policy is stale. Without one, a changed policy may not be picked up until max_age expires.',

  flag_mtasts_policy_host_missing: 'The policy host does not resolve',
  fd_mtasts_policy_host_missing: 'The TXT record announces a policy, and mta-sts.<domain> has no address, so no sender can fetch it.',

  flag_mtasts_policy_host_private: 'The policy host resolves into private address space',
  fd_mtasts_policy_host_private: 'The policy was not fetched: the host points at an address this service will not connect to.',

  flag_mtasts_policy_unreachable: 'The MTA-STS policy could not be fetched',
  fd_mtasts_policy_unreachable: 'The TXT record promises a policy that is not there, or whose certificate does not validate. Since the whole mechanism rests on that HTTPS certificate, a failure here means senders fall back to opportunistic TLS.',

  flag_mtasts_policy_wrong_content_type: 'The policy is not served as text/plain',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 requires text/plain. Strict senders will refuse it.',

  flag_mtasts_policy_bad_version: 'The policy version is not STSv1',
  fd_mtasts_policy_bad_version: 'Senders will not use a policy whose version they do not recognise.',

  flag_mtasts_policy_bad_mode: 'The policy mode is not a recognised value',
  fd_mtasts_policy_bad_mode: 'mode must be enforce, testing or none.',

  flag_mtasts_mode_testing: 'MTA-STS is in testing mode',
  fd_mtasts_mode_testing: 'Failures are reported and mail is delivered anyway, so the policy protects nothing yet. A staging post, not a destination.',

  flag_mtasts_mode_none: 'MTA-STS is switched off by its own policy',
  fd_mtasts_mode_none: 'mode=none withdraws the policy. It exists so a domain can retire MTA-STS gracefully; left in place it simply means the record does nothing.',

  flag_mtasts_no_max_age: 'The policy has no max_age',
  fd_mtasts_no_max_age: 'max_age is required, and it is what makes the policy resistant to being suppressed — a sender that has cached it will keep enforcing it.',

  flag_mtasts_max_age_short: 'The policy is cached for less than a day',
  fd_mtasts_max_age_short: 'A short max_age narrows the window in which a cached policy protects a sender. A few weeks is the usual choice once the policy is stable.',

  flag_mtasts_mx_not_in_policy: 'A real mail server is missing from the policy',
  fd_mtasts_mx_not_in_policy: 'The MX set contains a host that no mx: pattern in the policy matches. Every sender enforcing this policy will refuse to deliver to that host — so mail fails for exactly the senders who are being careful.',

  flag_mtasts_policy_lists_unknown_mx: 'The policy lists patterns that match no current MX',
  fd_mtasts_policy_lists_unknown_mx: 'Harmless, and usually a leftover from a migration. Worth tidying so the policy still describes reality.',

  flag_mtasts_policy_no_mx: 'The policy lists no mail servers',
  fd_mtasts_policy_no_mx: 'A policy with no mx: entries matches nothing, so enforcing senders can deliver nowhere.',

  flag_tlsrpt_missing: 'No TLS-RPT record',
  fd_tlsrpt_missing: 'One TXT record, and it is the only way to learn that senders are failing to negotiate TLS with your servers. Without it an expired certificate or a broken STARTTLS is invisible from your side.',

  flag_tlsrpt_no_rua: 'The TLS-RPT record has no destination',
  fd_tlsrpt_no_rua: 'Without rua= there is nowhere for reports to go, so the record does nothing.',

  /* ---- findings: DANE ---- */
  flag_dane_missing: 'No DANE records',
  fd_dane_missing: 'TLSA records pin the certificate a mail server must present, using DNSSEC rather than the public certificate authorities. It is the stronger of the two transport mechanisms — and it needs the zone to be signed, which is the usual reason it is not in use.',

  flag_dane_partial: 'Only some mail servers have DANE records',
  fd_dane_partial: 'Senders choose a server by priority, so a set where only some hosts are pinned is protected only some of the time.',

  flag_dane_without_dnssec: 'A TLSA record in an unsigned zone',
  fd_dane_without_dnssec: 'DANE rests entirely on DNSSEC. Without signatures, anyone able to replace the MX record can replace the TLSA record too, so the pinning protects nothing while looking as though it does.',

  flag_dane_mismatch: 'The TLSA record does not match the certificate presented',
  fd_dane_mismatch: 'The server is presenting a certificate that its own DANE record does not authorise. Every sender that validates DANE will refuse to deliver — this stops mail.',

  flag_dane_pkix_usage: 'A TLSA record uses a PKIX usage',
  fd_dane_pkix_usage: 'Usages 0 and 1 require the certificate to validate through the public authorities as well. RFC 7672 §3.1 forbids both for SMTP, because there is no agreed way to do that check for mail.',

  flag_dane_full_certificate: 'A TLSA record pins the whole certificate',
  fd_dane_full_certificate: 'Matching type 0 stores the entire certificate rather than a hash. It works, it makes the record large, and it has to be replaced on every renewal.',

  /* ---- findings: SMTP ---- */
  flag_port_25_blocked_from_here: 'Outbound port 25 is blocked where this service runs',
  fd_port_25_blocked_from_here: 'This is about our network, not yours. Most hosting providers block outbound connections to port 25 by default. STARTTLS, DANE verification against a live certificate and the relay check therefore could not be made, and the grade is withheld rather than computed from what happened to be reachable.',

  flag_mx_not_reachable_on_25: 'No mail server answered on port 25',
  fd_mx_not_reachable_on_25: 'The MX records name hosts that do not accept connections on the port mail is delivered to. Nothing can be delivered to this domain.',

  flag_no_starttls: 'A mail server does not offer STARTTLS',
  fd_no_starttls: 'Every message delivered to this server crosses the internet unencrypted, readable by anything on the path. Offering STARTTLS costs a certificate and a line of configuration.',

  flag_starttls_fails: 'STARTTLS is offered and does not work',
  fd_starttls_fails: 'The server advertises STARTTLS and the handshake fails. Careful senders may refuse to fall back to plaintext and defer the mail instead — so this is worse than not offering it at all.',

  flag_starttls_legacy_protocol: 'The mail server negotiates an obsolete TLS version',
  fd_starttls_legacy_protocol: 'TLS 1.0 and 1.1 have been deprecated since RFC 8996. Senders are steadily withdrawing support, and when they do, mail stops.',

  flag_mx_certificate_not_trusted: 'The mail server\'s certificate does not validate',
  fd_mx_certificate_not_trusted: 'Ordinary opportunistic TLS does not verify certificates, so this does not stop delivery today. It stops it completely the moment MTA-STS in enforce mode or DANE is in play.',

  flag_banner_reveals_version: 'The greeting names the software and its version',
  fd_banner_reveals_version: 'A small gift to anyone scanning for a known bug in that exact version. The banner can say anything.',

  flag_open_relay: 'The server relays mail for strangers',
  fd_open_relay: 'It accepted a message from an unrelated sender to an unrelated recipient. Anyone can use it to send spam in your name, and it will be on blocklists within hours if it is not already. This needs fixing today. (The probe stopped at RCPT TO and sent RSET — no message was sent.)',

  flag_no_size_extension: 'The server does not announce SIZE',
  fd_no_size_extension: 'Without SIZE a sender cannot tell whether a large message will be accepted until it has finished transferring it.',

  flag_submission_without_starttls: 'The submission port does not offer STARTTLS',
  fd_submission_without_starttls: 'Port 587 is where mail clients authenticate. Without STARTTLS those credentials cross the network in the clear.',

  /* ---- findings: reverse DNS ---- */
  flag_rdns_missing: 'A mail server address has no PTR record',
  fd_rdns_missing: 'Missing reverse DNS is one of the most common reasons mail from a new server is deferred or filed as junk — and one of the least often explained by the receiving side.',

  flag_rdns_not_confirmed: 'Reverse DNS does not resolve back',
  fd_rdns_not_confirmed: 'The PTR record gives a name, and that name does not resolve to this address. Receivers check the round trip precisely because it requires two different parties to have done their part.',

  flag_rdns_none_confirmed: 'No mail server has forward-confirmed reverse DNS',
  fd_rdns_none_confirmed: 'Not one address passes the round-trip check. Expect delivery delays and junk filing from receivers that weigh it.',
};

OWN.ru = {
  title: 'Проверка почты — SPF, DKIM, DMARC, MTA-STS и DANE для любого домена',
  title_short: 'Проверка почты',
  h1: 'Проверка почты',
  subtitle: 'SPF раскрывается через все include и считается против лимита в десять запросов, выравнивание и отчётность DMARC, транспортная защита проверяется на живом соединении',
  ph_host: 'example.com',
  hero_label: 'Проверяемый домен',
  empty_hint: 'Введите доменное имя. Проверка раскрывает запись SPF через каждый include, перебирает селекторы DKIM, которыми пользуются крупные платформы, читает политику DMARC, забирает политику MTA-STS по HTTPS и открывает SMTP-сессии к почтовым серверам только на чтение. Ни одно письмо при этом не отправляется.',

  /* ---- этапы ---- */
  stage_resolve: 'поиск почтовых серверов',
  stage_mx: 'проверка набора MX',
  stage_spf: 'раскрытие SPF',
  stage_dkim: 'поиск ключей DKIM',
  stage_dmarc: 'чтение политики DMARC',
  stage_mtasts: 'загрузка политики MTA-STS',
  stage_dane: 'проверка DANE',
  stage_starttls: 'разговор с почтовыми серверами',
  stage_grade: 'выставление оценки',

  /* ---- карточки ---- */
  card_grade: 'Из чего сложилась оценка',
  card_mx: 'Почтовые серверы',
  card_spf: 'SPF',
  card_spf_tree: 'Раскрытие SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Защита транспорта',
  card_sessions: 'SMTP-сессии',
  card_rdns: 'Обратный DNS',

  /* ---- составляющие оценки ---- */
  comp_authentication: 'Аутентификация',
  comp_transport: 'Транспорт',
  comp_hygiene: 'Гигиена',

  /* ---- подписи строк ---- */
  k_mx_count: 'Записей MX',
  k_null_mx: 'Null MX',
  k_ipv6_mx: 'Доступны по IPv6',
  k_spf_record: 'Запись',
  k_spf_lookups: 'Израсходовано DNS-запросов',
  k_spf_voids: 'Пустых запросов',
  k_spf_policy: 'Что делать со всеми остальными',
  k_dkim_keys: 'Найдено ключей',
  k_dkim_tried: 'Перебрано селекторов',
  k_dkim_strongest: 'Самый сильный ключ',
  k_dmarc_policy: 'Политика',
  k_dmarc_subdomain: 'Политика для поддоменов',
  k_dmarc_percent: 'Применяется к',
  k_dmarc_alignment: 'Выравнивание (DKIM / SPF)',
  k_dmarc_rua: 'Сводные отчёты на',
  k_dmarc_ruf: 'Отчёты о сбоях на',
  k_dmarc_external: 'Внешняя отчётность разрешена',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Режим',
  k_mtasts_id: 'Идентификатор политики',
  k_mtasts_maxage: 'Кэшируется на',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Покрыто серверов',
  k_starttls: 'STARTTLS',
  k_port25: 'Исходящий порт 25',
  k_open_relay: 'Открытый релей',
  k_rdns_confirmed: 'Подтверждено прямым запросом',
  k_queries: 'Сделано запросов',

  /* ---- заголовки таблиц ---- */
  th_priority: 'Приоритет',
  th_host: 'Хост',
  th_addresses: 'Адреса',
  th_port: 'Порт',
  th_tls: 'TLS',
  th_banner: 'Приветствие',
  th_extensions: 'Объявлено',
  th_selector: 'Селектор',
  th_key_type: 'Ключ',
  th_bits: 'Бит',
  th_state: 'Состояние',
  th_address: 'Адрес',
  th_ptr: 'PTR',
  th_confirmed: 'Подтверждён',
  th_term: 'Терм',
  th_lookup: 'Запрос',

  /* ---- значения ---- */
  pol_none: 'none — только наблюдение',
  pol_quarantine: 'quarantine — в спам',
  pol_reject: 'reject — отклонять',
  spfp_pass: 'пропускать всех (+all)',
  spfp_fail: 'отклонять (-all)',
  spfp_softfail: 'мягкий отказ (~all)',
  spfp_neutral: 'нейтрально (?all)',
  spfp_redirect: 'делегировано через redirect',
  spfterm_no_target: 'нет цели',
  spfterm_loop: 'цикл — уже посещали',
  spfterm_lookup_failed: 'запрос не удался',
  spfterm_no_spf_record: 'там нет записи SPF',

  stsmode_enforce: 'enforce — применять',
  stsmode_testing: 'testing — только отчёты',
  stsmode_none: 'none — отключена',
  rdns_confirmed: 'подтверждён',
  rdns_unconfirmed: 'не разрешается обратно',
  rdns_missing: 'нет PTR',
  rdns_unknown: 'не проверялось',
  v_of_limit: '{used} из {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} дн.',
  v_blocked_here: 'закрыт из нашей сети',
  v_no_selector_found: 'ни одного из {n} известных селекторов',

  /* ---- пояснения ---- */
  note_spf: 'RFC 7208 разрешает десять терминов с DNS-запросами на всю проверку, считая внутри каждого include каждый вложенный include. За десятым получатель обязан вернуть permerror — а permerror означает, что SPF не применяется вовсе, ровно как если бы записи не было.',
  note_dmarc: 'При p=none не применяется ничего: письмо, не прошедшее выравнивание ни по SPF, ни по DKIM, доставляется как раньше. Это правильное место, чтобы начать, и неправильное, чтобы остаться.',
  note_transport: 'STARTTLS оппортунистичен: отправитель, у которого вырезали предложение шифрования, просто продолжит открытым текстом. MTA-STS и DANE — это то, что превращает возможность в гарантию.',
  note_sessions: 'Все сессии только на чтение. Проверка релея останавливается на RCPT TO и отправляет RSET; команда DATA не выдаётся никогда, поэтому отправить письмо невозможно.',
  note_rdns: 'Сама по себе запись PTR ничего не доказывает — владелец блока адресов может написать там любое имя. Получатели проверяют, разрешается ли это имя обратно в тот же адрес.',

  /* ---- ошибки этого сервиса ---- */
  err_smtp_timeout: 'Почтовый сервер не ответил вовремя.',
  err_smtp_network: 'До почтового сервера не удалось достучаться.',
  err_smtp_refused: 'Почтовый сервер отклонил соединение.',
  err_tls_failed: 'Рукопожатие TLS с почтовым сервером не удалось.',

  /* ---- чего не удалось установить ---- */
  inc_mx_lookup_failed: 'не удалось прочитать записи MX',
  inc_spf_lookup_failed: 'не удалось прочитать запись SPF',
  inc_dmarc_lookup_failed: 'не удалось прочитать запись DMARC',
  inc_port_25_unreachable_from_this_network: 'исходящий порт 25 закрыт там, где работает сервис, поэтому STARTTLS, сверку DANE с живым сертификатом и проверку релея сделать не удалось',
  inc_not_every_mx_was_probed: 'подключались только к серверам с наивысшим приоритетом',

  /* ---- ограничители оценки ---- */
  cap_open_relay: 'сервер пересылает почту для посторонних',
  cap_spf_authorises_everyone: 'SPF разрешает отправку всему интернету',
  cap_no_mail_servers: 'нет почтовых серверов',
  cap_mail_servers_unreachable: 'ни один почтовый сервер не ответил на порту 25',
  cap_dane_mismatch: 'DANE не совпадает с предъявленным сертификатом',
  cap_mtasts_policy_contradicts_dns: 'в политике MTA-STS не хватает реального почтового сервера',
  cap_spf_over_the_lookup_limit: 'SPF вышел за лимит запросов',
  cap_spf_permerror: 'SPF — постоянная ошибка',
  cap_dmarc_permerror: 'DMARC — постоянная ошибка',
  cap_mail_in_the_clear: 'почта принимается без шифрования',
  cap_no_spf: 'нет записи SPF',
  cap_no_dmarc: 'нет записи DMARC',
  cap_starttls_broken: 'STARTTLS предлагается и не работает',
  cap_dmarc_not_enforcing: 'DMARC ничего не применяет',
  cap_no_reverse_dns: 'нет подтверждённого обратного DNS',
  cap_spf_without_a_default: 'у SPF нет значения по умолчанию',
  cap_weak_dkim_key: 'слишком короткий ключ DKIM',
  cap_dmarc_reports_go_nowhere: 'отчёты DMARC не разрешены получателем',
  cap_mail_server_does_not_resolve: 'почтовый сервер не разрешается в адрес',
  cap_scan_incomplete: 'проверка неполная, поэтому оценка не выставлена',

  /* ---- находки: MX ---- */
  flag_null_mx: 'Домен объявляет, что почтой не занимается',
  fd_null_mx: 'Единственная запись MX с приоритетом 0, указывающая на корень, — это RFC 7505 для «домен не отправляет и не принимает почту». Осознанное решение, и куда лучше, чем полное отсутствие MX: без него отправители откатываются на адресную запись.',

  flag_no_mx: 'Нет записей MX',
  fd_no_mx: 'Ничто не говорит, куда доставлять почту для этого домена, и адресной записи для отката тоже нет, поэтому доставить письмо попросту некуда.',

  flag_no_mx_falls_back_to_a: 'Записей MX нет, отправители откатываются на запись A',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 предписывает отправителю без MX пробовать адресную запись. Почта для домена уйдёт на то, что слушает порт 25 у веб-сервера, — а этого почти никогда не хотели.',

  flag_duplicate_mx_host: 'Один и тот же хост указан дважды',
  fd_duplicate_mx_host: 'Один хост встречается с разными приоритетами. Это не резервирование, а та же самая машина, к которой попробуют дважды.',

  flag_mx_does_not_resolve: 'Имя почтового сервера не разрешается',
  fd_mx_does_not_resolve: 'MX указывает на хост без адресных записей. Каждый отправитель, дошедший до этого приоритета, ждёт ответа, не получает ничего и переходит дальше — задерживая почту, которая должна была прийти сразу.',

  flag_mx_points_at_cname: 'Запись MX указывает на псевдоним',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 требует, чтобы MX называл хост с адресными записями, а не CNAME. Часть отправителей справляется, часть отказывается, и состав этих частей со временем меняется.',

  flag_single_mx: 'Единственный почтовый сервер',
  fd_single_mx: 'С одним MX любая его недоступность означает, что отправители копят письма в очереди и повторяют попытки — часами или сутками, по своей собственной политике, — и часть этой почты в итоге вернётся отправителю.',

  flag_no_ipv6_mx: 'Ни один почтовый сервер недоступен по IPv6',
  fd_no_ipv6_mx: 'Отправители в IPv6-only сетях доберутся до домена через трансляцию, если доберутся вообще.',

  /* ---- находки: SPF ---- */
  flag_spf_missing: 'Нет записи SPF',
  fd_spf_missing: 'Ничто не говорит, какие серверы вправе отправлять почту от имени домена, поэтому и сверять нечего. SPF — это одна TXT-запись и самое дешёвое из всего, что есть на этой странице.',

  flag_spf_multiple_records: 'Больше одной записи SPF',
  fd_spf_multiple_records: 'RFC 7208 §4.5 делает две записи постоянной ошибкой, а permerror означает отсутствие результата SPF вообще — прямо противоположное тому, ради чего добавляли вторую. Их нужно объединить в одну.',

  flag_spf_too_many_lookups: 'SPF требует больше десяти DNS-запросов',
  fd_spf_too_many_lookups: 'Лимит в RFC 7208 §4.6.4 — десять терминов с запросами на всю проверку, считая внутри каждого include каждый вложенный include. За ним получатель обязан вернуть permerror, и SPF перестаёт применяться — записи с тем же успехом могло не быть. Перешагнуть лимит легко, добавив ещё одного провайдера, и по самой записи это совершенно не видно.',

  flag_spf_lookups_near_limit: 'SPF близок к лимиту в десять запросов',
  fd_spf_lookups_near_limit: 'Запаса почти не осталось. Следующий добавленный сервис — или изменение внутри чужого include, которым вы не управляете, — выведет запись за лимит.',

  flag_spf_too_many_void_lookups: 'Слишком много запросов SPF возвращают пустоту',
  fd_spf_too_many_void_lookups: 'RFC 7208 допускает два запроса, не давших ничего; сверх этого — постоянная ошибка. Обычно это забытый include для сервиса, которым больше не пользуются.',

  flag_spf_no_all: 'У SPF нет значения по умолчанию',
  fd_spf_no_all: 'Без механизма «all» и без redirect отправитель, не совпавший ни с чем, получает нейтральный результат — то есть то же самое, что отсутствие мнения.',

  flag_spf_plus_all: 'SPF разрешает отправку всему интернету',
  fd_spf_plus_all: '«+all» говорит, что отправлять от имени домена может любой хост где угодно. Это почти всегда непонимание того, что означает квалификатор, и это хуже отсутствия SPF: запись прямо ручается за подделывающего.',

  flag_spf_neutral_all: 'SPF заканчивается на ?all',
  fd_spf_neutral_all: '«?all» прямо отказывается что-либо говорить об отправителях, не совпавших ни с чем. Получатели трактуют это как отсутствие результата.',

  flag_spf_softfail_all: 'SPF заканчивается на ~all, а не на -all',
  fd_spf_softfail_all: 'Мягкий отказ просит получателей принять письмо, но пометить. Это верная настройка, пока вы ещё выясняете, кто отправляет от вашего имени, и то, что стоит ужесточить, когда выяснили.',

  flag_spf_uses_ptr: 'SPF использует механизм ptr',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 объявляет ptr устаревшим: он медленный, ненадёжный и перекладывает работу на того, кто держит обратную зону. Часть получателей игнорирует его полностью.',

  flag_spf_unknown_mechanism: 'В SPF есть термин, которого никто не понимает',
  fd_spf_unknown_mechanism: 'Нераспознанный механизм по RFC 7208 §4.6.1 — постоянная ошибка, отбрасывающая всю запись целиком. Обычно это опечатка.',

  flag_spf_duplicate_redirect: 'Больше одного модификатора redirect',
  fd_spf_duplicate_redirect: 'Второй redirect делает запись постоянной ошибкой.',

  flag_spf_redirect_after_all: 'Redirect, до которого никогда не дойдут',
  fd_spf_redirect_after_all: 'В записи есть и механизм «all», и redirect. «all» совпадает всегда, поэтому вычисление останавливается на нём, а redirect остаётся мёртвым текстом.',

  flag_spf_record_long: 'Запись SPF длинная',
  fd_spf_record_long: 'Длинные записи разбиваются на несколько строк на проводе. Само по себе это нормально — получатели склеивают их без разделителя, — но именно здесь разборщики, соединяющие куски пробелом, начинают портить запись.',

  flag_spf_include_loop: 'Include указывает на то, где уже были',
  fd_spf_include_loop: 'Раскрытие зацикливается. Получатель дойдёт до лимита запросов и вернёт постоянную ошибку.',

  flag_spf_include_without_record: 'Include указывает на домен без записи SPF',
  fd_spf_include_without_record: 'RFC 7208 §5.2 считает это постоянной ошибкой, а не просто впустую потраченным запросом. Обычно это сервис, который убрали с одной стороны и не убрали с другой.',

  /* ---- находки: DKIM ---- */
  flag_dkim_no_known_selector: 'Ни на одном известном нам селекторе ключа DKIM нет',
  fd_dkim_no_known_selector: 'Селектор выбирает тот, кто подписывает, и виден он только в заголовке подписанного письма, поэтому снаружи перебрать их нельзя. Это не доказательство отсутствия DKIM — если вы знаете свой селектор, передайте его через ?selector=, и проверка станет однозначной.',

  flag_dkim_key_revoked: 'Ключ DKIM отозван',
  fd_dkim_key_revoked: 'Запись опубликована с пустым p=, что отзывает ключ. Это правильный способ вывести ключ из обращения — и запись, оставшаяся в таком виде на месяцы, обычно означает незавершённую смену ключа.',

  flag_dkim_key_malformed: 'Ключ DKIM не разбирается',
  fd_dkim_key_malformed: 'Значение p= не является корректным ключевым материалом. Любая подпись, сделанная им, проверку не пройдёт.',

  flag_dkim_in_test_mode: 'Запись DKIM в тестовом режиме',
  fd_dkim_in_test_mode: 't=y просит получателей относиться к неверной подписи так, будто DKIM не используется. Место такому флагу — во время внедрения и больше нигде.',

  flag_dkim_key_too_short: 'Ключ DKIM короче 1024 бит',
  fd_dkim_key_too_short: 'Ниже 1024 бит подпись подделать не так уж трудно, и многие получатели просто игнорируют такие ключи.',

  flag_dkim_key_1024_bit: 'Ключ DKIM на 1024 бита',
  fd_dkim_key_1024_bit: 'Пока принимается везде и ниже текущих рекомендаций. Нормальный размер — 2048; смена сводится к новому селектору и DNS-записи.',

  /* ---- находки: DMARC ---- */
  flag_dmarc_missing: 'Нет записи DMARC',
  fd_dmarc_missing: 'Без DMARC результаты SPF и DKIM носят рекомендательный характер: ничто не связывает их с адресом, который видит читатель, и ничто не говорит получателям, что делать при несовпадении.',

  flag_dmarc_inherited: 'DMARC унаследован от родительского домена',
  fd_dmarc_inherited: 'У этого имени своей записи нет, поэтому действует политика организационного домена — его sp=, если он задан, иначе p=.',

  flag_dmarc_multiple_records: 'Больше одной записи DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: при нескольких записях политика отбрасывается целиком, как если бы её не публиковали.',

  flag_dmarc_no_policy: 'В записи DMARC нет тега p=',
  fd_dmarc_no_policy: 'Тег p= обязателен. Без него запись игнорируется.',

  flag_dmarc_invalid_policy: 'Политика DMARC не является распознаваемым значением',
  fd_dmarc_invalid_policy: 'p= должен быть none, quarantine или reject. При любом другом значении получатели отбрасывают запись.',

  flag_dmarc_policy_none: 'DMARC ничего не применяет',
  fd_dmarc_policy_none: 'p=none просит получателей присылать отчёты и ничего не менять. Письмо, не прошедшее выравнивание ни по SPF, ни по DKIM, доставляется ровно так же, как без DMARC. Это правильный способ начать — и очень многие домены сидят так годами, полагая, что защищены.',

  flag_dmarc_policy_quarantine: 'DMARC отправляет в карантин, а не отклоняет',
  fd_dmarc_policy_quarantine: 'Не прошедшая проверку почта попадает в папку со спамом, а не отклоняется. Разумный шаг на пути к reject — и место, где подделанные письма всё ещё доходят до людей.',

  flag_dmarc_subdomain_policy_none: 'Поддомены выведены из-под политики',
  fd_dmarc_subdomain_policy_none: 'sp=none оставляет любой поддомен — включая те, которых никогда не существовало, — доступным для подделки, тогда как сам домен защищён.',

  flag_dmarc_partial_percentage: 'Политика применяется лишь к части почты',
  fd_dmarc_partial_percentage: 'pct= меньше 100 говорит получателям применять политику к этой доле неудачных писем, а с остальными обходиться мягче. Полезно при внедрении и остаётся дырой всё то время, пока стоит.',

  flag_dmarc_no_reporting: 'Не указан адрес для сводных отчётов',
  fd_dmarc_no_reporting: 'Без rua= отчётов не будет, а значит, не будет и способа узнать, кто отправляет от имени вашего домена и что сломается, если политику ужесточить.',

  flag_dmarc_external_reporting_unauthorised: 'Внешний адрес для отчётов вас не авторизовал',
  fd_dmarc_external_reporting_unauthorised: 'Отчёты направлены в другой домен, а тот не публикует запись, которой соглашается их принимать (RFC 7489 §7.1). Соответствующие стандарту получатели не отправят ничего. Запись DMARC при этом выглядит безупречно, а отчёты не приходят — и это почти всегда списывают на то, что «отчёты идут не сразу».',

  /* ---- находки: MTA-STS и TLS-RPT ---- */
  flag_mtasts_missing: 'Нет политики MTA-STS',
  fd_mtasts_missing: 'STARTTLS оппортунистичен: отправитель, не увидевший предложения шифрования, отправит открытым текстом, а вырезать это предложение легко любому, кто находится между серверами. MTA-STS публикует по HTTPS, что домен всегда говорит по TLS, и тем самым требует от атакующего сломать не одну строчку сессии, а веб-PKI.',

  flag_mtasts_multiple_records: 'Больше одной TXT-записи MTA-STS',
  fd_mtasts_multiple_records: 'Отправители не могут понять, какой идентификатор актуален, поэтому политика может не обновиться при изменении.',

  flag_mtasts_no_id: 'В записи MTA-STS нет идентификатора',
  fd_mtasts_no_id: 'Идентификатор — это то, по чему отправитель понимает, что его копия политики устарела. Без него изменённая политика может не подхватиться, пока не истечёт max_age.',

  flag_mtasts_policy_host_missing: 'Хост политики не разрешается',
  fd_mtasts_policy_host_missing: 'TXT-запись объявляет политику, а у mta-sts.<домен> нет адреса, так что забрать её не сможет ни один отправитель.',

  flag_mtasts_policy_host_private: 'Хост политики разрешается в частный адрес',
  fd_mtasts_policy_host_private: 'Политика не загружалась: хост указывает на адрес, к которому сервис подключаться не станет.',

  flag_mtasts_policy_unreachable: 'Политику MTA-STS не удалось загрузить',
  fd_mtasts_policy_unreachable: 'TXT-запись обещает политику, которой там нет, либо сертификат хоста политики не проходит проверку. Поскольку весь механизм держится на этом сертификате HTTPS, сбой здесь означает, что отправители откатятся на оппортунистический TLS.',

  flag_mtasts_policy_wrong_content_type: 'Политика отдаётся не как text/plain',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 требует text/plain. Строгие отправители такую политику отвергнут.',

  flag_mtasts_policy_bad_version: 'Версия политики не STSv1',
  fd_mtasts_policy_bad_version: 'Отправители не станут использовать политику, версию которой не понимают.',

  flag_mtasts_policy_bad_mode: 'Режим политики не является распознаваемым значением',
  fd_mtasts_policy_bad_mode: 'mode должен быть enforce, testing или none.',

  flag_mtasts_mode_testing: 'MTA-STS в тестовом режиме',
  fd_mtasts_mode_testing: 'О сбоях сообщается, почта всё равно доставляется, то есть политика пока ничего не защищает. Промежуточная станция, а не конечная.',

  flag_mtasts_mode_none: 'MTA-STS отключён собственной политикой',
  fd_mtasts_mode_none: 'mode=none отзывает политику. Так предусмотрен аккуратный вывод MTA-STS из обращения; оставленный на месте, он просто означает, что запись ничего не делает.',

  flag_mtasts_no_max_age: 'В политике нет max_age',
  fd_mtasts_no_max_age: 'max_age обязателен, и именно он делает политику устойчивой к подавлению: отправитель, успевший её закэшировать, продолжит её применять.',

  flag_mtasts_max_age_short: 'Политика кэшируется меньше суток',
  fd_mtasts_max_age_short: 'Короткий max_age сужает окно, в котором закэшированная политика защищает отправителя. Обычный выбор для устоявшейся политики — несколько недель.',

  flag_mtasts_mx_not_in_policy: 'В политике не хватает реального почтового сервера',
  fd_mtasts_mx_not_in_policy: 'В наборе MX есть хост, под который не подходит ни один шаблон mx: из политики. Любой отправитель, применяющий эту политику, откажется доставлять на этот хост — то есть почта ломается ровно у тех отправителей, которые ведут себя аккуратно.',

  flag_mtasts_policy_lists_unknown_mx: 'В политике есть шаблоны, под которые не подходит ни один MX',
  fd_mtasts_policy_lists_unknown_mx: 'Безвредно и обычно осталось от переезда. Стоит прибрать, чтобы политика по-прежнему описывала действительность.',

  flag_mtasts_policy_no_mx: 'В политике не перечислено ни одного почтового сервера',
  fd_mtasts_policy_no_mx: 'Политика без записей mx: не подходит ни подо что, поэтому применяющим её отправителям доставлять некуда.',

  flag_tlsrpt_missing: 'Нет записи TLS-RPT',
  fd_tlsrpt_missing: 'Одна TXT-запись, и это единственный способ узнать, что у отправителей не получается договориться о TLS с вашими серверами. Без неё истёкший сертификат или сломанный STARTTLS с вашей стороны не виден вообще.',

  flag_tlsrpt_no_rua: 'В записи TLS-RPT нет адреса назначения',
  fd_tlsrpt_no_rua: 'Без rua= отчётам некуда идти, поэтому запись ничего не делает.',

  /* ---- находки: DANE ---- */
  flag_dane_missing: 'Нет записей DANE',
  fd_dane_missing: 'Записи TLSA закрепляют сертификат, который обязан предъявить почтовый сервер, опираясь на DNSSEC, а не на публичные удостоверяющие центры. Из двух транспортных механизмов этот сильнее — и он требует подписанной зоны, что обычно и есть причина, по которой его не используют.',

  flag_dane_partial: 'Записи DANE есть лишь у части почтовых серверов',
  fd_dane_partial: 'Отправители выбирают сервер по приоритету, поэтому набор, где закреплена только часть хостов, защищён только часть времени.',

  flag_dane_without_dnssec: 'Запись TLSA в неподписанной зоне',
  fd_dane_without_dnssec: 'DANE целиком держится на DNSSEC. Без подписей тот, кто способен подменить запись MX, подменит и TLSA, поэтому закрепление ничего не защищает, хотя и выглядит так, будто защищает.',

  flag_dane_mismatch: 'Запись TLSA не совпадает с предъявленным сертификатом',
  fd_dane_mismatch: 'Сервер предъявляет сертификат, который его же запись DANE не разрешает. Любой отправитель, проверяющий DANE, откажется доставлять — это останавливает почту.',

  flag_dane_pkix_usage: 'В записи TLSA используется PKIX-режим',
  fd_dane_pkix_usage: 'Режимы 0 и 1 требуют, чтобы сертификат дополнительно проходил проверку через публичные центры. RFC 7672 §3.1 запрещает оба для SMTP, потому что общепринятого способа делать такую проверку для почты нет.',

  flag_dane_full_certificate: 'Запись TLSA закрепляет сертификат целиком',
  fd_dane_full_certificate: 'Тип сопоставления 0 хранит весь сертификат, а не хеш. Работает, делает запись большой и требует замены при каждом продлении.',

  /* ---- находки: SMTP ---- */
  flag_port_25_blocked_from_here: 'Исходящий порт 25 закрыт там, где работает сервис',
  fd_port_25_blocked_from_here: 'Это про нашу сеть, не про вашу. Большинство хостеров закрывают исходящие соединения на порт 25 по умолчанию. Поэтому STARTTLS, сверку DANE с живым сертификатом и проверку релея сделать не удалось, и оценка не выставляется вместо того, чтобы считаться по тому, до чего дотянулись.',

  flag_mx_not_reachable_on_25: 'Ни один почтовый сервер не ответил на порту 25',
  fd_mx_not_reachable_on_25: 'Записи MX называют хосты, которые не принимают соединения на порту доставки почты. Доставить в этот домен ничего нельзя.',

  flag_no_starttls: 'Почтовый сервер не предлагает STARTTLS',
  fd_no_starttls: 'Каждое доставленное на этот сервер письмо идёт через интернет незашифрованным и читается всем, что стоит на пути. Предложить STARTTLS стоит сертификата и строчки конфигурации.',

  flag_starttls_fails: 'STARTTLS предлагается и не работает',
  fd_starttls_fails: 'Сервер объявляет STARTTLS, а рукопожатие срывается. Аккуратные отправители могут отказаться откатываться на открытый текст и отложить письмо — так что это хуже, чем не предлагать STARTTLS вовсе.',

  flag_starttls_legacy_protocol: 'Почтовый сервер договаривается на устаревшей версии TLS',
  fd_starttls_legacy_protocol: 'TLS 1.0 и 1.1 объявлены устаревшими в RFC 8996. Отправители последовательно снимают их поддержку, и когда снимут — почта перестанет ходить.',

  flag_mx_certificate_not_trusted: 'Сертификат почтового сервера не проходит проверку',
  fd_mx_certificate_not_trusted: 'Обычный оппортунистический TLS сертификаты не проверяет, поэтому сегодня доставке это не мешает. Мешать начнёт ровно в тот момент, когда появится MTA-STS в режиме enforce или DANE.',

  flag_banner_reveals_version: 'В приветствии названы программа и её версия',
  fd_banner_reveals_version: 'Небольшой подарок тому, кто ищет хосты с известной ошибкой именно в этой версии. В баннере можно написать что угодно.',

  flag_open_relay: 'Сервер пересылает почту для посторонних',
  fd_open_relay: 'Он принял письмо от постороннего отправителя постороннему получателю. Любой может слать через него спам от вашего имени, и он окажется в чёрных списках в течение суток, если уже не там. Это чинят сегодня. (Проверка остановилась на RCPT TO и отправила RSET — никакого письма отправлено не было.)',

  flag_no_size_extension: 'Сервер не объявляет SIZE',
  fd_no_size_extension: 'Без SIZE отправитель не может узнать, примут ли большое письмо, пока не передаст его целиком.',

  flag_submission_without_starttls: 'Порт отправки не предлагает STARTTLS',
  fd_submission_without_starttls: 'Порт 587 — это то место, где почтовые клиенты проходят аутентификацию. Без STARTTLS их учётные данные идут по сети открытым текстом.',

  /* ---- находки: обратный DNS ---- */
  flag_rdns_missing: 'У адреса почтового сервера нет записи PTR',
  fd_rdns_missing: 'Отсутствие обратного DNS — одна из самых частых причин, по которым почту с нового сервера откладывают или кладут в спам, и одна из тех, которые получающая сторона объясняет реже всего.',

  flag_rdns_not_confirmed: 'Обратный DNS не разрешается обратно',
  fd_rdns_not_confirmed: 'Запись PTR даёт имя, и это имя не разрешается в тот же адрес. Получатели проверяют именно круговой запрос — как раз потому, что для его прохождения свою часть работы должны сделать две разные стороны.',

  flag_rdns_none_confirmed: 'Ни у одного почтового сервера нет подтверждённого обратного DNS',
  fd_rdns_none_confirmed: 'Круговую проверку не проходит ни один адрес. Ждите задержек доставки и попадания в спам у получателей, которые это учитывают.',
};

window.I18N = window.mergeI18N(OWN);
