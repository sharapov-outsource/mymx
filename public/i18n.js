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
  subtitle: 'SPF раскрывается через все include и сверяется с лимитом в десять запросов, выравнивание и отчётность DMARC, транспортная защита проверяется на живом соединении',
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
  note_transport: 'STARTTLS необязателен: отправитель, у которого вырезали объявление о шифровании, просто продолжит открытым текстом. MTA-STS и DANE — это то, что превращает возможность в гарантию.',
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
  fd_null_mx: 'Единственная запись MX с приоритетом 0, указывающая на корень, — это описанный в RFC 7505 способ сказать, что домен не отправляет и не принимает почту. Осознанное решение, и куда лучше, чем полное отсутствие MX: без него отправители откатываются на A-запись.',

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
  fd_spf_too_many_lookups: 'Лимит в RFC 7208 §4.6.4 — десять терминов, обращающихся к DNS, на всю проверку, считая внутри каждого include каждый вложенный include. За ним получатель обязан вернуть permerror, и SPF перестаёт применяться — записи с тем же успехом могло не быть. Перешагнуть лимит легко, добавив ещё одного провайдера, и по самой записи это совершенно не видно.',

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
  fd_spf_record_long: 'Длинные записи при передаче разбиваются на несколько строк. Само по себе это нормально — получатели склеивают их без разделителя, — но именно здесь разборщики, соединяющие куски пробелом, начинают портить запись.',

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
  fd_dkim_key_malformed: 'Значение p= не разбирается как ключ. Любая подпись, сделанная им, проверку не пройдёт.',

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

  flag_dmarc_invalid_policy: 'Значение политики DMARC не распознано',
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
  fd_mtasts_missing: 'STARTTLS необязателен: если отправитель не увидел, что сервер объявляет шифрование, он отправит письмо открытым текстом, — а убрать это объявление из ответа может любой, кто стоит между серверами. MTA-STS выкладывает по HTTPS политику: домен всегда принимает почту по TLS. Чтобы обойти её, атакующему придётся ломать уже не одну строку в диалоге, а веб-PKI.',

  flag_mtasts_multiple_records: 'Больше одной TXT-записи MTA-STS',
  fd_mtasts_multiple_records: 'Отправители не могут понять, какой идентификатор актуален, поэтому политика может не обновиться при изменении.',

  flag_mtasts_no_id: 'В записи MTA-STS нет идентификатора',
  fd_mtasts_no_id: 'Идентификатор — это то, по чему отправитель понимает, что его копия политики устарела. Без него изменённая политика может не подхватиться, пока не истечёт max_age.',

  flag_mtasts_policy_host_missing: 'Хост политики не разрешается',
  fd_mtasts_policy_host_missing: 'TXT-запись объявляет политику, а у mta-sts.<домен> нет адреса, так что забрать её не сможет ни один отправитель.',

  flag_mtasts_policy_host_private: 'Хост политики разрешается в частный адрес',
  fd_mtasts_policy_host_private: 'Политика не загружалась: хост указывает на адрес, к которому сервис подключаться не станет.',

  flag_mtasts_policy_unreachable: 'Политику MTA-STS не удалось загрузить',
  fd_mtasts_policy_unreachable: 'TXT-запись обещает политику, которой там нет, либо сертификат хоста политики не проходит проверку. Поскольку весь механизм держится на этом сертификате HTTPS, сбой здесь означает, что отправители откатятся на необязательное шифрование.',

  flag_mtasts_policy_wrong_content_type: 'Политика отдаётся не как text/plain',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 требует text/plain. Строгие отправители такую политику отвергнут.',

  flag_mtasts_policy_bad_version: 'Версия политики не STSv1',
  fd_mtasts_policy_bad_version: 'Отправители не станут использовать политику, версию которой не понимают.',

  flag_mtasts_policy_bad_mode: 'Режим политики не распознан',
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
  fd_mtasts_mx_not_in_policy: 'В наборе MX есть хост, который не покрывает ни один шаблон mx: из политики. Любой отправитель, применяющий эту политику, откажется доставлять на этот хост — то есть почта ломается ровно у тех отправителей, которые ведут себя аккуратно.',

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
  fd_dane_missing: 'Записи TLSA задают, какой сертификат обязан предъявить почтовый сервер, и опираются при этом на DNSSEC, а не на публичные удостоверяющие центры. Из двух транспортных механизмов этот сильнее — и он требует подписанной зоны, что обычно и есть причина, по которой его не используют.',

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
  fd_mx_certificate_not_trusted: 'Сам по себе STARTTLS сертификаты не проверяет, поэтому сегодня доставке это не мешает. Мешать начнёт ровно в тот момент, когда появится MTA-STS в режиме enforce или DANE.',

  flag_banner_reveals_version: 'В приветствии названы программа и её версия',
  fd_banner_reveals_version: 'Небольшой подарок тому, кто ищет хосты с известной ошибкой именно в этой версии. В баннере можно написать что угодно.',

  flag_open_relay: 'Сервер пересылает почту для посторонних',
  fd_open_relay: 'Он принял письмо от постороннего отправителя постороннему получателю. Любой может слать через него спам от вашего имени, и он окажется в чёрных списках в течение суток, если уже не там. Чинить это нужно сегодня же. (Проверка остановилась на RCPT TO и отправила RSET — никакого письма отправлено не было.)',

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

OWN.es = {
  title: 'Comprobación de correo — SPF, DKIM, DMARC, MTA-STS y DANE de cualquier dominio',
  title_short: 'Comprobación de correo',
  h1: 'Comprobación de correo',
  subtitle: 'SPF desplegado a través de cada include y contado contra el límite de diez, alineación y notificación DMARC, y la seguridad del transporte comprobada sobre la conexión real',
  ph_host: 'example.com',
  hero_label: 'Dominio comprobado',
  empty_hint: 'Introduzca un nombre de dominio. La comprobación despliega el registro SPF a través de cada include, prueba los selectores DKIM que usan las grandes plataformas, lee la política DMARC, descarga la política MTA-STS por HTTPS y abre sesiones SMTP de solo lectura con los servidores de correo. Nunca se envía ningún mensaje.',

  stage_resolve: 'buscando los servidores de correo',
  stage_mx: 'comprobando el conjunto MX',
  stage_spf: 'desplegando SPF',
  stage_dkim: 'buscando claves DKIM',
  stage_dmarc: 'leyendo la política DMARC',
  stage_mtasts: 'descargando la política MTA-STS',
  stage_dane: 'comprobando DANE',
  stage_starttls: 'hablando con los servidores de correo',
  stage_grade: 'calificando',

  card_grade: 'Desglose de la nota',
  card_mx: 'Servidores de correo',
  card_spf: 'SPF',
  card_spf_tree: 'Despliegue de SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Seguridad del transporte',
  card_sessions: 'Sesiones SMTP',
  card_rdns: 'DNS inverso',

  comp_authentication: 'Autenticación',
  comp_transport: 'Transporte',
  comp_hygiene: 'Higiene',

  k_mx_count: 'Registros MX',
  k_null_mx: 'MX nulo',
  k_ipv6_mx: 'Accesibles por IPv6',
  k_spf_record: 'Registro',
  k_spf_lookups: 'Consultas DNS usadas',
  k_spf_voids: 'Consultas vacías',
  k_spf_policy: 'Por defecto para los demás',
  k_dkim_keys: 'Claves encontradas',
  k_dkim_tried: 'Selectores probados',
  k_dkim_strongest: 'Clave más fuerte',
  k_dmarc_policy: 'Política',
  k_dmarc_subdomain: 'Política para subdominios',
  k_dmarc_percent: 'Se aplica al',
  k_dmarc_alignment: 'Alineación (DKIM / SPF)',
  k_dmarc_rua: 'Informes agregados a',
  k_dmarc_ruf: 'Informes forenses a',
  k_dmarc_external: 'Notificación externa autorizada',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Modo',
  k_mtasts_id: 'Id de la política',
  k_mtasts_maxage: 'Se guarda durante',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Servidores cubiertos',
  k_starttls: 'STARTTLS',
  k_port25: 'Puerto 25 saliente',
  k_open_relay: 'Retransmisión abierta',
  k_rdns_confirmed: 'Confirmado hacia delante',
  k_queries: 'Consultas realizadas',

  th_priority: 'Prioridad',
  th_host: 'Host',
  th_addresses: 'Direcciones',
  th_port: 'Puerto',
  th_tls: 'TLS',
  th_banner: 'Saludo',
  th_extensions: 'Anunciado',
  th_selector: 'Selector',
  th_key_type: 'Clave',
  th_bits: 'Bits',
  th_state: 'Estado',
  th_address: 'Dirección',
  th_ptr: 'PTR',
  th_confirmed: 'Confirmado',
  th_term: 'Término',
  th_lookup: 'Consulta',

  pol_none: 'none — solo observación',
  pol_quarantine: 'quarantine — a la carpeta de correo no deseado',
  pol_reject: 'reject — rechazar',
  spfp_pass: 'admitir a todos (+all)',
  spfp_fail: 'rechazar (-all)',
  spfp_softfail: 'fallo suave (~all)',
  spfp_neutral: 'neutral (?all)',
  spfp_redirect: 'delegado mediante redirect',
  spfterm_no_target: 'sin destino',
  spfterm_loop: 'bucle — ya visitado',
  spfterm_lookup_failed: 'la consulta falló',
  spfterm_no_spf_record: 'allí no hay registro SPF',

  stsmode_enforce: 'enforce — aplicar',
  stsmode_testing: 'testing — solo informes',
  stsmode_none: 'none — desactivada',
  rdns_confirmed: 'confirmado',
  rdns_unconfirmed: 'no resuelve de vuelta',
  rdns_missing: 'sin PTR',
  rdns_unknown: 'sin comprobar',
  v_of_limit: '{used} de {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} d',
  v_blocked_here: 'bloqueado desde nuestra red',
  v_no_selector_found: 'ninguno de los {n} selectores conocidos',

  note_spf: 'El RFC 7208 permite diez términos con consulta DNS en toda la evaluación, siguiendo cada include dentro de cada include. Pasados los diez, un receptor debe devolver permerror — y un permerror significa que SPF no se aplica en absoluto, exactamente como si no hubiera registro.',
  note_dmarc: 'Con p=none no se aplica nada: un mensaje que falla la alineación de SPF y de DKIM se entrega igual que antes. Es el sitio correcto para empezar y el equivocado para quedarse.',
  note_transport: 'STARTTLS es oportunista: a un remitente al que se le quita la oferta simplemente continúa en claro. MTA-STS y DANE son lo que convierte esa posibilidad en una garantía.',
  note_sessions: 'Todas las sesiones son de solo lectura. La prueba de retransmisión se detiene en RCPT TO y envía RSET; nunca se emite una orden DATA, así que no puede enviarse ningún mensaje.',
  note_rdns: 'Un registro PTR por sí solo no prueba nada — el dueño de un bloque de direcciones puede poner allí cualquier nombre. Lo que los receptores comprueban es si ese nombre resuelve de vuelta a la misma dirección.',

  err_smtp_timeout: 'El servidor de correo no respondió a tiempo.',
  err_smtp_network: 'No se pudo alcanzar el servidor de correo.',
  err_smtp_refused: 'El servidor de correo rechazó la conexión.',
  err_tls_failed: 'El saludo TLS con el servidor de correo falló.',

  inc_mx_lookup_failed: 'no se pudieron leer los registros MX',
  inc_spf_lookup_failed: 'no se pudo leer el registro SPF',
  inc_dmarc_lookup_failed: 'no se pudo leer el registro DMARC',
  inc_port_25_unreachable_from_this_network: 'el puerto 25 saliente está bloqueado donde se ejecuta este servicio, así que STARTTLS, la verificación DANE contra el certificado real y la prueba de retransmisión no pudieron hacerse',
  inc_not_every_mx_was_probed: 'solo se conectó con los servidores de mayor prioridad',

  cap_open_relay: 'el servidor retransmite correo de desconocidos',
  cap_spf_authorises_everyone: 'SPF autoriza a todo internet',
  cap_no_mail_servers: 'sin servidores de correo',
  cap_mail_servers_unreachable: 'ningún servidor de correo respondió en el puerto 25',
  cap_dane_mismatch: 'DANE no coincide con el certificado presentado',
  cap_mtasts_policy_contradicts_dns: 'la política MTA-STS omite un servidor de correo real',
  cap_spf_over_the_lookup_limit: 'SPF supera el límite de consultas',
  cap_spf_permerror: 'SPF es un error permanente',
  cap_dmarc_permerror: 'DMARC es un error permanente',
  cap_mail_in_the_clear: 'el correo se acepta sin cifrar',
  cap_no_spf: 'sin registro SPF',
  cap_no_dmarc: 'sin registro DMARC',
  cap_starttls_broken: 'STARTTLS se ofrece y no funciona',
  cap_dmarc_not_enforcing: 'DMARC no aplica nada',
  cap_no_reverse_dns: 'sin DNS inverso confirmado',
  cap_spf_without_a_default: 'SPF no tiene valor por defecto',
  cap_weak_dkim_key: 'una clave DKIM demasiado corta',
  cap_dmarc_reports_go_nowhere: 'los informes DMARC no están autorizados',
  cap_mail_server_does_not_resolve: 'un servidor de correo no resuelve',
  cap_scan_incomplete: 'la comprobación quedó incompleta, así que no se otorgó nota',

  flag_null_mx: 'El dominio declara que no gestiona correo',
  fd_null_mx: 'Un único MX con prioridad 0 apuntando a la raíz es el RFC 7505 para «este dominio ni envía ni recibe correo». Deliberado, y mucho mejor que no tener MX en absoluto — sin él, los remitentes recurren al registro de dirección.',

  flag_no_mx: 'Sin registros MX',
  fd_no_mx: 'Nada indica adónde debe ir el correo de este dominio, y tampoco hay dirección de reserva, así que sencillamente no se puede entregar.',

  flag_no_mx_falls_back_to_a: 'Sin registros MX, los remitentes recurren al registro A',
  fd_no_mx_falls_back_to_a: 'El RFC 5321 §5.1 indica al remitente sin MX que pruebe el registro de dirección. El correo de este dominio se entregará a lo que esté escuchando en el puerto 25 del servidor web — algo que casi nunca es lo que se pretendía.',

  flag_duplicate_mx_host: 'El mismo host aparece dos veces',
  fd_duplicate_mx_host: 'Un host figura con más de una prioridad. Eso no es redundancia; es la misma máquina intentada dos veces.',

  flag_mx_does_not_resolve: 'El nombre de un servidor de correo no resuelve',
  fd_mx_does_not_resolve: 'El MX nombra un host sin registros de dirección. Todo remitente que llegue a esa prioridad espera la consulta, no obtiene nada y sigue adelante — retrasando correo que debería haber llegado de inmediato.',

  flag_mx_points_at_cname: 'Un registro MX apunta a un alias',
  fd_mx_points_at_cname: 'El RFC 2181 §10.3 exige que un MX nombre un host con registros de dirección, no un CNAME. Algunos remitentes lo toleran, otros lo rechazan, y quién hace qué cambia con el tiempo.',

  flag_single_mx: 'Un solo servidor de correo',
  fd_single_mx: 'Con un único MX, cualquier caída significa que los remitentes encolan y reintentan — durante horas o días, según su propia política — y parte de ese correo acabará rebotando.',

  flag_no_ipv6_mx: 'Ningún servidor de correo es accesible por IPv6',
  fd_no_ipv6_mx: 'Los remitentes en redes solo-IPv6 llegan a este dominio a través de un traductor, si es que llegan.',

  flag_spf_missing: 'Sin registro SPF',
  fd_spf_missing: 'Nada indica qué servidores pueden enviar correo como este dominio, así que no hay nada contra lo que comprobar. SPF es un registro TXT y lo más barato de toda esta página.',

  flag_spf_multiple_records: 'Más de un registro SPF',
  fd_spf_multiple_records: 'El RFC 7208 §4.5 convierte dos registros en un error permanente, y un permerror significa ningún resultado SPF — lo contrario de lo que se pretendía al añadir el segundo. Hay que fundirlos en uno.',

  flag_spf_too_many_lookups: 'SPF necesita más de diez consultas DNS',
  fd_spf_too_many_lookups: 'El límite del RFC 7208 §4.6.4 son diez términos con consulta en toda la evaluación, siguiendo cada include dentro de cada include. Pasado ese punto, un receptor debe devolver permerror y SPF deja de aplicarse — el registro podría no existir. Es fácil superarlo añadiendo un proveedor más, y completamente invisible desde el propio registro.',

  flag_spf_lookups_near_limit: 'SPF está cerca del límite de diez consultas',
  fd_spf_lookups_near_limit: 'Queda poco margen. El próximo servicio que se añada — o un cambio dentro del include de otro, que usted no controla — lo hará superarlo.',

  flag_spf_too_many_void_lookups: 'Demasiadas consultas SPF no devuelven nada',
  fd_spf_too_many_void_lookups: 'El RFC 7208 permite dos consultas que no resuelvan a nada; más allá es un error permanente. Suele ser un include olvidado de un servicio que ya no se usa.',

  flag_spf_no_all: 'SPF no tiene valor por defecto',
  fd_spf_no_all: 'Sin un mecanismo «all» ni un redirect, un remitente que no coincida con nada obtiene un resultado neutral — que es lo mismo que no tener opinión.',

  flag_spf_plus_all: 'SPF autoriza a todo internet',
  fd_spf_plus_all: '«+all» dice que cualquier host de cualquier lugar puede enviar como este dominio. Casi siempre es un malentendido sobre el cualificador, y es peor que no tener SPF, porque avala explícitamente al falsificador.',

  flag_spf_neutral_all: 'SPF termina en ?all',
  fd_spf_neutral_all: '«?all» se niega explícitamente a decir nada sobre los remitentes que no coinciden con nada. Los receptores lo tratan como ausencia de resultado.',

  flag_spf_softfail_all: 'SPF termina en ~all en lugar de -all',
  fd_spf_softfail_all: 'El fallo suave pide a los receptores que acepten pero marquen. Es lo correcto mientras todavía se averigua quién envía en su nombre, y lo que hay que endurecer una vez que se sabe.',

  flag_spf_uses_ptr: 'SPF usa el mecanismo ptr',
  fd_spf_uses_ptr: 'El RFC 7208 §5.5 lo declara obsoleto sin rodeos: es lento, poco fiable y traslada trabajo a quien gestiona la zona inversa. Algunos receptores lo ignoran por completo.',

  flag_spf_unknown_mechanism: 'SPF contiene un término que nadie entiende',
  fd_spf_unknown_mechanism: 'Un mecanismo no reconocido es un error permanente según el RFC 7208 §4.6.1, y descarta todo el registro. Normalmente es una errata.',

  flag_spf_duplicate_redirect: 'Más de un modificador redirect',
  fd_spf_duplicate_redirect: 'Un segundo redirect convierte el registro en un error permanente.',

  flag_spf_redirect_after_all: 'Un redirect al que nunca se llega',
  fd_spf_redirect_after_all: 'El registro tiene a la vez un mecanismo «all» y un redirect. «all» siempre coincide, así que la evaluación se detiene ahí y el redirect es texto muerto.',

  flag_spf_record_long: 'El registro SPF es largo',
  fd_spf_record_long: 'Los registros largos se parten en varias cadenas al viajar. Eso está bien en sí — los receptores las unen sin nada entre medias — pero es donde los analizadores que las unen con un espacio empiezan a corromper el registro.',

  flag_spf_include_loop: 'Un include apunta a algo ya visitado',
  fd_spf_include_loop: 'El despliegue entra en bucle. Un receptor se detiene en el límite de consultas y devuelve un error permanente.',

  flag_spf_include_without_record: 'Un include apunta a un dominio sin registro SPF',
  fd_spf_include_without_record: 'El RFC 7208 §5.2 lo convierte en un error permanente, no en una simple consulta desperdiciada. Suele ser un servicio que se retiró por un lado y no por el otro.',

  flag_dkim_no_known_selector: 'No se encontró clave DKIM en ningún selector conocido',
  fd_dkim_no_known_selector: 'Los selectores los elige quien firma y solo aparecen en la cabecera de un mensaje firmado, así que no pueden enumerarse desde fuera. Esto no prueba que falte DKIM — si conoce su selector, páselo con ?selector= y la comprobación pasa a ser concluyente.',

  flag_dkim_key_revoked: 'Una clave DKIM ha sido revocada',
  fd_dkim_key_revoked: 'El registro se publica con p= vacío, lo que revoca la clave. Esa es la forma correcta de retirar una — y un registro que lleva meses así suele ser una rotación que nadie terminó.',

  flag_dkim_key_malformed: 'Una clave DKIM no se puede analizar',
  fd_dkim_key_malformed: 'El valor de p= no es material de clave válido. Toda firma hecha con ella fallará la verificación.',

  flag_dkim_in_test_mode: 'Un registro DKIM está en modo de prueba',
  fd_dkim_in_test_mode: 't=y indica a los receptores que traten una firma fallida como si DKIM no estuviera en uso. Su sitio es un despliegue en curso y ningún otro.',

  flag_dkim_key_too_short: 'Una clave DKIM tiene menos de 1024 bits',
  fd_dkim_key_too_short: 'Por debajo de 1024 bits la firma no es realmente difícil de falsificar, y muchos receptores ignoran esas claves sin más.',

  flag_dkim_key_1024_bit: 'Una clave DKIM es de 1024 bits',
  fd_dkim_key_1024_bit: 'Todavía se acepta en todas partes, y está por debajo de las recomendaciones actuales. 2048 es el tamaño normal; la rotación es un selector nuevo y un registro DNS.',

  flag_dmarc_missing: 'Sin registro DMARC',
  fd_dmarc_missing: 'Sin DMARC, los resultados de SPF y DKIM son orientativos: nada los ata a la dirección que ve el lector, y nada indica a los receptores qué hacer cuando fallan.',

  flag_dmarc_inherited: 'DMARC se hereda del dominio padre',
  fd_dmarc_inherited: 'Este nombre no tiene registro propio, así que se aplica la política del dominio organizativo — su valor sp= si lo tiene, y si no su p=.',

  flag_dmarc_multiple_records: 'Más de un registro DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: con más de un registro la política se descarta por completo, como si no se hubiera publicado ninguna.',

  flag_dmarc_no_policy: 'El registro DMARC no tiene etiqueta p=',
  fd_dmarc_no_policy: 'p= es obligatoria. Sin ella el registro se ignora.',

  flag_dmarc_invalid_policy: 'La política DMARC no es un valor reconocido',
  fd_dmarc_invalid_policy: 'p= debe ser none, quarantine o reject. Con cualquier otra cosa los receptores descartan el registro.',

  flag_dmarc_policy_none: 'DMARC no aplica nada',
  fd_dmarc_policy_none: 'p=none pide a los receptores que informen y no cambien nada. Un mensaje que falla la alineación de SPF y de DKIM se entrega exactamente igual que sin DMARC. Es la forma correcta de empezar — y muchísimos dominios llevan años ahí creyéndose protegidos.',

  flag_dmarc_policy_quarantine: 'DMARC pone en cuarentena en vez de rechazar',
  fd_dmarc_policy_quarantine: 'El correo que falla va a la carpeta de no deseado en lugar de ser rechazado. Un paso razonable camino de reject, y un lugar donde el correo falsificado sigue llegando a las personas.',

  flag_dmarc_subdomain_policy_none: 'Los subdominios quedan exentos de la política',
  fd_dmarc_subdomain_policy_none: 'sp=none deja todos los subdominios — incluidos los que nunca han existido — disponibles para la suplantación, mientras el dominio en sí está protegido.',

  flag_dmarc_partial_percentage: 'La política se aplica solo a parte del correo',
  fd_dmarc_partial_percentage: 'pct= por debajo de 100 indica a los receptores que apliquen la política a esa proporción de mensajes fallidos y traten al resto con más indulgencia. Útil durante el despliegue, y una brecha mientras siga puesto.',

  flag_dmarc_no_reporting: 'Sin dirección para informes agregados',
  fd_dmarc_no_reporting: 'Sin rua= no llegan informes, lo que significa no tener forma de saber quién envía como su dominio ni qué se rompería al endurecer la política.',

  flag_dmarc_external_reporting_unauthorised: 'La dirección externa de informes no le ha autorizado',
  fd_dmarc_external_reporting_unauthorised: 'Los informes van dirigidos a otro dominio, y ese dominio no publica el registro que acepta recibirlos (RFC 7489 §7.1). Los receptores conformes no envían nada. El registro DMARC parece perfecto y los informes nunca llegan — algo que casi siempre se achaca a que «los informes tardan».',

  flag_mtasts_missing: 'Sin política MTA-STS',
  fd_mtasts_missing: 'STARTTLS es oportunista: un remitente que no ve la oferta envía en claro, y quitar esa oferta es fácil para cualquiera que esté entre los dos servidores. MTA-STS publica por HTTPS que este dominio siempre habla TLS, con lo que ese ataque pasa a exigir romper la PKI web.',

  flag_mtasts_multiple_records: 'Más de un registro TXT de MTA-STS',
  fd_mtasts_multiple_records: 'Los remitentes no pueden saber qué id es el actual, así que la política puede no refrescarse cuando cambie.',

  flag_mtasts_no_id: 'El registro MTA-STS no tiene id',
  fd_mtasts_no_id: 'El id es lo que le dice a un remitente que su copia de la política está obsoleta. Sin él, una política cambiada puede no recogerse hasta que expire max_age.',

  flag_mtasts_policy_host_missing: 'El host de la política no resuelve',
  fd_mtasts_policy_host_missing: 'El registro TXT anuncia una política y mta-sts.<dominio> no tiene dirección, así que ningún remitente puede descargarla.',

  flag_mtasts_policy_host_private: 'El host de la política resuelve a espacio de direcciones privado',
  fd_mtasts_policy_host_private: 'La política no se descargó: el host apunta a una dirección a la que este servicio no se conecta.',

  flag_mtasts_policy_unreachable: 'No se pudo descargar la política MTA-STS',
  fd_mtasts_policy_unreachable: 'El registro TXT promete una política que no está ahí, o cuyo certificado no valida. Como todo el mecanismo descansa en ese certificado HTTPS, un fallo aquí significa que los remitentes vuelven al TLS oportunista.',

  flag_mtasts_policy_wrong_content_type: 'La política no se sirve como text/plain',
  fd_mtasts_policy_wrong_content_type: 'El RFC 8461 exige text/plain. Los remitentes estrictos la rechazarán.',

  flag_mtasts_policy_bad_version: 'La versión de la política no es STSv1',
  fd_mtasts_policy_bad_version: 'Los remitentes no usarán una política cuya versión no reconocen.',

  flag_mtasts_policy_bad_mode: 'El modo de la política no es un valor reconocido',
  fd_mtasts_policy_bad_mode: 'mode debe ser enforce, testing o none.',

  flag_mtasts_mode_testing: 'MTA-STS está en modo de prueba',
  fd_mtasts_mode_testing: 'Los fallos se informan y el correo se entrega igualmente, así que la política todavía no protege nada. Una etapa de paso, no un destino.',

  flag_mtasts_mode_none: 'MTA-STS está desactivado por su propia política',
  fd_mtasts_mode_none: 'mode=none retira la política. Existe para que un dominio pueda abandonar MTA-STS con orden; dejado ahí significa simplemente que el registro no hace nada.',

  flag_mtasts_no_max_age: 'La política no tiene max_age',
  fd_mtasts_no_max_age: 'max_age es obligatorio, y es lo que hace que la política resista ser suprimida: un remitente que la haya guardado seguirá aplicándola.',

  flag_mtasts_max_age_short: 'La política se guarda menos de un día',
  fd_mtasts_max_age_short: 'Un max_age corto estrecha la ventana en la que una política guardada protege a un remitente. Unas semanas es lo habitual una vez que la política es estable.',

  flag_mtasts_mx_not_in_policy: 'Falta un servidor de correo real en la política',
  fd_mtasts_mx_not_in_policy: 'El conjunto MX contiene un host con el que no coincide ningún patrón mx: de la política. Todo remitente que aplique esta política se negará a entregar en ese host — así que el correo falla justo con los remitentes que están siendo cuidadosos.',

  flag_mtasts_policy_lists_unknown_mx: 'La política lista patrones que no coinciden con ningún MX actual',
  fd_mtasts_policy_lists_unknown_mx: 'Inofensivo, y normalmente un resto de una migración. Merece la pena limpiarlo para que la política siga describiendo la realidad.',

  flag_mtasts_policy_no_mx: 'La política no lista ningún servidor de correo',
  fd_mtasts_policy_no_mx: 'Una política sin entradas mx: no coincide con nada, así que los remitentes que la apliquen no tienen dónde entregar.',

  flag_tlsrpt_missing: 'Sin registro TLS-RPT',
  fd_tlsrpt_missing: 'Un registro TXT, y la única forma de enterarse de que los remitentes no consiguen negociar TLS con sus servidores. Sin él, un certificado caducado o un STARTTLS roto son invisibles desde su lado.',

  flag_tlsrpt_no_rua: 'El registro TLS-RPT no tiene destino',
  fd_tlsrpt_no_rua: 'Sin rua= los informes no tienen adónde ir, así que el registro no hace nada.',

  flag_dane_missing: 'Sin registros DANE',
  fd_dane_missing: 'Los registros TLSA fijan el certificado que debe presentar un servidor de correo, apoyándose en DNSSEC y no en las autoridades públicas. Es el más fuerte de los dos mecanismos de transporte — y necesita la zona firmada, que suele ser la razón de que no se use.',

  flag_dane_partial: 'Solo algunos servidores de correo tienen registros DANE',
  fd_dane_partial: 'Los remitentes eligen servidor por prioridad, así que un conjunto donde solo algunos hosts están fijados está protegido solo parte del tiempo.',

  flag_dane_without_dnssec: 'Un registro TLSA en una zona sin firmar',
  fd_dane_without_dnssec: 'DANE descansa por completo en DNSSEC. Sin firmas, quien pueda sustituir el registro MX puede sustituir también el TLSA, así que la fijación no protege nada aunque lo aparente.',

  flag_dane_mismatch: 'El registro TLSA no coincide con el certificado presentado',
  fd_dane_mismatch: 'El servidor presenta un certificado que su propio registro DANE no autoriza. Todo remitente que valide DANE se negará a entregar — esto detiene el correo.',

  flag_dane_pkix_usage: 'Un registro TLSA usa un modo PKIX',
  fd_dane_pkix_usage: 'Los usos 0 y 1 exigen además que el certificado valide a través de las autoridades públicas. El RFC 7672 §3.1 prohíbe ambos para SMTP, porque no hay forma acordada de hacer esa comprobación para el correo.',

  flag_dane_full_certificate: 'Un registro TLSA fija el certificado entero',
  fd_dane_full_certificate: 'El tipo de coincidencia 0 guarda el certificado completo en lugar de un resumen. Funciona, hace el registro grande y obliga a reemplazarlo en cada renovación.',

  flag_port_25_blocked_from_here: 'El puerto 25 saliente está bloqueado donde se ejecuta este servicio',
  fd_port_25_blocked_from_here: 'Esto es sobre nuestra red, no sobre la suya. La mayoría de los proveedores bloquean por defecto las conexiones salientes al puerto 25. Por eso no pudieron hacerse STARTTLS, la verificación DANE contra un certificado real ni la prueba de retransmisión, y la nota se retiene en vez de calcularse con lo que resultó alcanzable.',

  flag_mx_not_reachable_on_25: 'Ningún servidor de correo respondió en el puerto 25',
  fd_mx_not_reachable_on_25: 'Los registros MX nombran hosts que no aceptan conexiones en el puerto por el que se entrega el correo. A este dominio no se le puede entregar nada.',

  flag_no_starttls: 'Un servidor de correo no ofrece STARTTLS',
  fd_no_starttls: 'Cada mensaje entregado a este servidor cruza internet sin cifrar, legible por cualquier cosa que esté en el camino. Ofrecer STARTTLS cuesta un certificado y una línea de configuración.',

  flag_starttls_fails: 'STARTTLS se ofrece y no funciona',
  fd_starttls_fails: 'El servidor anuncia STARTTLS y el saludo falla. Los remitentes cuidadosos pueden negarse a caer a texto plano y aplazar el correo — así que esto es peor que no ofrecerlo.',

  flag_starttls_legacy_protocol: 'El servidor de correo negocia una versión obsoleta de TLS',
  fd_starttls_legacy_protocol: 'TLS 1.0 y 1.1 están obsoletos desde el RFC 8996. Los remitentes van retirando su soporte, y cuando lo hagan el correo dejará de llegar.',

  flag_mx_certificate_not_trusted: 'El certificado del servidor de correo no valida',
  fd_mx_certificate_not_trusted: 'El TLS oportunista corriente no verifica certificados, así que hoy esto no impide la entrega. La impide por completo en cuanto entra en juego MTA-STS en modo enforce o DANE.',

  flag_banner_reveals_version: 'El saludo nombra el programa y su versión',
  fd_banner_reveals_version: 'Un pequeño regalo para quien busque hosts con un fallo conocido en esa versión exacta. En el saludo puede escribirse cualquier cosa.',

  flag_open_relay: 'El servidor retransmite correo de desconocidos',
  fd_open_relay: 'Aceptó un mensaje de un remitente ajeno para un destinatario ajeno. Cualquiera puede usarlo para enviar spam en su nombre, y estará en listas negras en cuestión de horas si no lo está ya. Esto se arregla hoy. (La prueba se detuvo en RCPT TO y envió RSET: no se envió ningún mensaje.)',

  flag_no_size_extension: 'El servidor no anuncia SIZE',
  fd_no_size_extension: 'Sin SIZE un remitente no puede saber si se aceptará un mensaje grande hasta haberlo transferido entero.',

  flag_submission_without_starttls: 'El puerto de envío no ofrece STARTTLS',
  fd_submission_without_starttls: 'El puerto 587 es donde los clientes de correo se autentican. Sin STARTTLS esas credenciales cruzan la red en claro.',

  flag_rdns_missing: 'Una dirección de servidor de correo no tiene registro PTR',
  fd_rdns_missing: 'La falta de DNS inverso es una de las razones más habituales de que el correo de un servidor nuevo se aplace o acabe en no deseado — y de las que menos explica el lado receptor.',

  flag_rdns_not_confirmed: 'El DNS inverso no resuelve de vuelta',
  fd_rdns_not_confirmed: 'El registro PTR da un nombre, y ese nombre no resuelve a esta dirección. Los receptores comprueban el viaje de ida y vuelta precisamente porque exige que dos partes distintas hayan hecho lo suyo.',

  flag_rdns_none_confirmed: 'Ningún servidor de correo tiene DNS inverso confirmado hacia delante',
  fd_rdns_none_confirmed: 'Ni una sola dirección pasa la comprobación de ida y vuelta. Espere retrasos de entrega y clasificación como no deseado por parte de los receptores que lo tienen en cuenta.',
};

OWN.pt = {
  title: 'Verificação de e-mail — SPF, DKIM, DMARC, MTA-STS e DANE de qualquer domínio',
  title_short: 'Verificação de e-mail',
  h1: 'Verificação de e-mail',
  subtitle: 'SPF expandido através de cada include e contado contra o limite de dez, alinhamento e relatórios DMARC, e a segurança do transporte verificada na conexão real',
  ph_host: 'example.com',
  hero_label: 'Domínio verificado',
  empty_hint: 'Digite um nome de domínio. A verificação expande o registro SPF através de cada include, tenta os seletores DKIM que as grandes plataformas usam, lê a política DMARC, busca a política MTA-STS por HTTPS e abre sessões SMTP somente de leitura com os servidores de e-mail. Nenhuma mensagem é enviada.',

  stage_resolve: 'procurando os servidores de e-mail',
  stage_mx: 'verificando o conjunto MX',
  stage_spf: 'expandindo o SPF',
  stage_dkim: 'procurando chaves DKIM',
  stage_dmarc: 'lendo a política DMARC',
  stage_mtasts: 'buscando a política MTA-STS',
  stage_dane: 'verificando DANE',
  stage_starttls: 'conversando com os servidores de e-mail',
  stage_grade: 'atribuindo a nota',

  card_grade: 'Composição da nota',
  card_mx: 'Servidores de e-mail',
  card_spf: 'SPF',
  card_spf_tree: 'Expansão do SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Segurança do transporte',
  card_sessions: 'Sessões SMTP',
  card_rdns: 'DNS reverso',

  comp_authentication: 'Autenticação',
  comp_transport: 'Transporte',
  comp_hygiene: 'Higiene',

  k_mx_count: 'Registros MX',
  k_null_mx: 'MX nulo',
  k_ipv6_mx: 'Acessíveis por IPv6',
  k_spf_record: 'Registro',
  k_spf_lookups: 'Consultas DNS usadas',
  k_spf_voids: 'Consultas vazias',
  k_spf_policy: 'Padrão para os demais',
  k_dkim_keys: 'Chaves encontradas',
  k_dkim_tried: 'Seletores testados',
  k_dkim_strongest: 'Chave mais forte',
  k_dmarc_policy: 'Política',
  k_dmarc_subdomain: 'Política para subdomínios',
  k_dmarc_percent: 'Aplicada a',
  k_dmarc_alignment: 'Alinhamento (DKIM / SPF)',
  k_dmarc_rua: 'Relatórios agregados para',
  k_dmarc_ruf: 'Relatórios forenses para',
  k_dmarc_external: 'Relatórios externos autorizados',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Modo',
  k_mtasts_id: 'Id da política',
  k_mtasts_maxage: 'Guardada por',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Servidores cobertos',
  k_starttls: 'STARTTLS',
  k_port25: 'Porta 25 de saída',
  k_open_relay: 'Retransmissão aberta',
  k_rdns_confirmed: 'Confirmado no caminho de volta',
  k_queries: 'Consultas feitas',

  th_priority: 'Prioridade',
  th_host: 'Host',
  th_addresses: 'Endereços',
  th_port: 'Porta',
  th_tls: 'TLS',
  th_banner: 'Saudação',
  th_extensions: 'Anunciado',
  th_selector: 'Seletor',
  th_key_type: 'Chave',
  th_bits: 'Bits',
  th_state: 'Estado',
  th_address: 'Endereço',
  th_ptr: 'PTR',
  th_confirmed: 'Confirmado',
  th_term: 'Termo',
  th_lookup: 'Consulta',

  pol_none: 'none — apenas observação',
  pol_quarantine: 'quarantine — para o lixo eletrônico',
  pol_reject: 'reject — rejeitar',
  spfp_pass: 'aceitar todos (+all)',
  spfp_fail: 'rejeitar (-all)',
  spfp_softfail: 'falha branda (~all)',
  spfp_neutral: 'neutro (?all)',
  spfp_redirect: 'delegado por redirect',
  spfterm_no_target: 'sem destino',
  spfterm_loop: 'laço — já visitado',
  spfterm_lookup_failed: 'a consulta falhou',
  spfterm_no_spf_record: 'não há registro SPF ali',

  stsmode_enforce: 'enforce — aplicar',
  stsmode_testing: 'testing — só relatórios',
  stsmode_none: 'none — desativada',
  rdns_confirmed: 'confirmado',
  rdns_unconfirmed: 'não resolve de volta',
  rdns_missing: 'sem PTR',
  rdns_unknown: 'não verificado',
  v_of_limit: '{used} de {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} d',
  v_blocked_here: 'bloqueada a partir da nossa rede',
  v_no_selector_found: 'nenhum dos {n} seletores conhecidos',

  note_spf: 'O RFC 7208 permite dez termos com consulta DNS em toda a avaliação, seguindo cada include dentro de cada include. Passando de dez, um receptor precisa devolver permerror — e um permerror significa que o SPF não se aplica de forma alguma, exatamente como se não houvesse registro.',
  note_dmarc: 'Com p=none nada é aplicado: uma mensagem que falha o alinhamento tanto de SPF quanto de DKIM é entregue como antes. É o lugar certo para começar e o errado para ficar.',
  note_transport: 'O STARTTLS é oportunista: um remetente de quem se retira a oferta simplesmente segue em texto aberto. MTA-STS e DANE são o que transforma essa possibilidade em garantia.',
  note_sessions: 'Todas as sessões são somente de leitura. A sondagem de retransmissão para em RCPT TO e envia RSET; nenhum comando DATA é emitido, então nenhuma mensagem pode ser enviada.',
  note_rdns: 'Um registro PTR sozinho não prova nada — o dono de um bloco de endereços pode colocar ali qualquer nome. O que os receptores verificam é se esse nome resolve de volta para o mesmo endereço.',

  err_smtp_timeout: 'O servidor de e-mail não respondeu a tempo.',
  err_smtp_network: 'Não foi possível alcançar o servidor de e-mail.',
  err_smtp_refused: 'O servidor de e-mail recusou a conexão.',
  err_tls_failed: 'O handshake TLS com o servidor de e-mail falhou.',

  inc_mx_lookup_failed: 'não foi possível ler os registros MX',
  inc_spf_lookup_failed: 'não foi possível ler o registro SPF',
  inc_dmarc_lookup_failed: 'não foi possível ler o registro DMARC',
  inc_port_25_unreachable_from_this_network: 'a porta 25 de saída está bloqueada onde este serviço roda, então STARTTLS, a conferência do DANE contra o certificado real e a sondagem de retransmissão não puderam ser feitas',
  inc_not_every_mx_was_probed: 'só houve conexão com os servidores de maior prioridade',

  cap_open_relay: 'o servidor retransmite e-mail de estranhos',
  cap_spf_authorises_everyone: 'o SPF autoriza a internet inteira',
  cap_no_mail_servers: 'sem servidores de e-mail',
  cap_mail_servers_unreachable: 'nenhum servidor de e-mail respondeu na porta 25',
  cap_dane_mismatch: 'o DANE não bate com o certificado apresentado',
  cap_mtasts_policy_contradicts_dns: 'a política MTA-STS omite um servidor de e-mail real',
  cap_spf_over_the_lookup_limit: 'o SPF passou do limite de consultas',
  cap_spf_permerror: 'o SPF é um erro permanente',
  cap_dmarc_permerror: 'o DMARC é um erro permanente',
  cap_mail_in_the_clear: 'o e-mail é aceito sem criptografia',
  cap_no_spf: 'sem registro SPF',
  cap_no_dmarc: 'sem registro DMARC',
  cap_starttls_broken: 'o STARTTLS é oferecido e não funciona',
  cap_dmarc_not_enforcing: 'o DMARC não aplica nada',
  cap_no_reverse_dns: 'sem DNS reverso confirmado',
  cap_spf_without_a_default: 'o SPF não tem padrão',
  cap_weak_dkim_key: 'uma chave DKIM curta demais',
  cap_dmarc_reports_go_nowhere: 'os relatórios DMARC não estão autorizados',
  cap_mail_server_does_not_resolve: 'um servidor de e-mail não resolve',
  cap_scan_incomplete: 'a verificação ficou incompleta, então nenhuma nota foi dada',

  flag_null_mx: 'O domínio declara que não lida com e-mail',
  fd_null_mx: 'Um único MX com prioridade 0 apontando para a raiz é o RFC 7505 para «este domínio não envia nem recebe e-mail». Deliberado, e bem melhor do que não ter MX nenhum — sem ele, os remetentes recorrem ao registro de endereço.',

  flag_no_mx: 'Sem registros MX',
  fd_no_mx: 'Nada diz para onde o e-mail deste domínio deve ir, e também não há endereço de reserva, então simplesmente não há como entregar.',

  flag_no_mx_falls_back_to_a: 'Sem registros MX, os remetentes recorrem ao registro A',
  fd_no_mx_falls_back_to_a: 'O RFC 5321 §5.1 manda o remetente sem MX tentar o registro de endereço. O e-mail deste domínio será entregue ao que estiver escutando na porta 25 do servidor web — o que raramente é o pretendido.',

  flag_duplicate_mx_host: 'O mesmo host aparece duas vezes',
  fd_duplicate_mx_host: 'Um host aparece em mais de uma prioridade. Isso não é redundância; é a mesma máquina sendo tentada duas vezes.',

  flag_mx_does_not_resolve: 'O nome de um servidor de e-mail não resolve',
  fd_mx_does_not_resolve: 'O MX nomeia um host sem registros de endereço. Todo remetente que chegar a essa prioridade espera a consulta, não recebe nada e segue adiante — atrasando e-mail que deveria ter chegado de imediato.',

  flag_mx_points_at_cname: 'Um registro MX aponta para um alias',
  fd_mx_points_at_cname: 'O RFC 2181 §10.3 exige que um MX nomeie um host com registros de endereço, não um CNAME. Alguns remetentes toleram, outros recusam, e quem faz o quê muda com o tempo.',

  flag_single_mx: 'Apenas um servidor de e-mail',
  fd_single_mx: 'Com um único MX, qualquer indisponibilidade faz os remetentes enfileirarem e tentarem de novo — por horas ou dias, conforme a política de cada um — e parte desse e-mail acabará voltando.',

  flag_no_ipv6_mx: 'Nenhum servidor de e-mail é acessível por IPv6',
  fd_no_ipv6_mx: 'Remetentes em redes somente-IPv6 chegam a este domínio por um tradutor, se é que chegam.',

  flag_spf_missing: 'Sem registro SPF',
  fd_spf_missing: 'Nada diz quais servidores podem enviar e-mail como este domínio, então não há contra o que conferir. SPF é um registro TXT e a coisa mais barata desta página inteira.',

  flag_spf_multiple_records: 'Mais de um registro SPF',
  fd_spf_multiple_records: 'O RFC 7208 §4.5 torna dois registros um erro permanente, e um permerror significa nenhum resultado de SPF — o oposto do que se pretendia ao acrescentar o segundo. É preciso fundi-los em um só.',

  flag_spf_too_many_lookups: 'O SPF precisa de mais de dez consultas DNS',
  fd_spf_too_many_lookups: 'O limite do RFC 7208 §4.6.4 é de dez termos com consulta em toda a avaliação, seguindo cada include dentro de cada include. Passando disso, um receptor precisa devolver permerror e o SPF deixa de valer — o registro poderia não existir. É fácil ultrapassar acrescentando mais um provedor, e completamente invisível no próprio registro.',

  flag_spf_lookups_near_limit: 'O SPF está perto do limite de dez consultas',
  fd_spf_lookups_near_limit: 'Sobrou pouca folga. O próximo serviço acrescentado — ou uma mudança dentro do include de outra pessoa, que você não controla — vai ultrapassar.',

  flag_spf_too_many_void_lookups: 'Consultas SPF demais não devolvem nada',
  fd_spf_too_many_void_lookups: 'O RFC 7208 permite duas consultas que não resolvem para nada; além disso é erro permanente. Normalmente é um include esquecido de um serviço que não se usa mais.',

  flag_spf_no_all: 'O SPF não tem padrão',
  fd_spf_no_all: 'Sem um mecanismo «all» nem um redirect, um remetente que não casa com nada recebe resultado neutro — o mesmo que não ter opinião alguma.',

  flag_spf_plus_all: 'O SPF autoriza a internet inteira',
  fd_spf_plus_all: '«+all» diz que qualquer host em qualquer lugar pode enviar como este domínio. Quase sempre é um mal-entendido sobre o qualificador, e é pior do que não ter SPF, porque endossa explicitamente o falsificador.',

  flag_spf_neutral_all: 'O SPF termina em ?all',
  fd_spf_neutral_all: '«?all» recusa-se explicitamente a dizer qualquer coisa sobre remetentes que não casam com nada. Os receptores tratam isso como ausência de resultado.',

  flag_spf_softfail_all: 'O SPF termina em ~all em vez de -all',
  fd_spf_softfail_all: 'A falha branda pede aos receptores que aceitem mas marquem. É o ajuste certo enquanto você ainda descobre quem envia em seu nome, e o que apertar depois que já sabe.',

  flag_spf_uses_ptr: 'O SPF usa o mecanismo ptr',
  fd_spf_uses_ptr: 'O RFC 7208 §5.5 o declara obsoleto sem meias palavras: é lento, pouco confiável e empurra trabalho para quem cuida da zona reversa. Alguns receptores o ignoram por completo.',

  flag_spf_unknown_mechanism: 'O SPF contém um termo que ninguém entende',
  fd_spf_unknown_mechanism: 'Um mecanismo não reconhecido é erro permanente pelo RFC 7208 §4.6.1, e descarta o registro inteiro. Normalmente é um erro de digitação.',

  flag_spf_duplicate_redirect: 'Mais de um modificador redirect',
  fd_spf_duplicate_redirect: 'Um segundo redirect torna o registro um erro permanente.',

  flag_spf_redirect_after_all: 'Um redirect que nunca será alcançado',
  fd_spf_redirect_after_all: 'O registro tem tanto um mecanismo «all» quanto um redirect. «all» sempre casa, então a avaliação para ali e o redirect é texto morto.',

  flag_spf_record_long: 'O registro SPF é longo',
  fd_spf_record_long: 'Registros longos são partidos em várias cadeias no transporte. Isso em si tudo bem — os receptores as juntam sem nada no meio — mas é onde analisadores que as unem com espaço começam a corromper o registro.',

  flag_spf_include_loop: 'Um include aponta de volta para algo já visitado',
  fd_spf_include_loop: 'A expansão entra em laço. Um receptor para no limite de consultas e devolve erro permanente.',

  flag_spf_include_without_record: 'Um include aponta para um domínio sem registro SPF',
  fd_spf_include_without_record: 'O RFC 7208 §5.2 torna isso um erro permanente, não apenas uma consulta desperdiçada. Normalmente é um serviço removido de um lado e não do outro.',

  flag_dkim_no_known_selector: 'Nenhuma chave DKIM em nenhum seletor que conhecemos',
  fd_dkim_no_known_selector: 'Os seletores são escolhidos por quem assina e só aparecem no cabeçalho de uma mensagem assinada, então não podem ser enumerados de fora. Isso não prova que falte DKIM — se você sabe o seu seletor, passe-o com ?selector= e a verificação passa a ser conclusiva.',

  flag_dkim_key_revoked: 'Uma chave DKIM foi revogada',
  fd_dkim_key_revoked: 'O registro é publicado com p= vazio, o que revoga a chave. Essa é a forma correta de aposentar uma — e um registro deixado assim por meses costuma ser uma troca que ninguém terminou.',

  flag_dkim_key_malformed: 'Uma chave DKIM não pode ser lida',
  fd_dkim_key_malformed: 'O valor de p= não é material de chave válido. Toda assinatura feita com ela falhará na verificação.',

  flag_dkim_in_test_mode: 'Um registro DKIM está em modo de teste',
  fd_dkim_in_test_mode: 't=y diz aos receptores para tratarem uma assinatura falha como se DKIM não estivesse em uso. O lugar disso é uma implantação em curso e nenhum outro.',

  flag_dkim_key_too_short: 'Uma chave DKIM tem menos de 1024 bits',
  fd_dkim_key_too_short: 'Abaixo de 1024 bits a assinatura não é realmente difícil de forjar, e muitos receptores ignoram essas chaves de saída.',

  flag_dkim_key_1024_bit: 'Uma chave DKIM tem 1024 bits',
  fd_dkim_key_1024_bit: 'Ainda aceita em todo lugar, e abaixo das recomendações atuais. 2048 é o tamanho normal; a troca é um seletor novo e um registro DNS.',

  flag_dmarc_missing: 'Sem registro DMARC',
  fd_dmarc_missing: 'Sem DMARC, os resultados de SPF e DKIM são consultivos: nada os liga ao endereço que o leitor de fato vê, e nada diz aos receptores o que fazer quando falham.',

  flag_dmarc_inherited: 'O DMARC é herdado do domínio pai',
  fd_dmarc_inherited: 'Este nome não tem registro próprio, então vale a política do domínio organizacional — o valor sp= dele, se houver, e senão o p=.',

  flag_dmarc_multiple_records: 'Mais de um registro DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: com mais de um registro a política é descartada por inteiro, como se nenhuma tivesse sido publicada.',

  flag_dmarc_no_policy: 'O registro DMARC não tem a tag p=',
  fd_dmarc_no_policy: 'p= é obrigatória. Sem ela o registro é ignorado.',

  flag_dmarc_invalid_policy: 'A política DMARC não é um valor reconhecido',
  fd_dmarc_invalid_policy: 'p= precisa ser none, quarantine ou reject. Com qualquer outra coisa os receptores descartam o registro.',

  flag_dmarc_policy_none: 'O DMARC não aplica nada',
  fd_dmarc_policy_none: 'p=none pede aos receptores que relatem e não mudem nada. Uma mensagem que falha o alinhamento de SPF e de DKIM é entregue exatamente como seria sem DMARC. É o jeito certo de começar — e um bocado de domínios está aqui há anos acreditando estar protegido.',

  flag_dmarc_policy_quarantine: 'O DMARC coloca em quarentena em vez de rejeitar',
  fd_dmarc_policy_quarantine: 'O e-mail que falha vai para o lixo eletrônico em vez de ser recusado. Um passo razoável rumo ao reject, e um lugar onde e-mail forjado ainda chega às pessoas.',

  flag_dmarc_subdomain_policy_none: 'Os subdomínios ficam de fora da política',
  fd_dmarc_subdomain_policy_none: 'sp=none deixa todo subdomínio — inclusive os que nunca existiram — disponível para falsificação, enquanto o domínio em si está protegido.',

  flag_dmarc_partial_percentage: 'A política se aplica a só uma parte do e-mail',
  fd_dmarc_partial_percentage: 'pct= abaixo de 100 diz aos receptores para aplicar a política àquela fatia das mensagens que falham e tratar o resto com mais leniência. Útil durante a implantação, e uma brecha enquanto estiver ali.',

  flag_dmarc_no_reporting: 'Sem endereço para relatórios agregados',
  fd_dmarc_no_reporting: 'Sem rua= não chegam relatórios, o que significa não ter como descobrir quem envia como o seu domínio nem o que quebraria ao apertar a política.',

  flag_dmarc_external_reporting_unauthorised: 'O endereço externo de relatórios não autorizou você',
  fd_dmarc_external_reporting_unauthorised: 'Os relatórios apontam para outro domínio, e esse domínio não publica o registro que concorda em recebê-los (RFC 7489 §7.1). Receptores em conformidade não enviam nada. O registro DMARC parece perfeito e os relatórios nunca chegam — o que quase sempre é atribuído a «relatórios demoram».',

  flag_mtasts_missing: 'Sem política MTA-STS',
  fd_mtasts_missing: 'O STARTTLS é oportunista: um remetente que não vê a oferta envia em texto aberto, e retirar essa oferta é fácil para quem estiver entre os dois servidores. O MTA-STS publica por HTTPS que este domínio sempre fala TLS, o que faz esse ataque exigir quebrar a PKI da web.',

  flag_mtasts_multiple_records: 'Mais de um registro TXT de MTA-STS',
  fd_mtasts_multiple_records: 'Os remetentes não conseguem dizer qual id é o atual, então a política pode não ser atualizada quando mudar.',

  flag_mtasts_no_id: 'O registro MTA-STS não tem id',
  fd_mtasts_no_id: 'O id é como um remetente sabe que sua cópia da política está velha. Sem ele, uma política alterada pode não ser recolhida até que max_age expire.',

  flag_mtasts_policy_host_missing: 'O host da política não resolve',
  fd_mtasts_policy_host_missing: 'O registro TXT anuncia uma política, e mta-sts.<domínio> não tem endereço, então nenhum remetente consegue buscá-la.',

  flag_mtasts_policy_host_private: 'O host da política resolve para espaço de endereços privado',
  fd_mtasts_policy_host_private: 'A política não foi buscada: o host aponta para um endereço ao qual este serviço não se conecta.',

  flag_mtasts_policy_unreachable: 'Não foi possível buscar a política MTA-STS',
  fd_mtasts_policy_unreachable: 'O registro TXT promete uma política que não está lá, ou cujo certificado não valida. Como o mecanismo inteiro repousa nesse certificado HTTPS, uma falha aqui significa que os remetentes voltam ao TLS oportunista.',

  flag_mtasts_policy_wrong_content_type: 'A política não é servida como text/plain',
  fd_mtasts_policy_wrong_content_type: 'O RFC 8461 exige text/plain. Remetentes estritos vão recusá-la.',

  flag_mtasts_policy_bad_version: 'A versão da política não é STSv1',
  fd_mtasts_policy_bad_version: 'Os remetentes não usarão uma política cuja versão não reconhecem.',

  flag_mtasts_policy_bad_mode: 'O modo da política não é um valor reconhecido',
  fd_mtasts_policy_bad_mode: 'mode precisa ser enforce, testing ou none.',

  flag_mtasts_mode_testing: 'O MTA-STS está em modo de teste',
  fd_mtasts_mode_testing: 'As falhas são relatadas e o e-mail é entregue mesmo assim, então a política ainda não protege nada. Um ponto de parada, não um destino.',

  flag_mtasts_mode_none: 'O MTA-STS está desligado pela própria política',
  fd_mtasts_mode_none: 'mode=none retira a política. Existe para que um domínio possa abandonar o MTA-STS com ordem; deixado ali, significa apenas que o registro não faz nada.',

  flag_mtasts_no_max_age: 'A política não tem max_age',
  fd_mtasts_no_max_age: 'max_age é obrigatório, e é o que torna a política resistente a ser suprimida — um remetente que já a guardou continuará a aplicá-la.',

  flag_mtasts_max_age_short: 'A política é guardada por menos de um dia',
  fd_mtasts_max_age_short: 'Um max_age curto estreita a janela em que uma política guardada protege um remetente. Algumas semanas é o usual depois que a política se estabiliza.',

  flag_mtasts_mx_not_in_policy: 'Falta um servidor de e-mail real na política',
  fd_mtasts_mx_not_in_policy: 'O conjunto MX contém um host com o qual nenhum padrão mx: da política casa. Todo remetente que aplicar essa política se recusará a entregar naquele host — ou seja, o e-mail falha justo com os remetentes que estão sendo cuidadosos.',

  flag_mtasts_policy_lists_unknown_mx: 'A política lista padrões que não casam com nenhum MX atual',
  fd_mtasts_policy_lists_unknown_mx: 'Inofensivo, e normalmente sobra de uma migração. Vale arrumar para que a política continue descrevendo a realidade.',

  flag_mtasts_policy_no_mx: 'A política não lista nenhum servidor de e-mail',
  fd_mtasts_policy_no_mx: 'Uma política sem entradas mx: não casa com nada, então remetentes que a aplicam não têm onde entregar.',

  flag_tlsrpt_missing: 'Sem registro TLS-RPT',
  fd_tlsrpt_missing: 'Um registro TXT, e a única forma de saber que remetentes estão falhando em negociar TLS com os seus servidores. Sem ele, um certificado vencido ou um STARTTLS quebrado são invisíveis do seu lado.',

  flag_tlsrpt_no_rua: 'O registro TLS-RPT não tem destino',
  fd_tlsrpt_no_rua: 'Sem rua= os relatórios não têm para onde ir, então o registro não faz nada.',

  flag_dane_missing: 'Sem registros DANE',
  fd_dane_missing: 'Registros TLSA fixam o certificado que um servidor de e-mail precisa apresentar, apoiando-se em DNSSEC e não nas autoridades públicas. É o mais forte dos dois mecanismos de transporte — e precisa da zona assinada, que costuma ser a razão de não estar em uso.',

  flag_dane_partial: 'Só alguns servidores de e-mail têm registros DANE',
  fd_dane_partial: 'Os remetentes escolhem servidor por prioridade, então um conjunto em que só alguns hosts estão fixados fica protegido só parte do tempo.',

  flag_dane_without_dnssec: 'Um registro TLSA numa zona sem assinatura',
  fd_dane_without_dnssec: 'O DANE repousa inteiramente no DNSSEC. Sem assinaturas, quem puder trocar o registro MX pode trocar o TLSA também, então a fixação não protege nada, embora pareça proteger.',

  flag_dane_mismatch: 'O registro TLSA não bate com o certificado apresentado',
  fd_dane_mismatch: 'O servidor apresenta um certificado que o próprio registro DANE dele não autoriza. Todo remetente que valida DANE se recusará a entregar — isso para o e-mail.',

  flag_dane_pkix_usage: 'Um registro TLSA usa um modo PKIX',
  fd_dane_pkix_usage: 'Os usos 0 e 1 exigem que o certificado valide também pela PKI pública. O RFC 7672 §3.1 proíbe ambos para SMTP, porque não há forma acordada de fazer essa conferência para e-mail.',

  flag_dane_full_certificate: 'Um registro TLSA fixa o certificado inteiro',
  fd_dane_full_certificate: 'O tipo de correspondência 0 guarda o certificado inteiro em vez de um resumo. Funciona, deixa o registro grande e obriga a substituí-lo a cada renovação.',

  flag_port_25_blocked_from_here: 'A porta 25 de saída está bloqueada onde este serviço roda',
  fd_port_25_blocked_from_here: 'Isto é sobre a nossa rede, não a sua. A maioria dos provedores bloqueia por padrão as conexões de saída para a porta 25. Por isso STARTTLS, a conferência do DANE contra um certificado real e a sondagem de retransmissão não puderam ser feitas, e a nota é retida em vez de calculada com o que por acaso deu para alcançar.',

  flag_mx_not_reachable_on_25: 'Nenhum servidor de e-mail respondeu na porta 25',
  fd_mx_not_reachable_on_25: 'Os registros MX nomeiam hosts que não aceitam conexões na porta por onde o e-mail é entregue. Não há como entregar nada a este domínio.',

  flag_no_starttls: 'Um servidor de e-mail não oferece STARTTLS',
  fd_no_starttls: 'Toda mensagem entregue a este servidor atravessa a internet sem criptografia, legível por qualquer coisa no caminho. Oferecer STARTTLS custa um certificado e uma linha de configuração.',

  flag_starttls_fails: 'O STARTTLS é oferecido e não funciona',
  fd_starttls_fails: 'O servidor anuncia STARTTLS e o handshake falha. Remetentes cuidadosos podem se recusar a cair para texto aberto e adiar o e-mail — então isso é pior do que não oferecer.',

  flag_starttls_legacy_protocol: 'O servidor de e-mail negocia uma versão obsoleta de TLS',
  fd_starttls_legacy_protocol: 'TLS 1.0 e 1.1 estão obsoletos desde o RFC 8996. Os remetentes vêm retirando o suporte, e quando retirarem o e-mail para de chegar.',

  flag_mx_certificate_not_trusted: 'O certificado do servidor de e-mail não valida',
  fd_mx_certificate_not_trusted: 'O TLS oportunista comum não verifica certificados, então hoje isso não impede a entrega. Passa a impedir por completo assim que MTA-STS em modo enforce ou DANE entrar em jogo.',

  flag_banner_reveals_version: 'A saudação nomeia o software e a versão',
  fd_banner_reveals_version: 'Um pequeno presente para quem procura hosts com uma falha conhecida naquela versão exata. A saudação pode dizer qualquer coisa.',

  flag_open_relay: 'O servidor retransmite e-mail de estranhos',
  fd_open_relay: 'Ele aceitou uma mensagem de um remetente alheio para um destinatário alheio. Qualquer um pode usá-lo para mandar spam em seu nome, e ele estará em listas de bloqueio em poucas horas, se já não estiver. Isso se conserta hoje. (A sondagem parou em RCPT TO e enviou RSET — nenhuma mensagem foi enviada.)',

  flag_no_size_extension: 'O servidor não anuncia SIZE',
  fd_no_size_extension: 'Sem SIZE um remetente não tem como saber se uma mensagem grande será aceita antes de tê-la transferido inteira.',

  flag_submission_without_starttls: 'A porta de submissão não oferece STARTTLS',
  fd_submission_without_starttls: 'A porta 587 é onde os clientes de e-mail se autenticam. Sem STARTTLS essas credenciais atravessam a rede em texto aberto.',

  flag_rdns_missing: 'Um endereço de servidor de e-mail não tem registro PTR',
  fd_rdns_missing: 'A falta de DNS reverso é uma das razões mais comuns de o e-mail de um servidor novo ser adiado ou ir para o lixo eletrônico — e uma das menos explicadas pelo lado receptor.',

  flag_rdns_not_confirmed: 'O DNS reverso não resolve de volta',
  fd_rdns_not_confirmed: 'O registro PTR dá um nome, e esse nome não resolve para este endereço. Os receptores conferem a ida e volta justamente porque ela exige que duas partes diferentes tenham feito a sua parte.',

  flag_rdns_none_confirmed: 'Nenhum servidor de e-mail tem DNS reverso confirmado',
  fd_rdns_none_confirmed: 'Nenhum endereço passa na conferência de ida e volta. Espere atrasos de entrega e classificação como lixo eletrônico por parte dos receptores que levam isso em conta.',
};

OWN.fr = {
  title: 'Contrôle e-mail — SPF, DKIM, DMARC, MTA-STS et DANE pour n’importe quel domaine',
  title_short: 'Contrôle e-mail',
  h1: 'Contrôle e-mail',
  subtitle: 'SPF déployé à travers chaque include et compté face à la limite de dix, alignement et rapports DMARC, et la sécurité du transport vérifiée sur la connexion réelle',
  ph_host: 'example.com',
  hero_label: 'Domaine contrôlé',
  empty_hint: 'Saisissez un nom de domaine. Le contrôle déploie l’enregistrement SPF à travers chaque include, essaie les sélecteurs DKIM qu’utilisent les grandes plateformes, lit la politique DMARC, récupère la politique MTA-STS en HTTPS et ouvre des sessions SMTP en lecture seule avec les serveurs de messagerie. Aucun message n’est jamais envoyé.',

  stage_resolve: 'recherche des serveurs de messagerie',
  stage_mx: 'contrôle du jeu MX',
  stage_spf: 'déploiement de SPF',
  stage_dkim: 'recherche des clés DKIM',
  stage_dmarc: 'lecture de la politique DMARC',
  stage_mtasts: 'récupération de la politique MTA-STS',
  stage_dane: 'contrôle de DANE',
  stage_starttls: 'dialogue avec les serveurs de messagerie',
  stage_grade: 'notation',

  card_grade: 'Détail de la note',
  card_mx: 'Serveurs de messagerie',
  card_spf: 'SPF',
  card_spf_tree: 'Déploiement de SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Sécurité du transport',
  card_sessions: 'Sessions SMTP',
  card_rdns: 'DNS inverse',

  comp_authentication: 'Authentification',
  comp_transport: 'Transport',
  comp_hygiene: 'Hygiène',

  k_mx_count: 'Enregistrements MX',
  k_null_mx: 'MX nul',
  k_ipv6_mx: 'Joignables en IPv6',
  k_spf_record: 'Enregistrement',
  k_spf_lookups: 'Requêtes DNS utilisées',
  k_spf_voids: 'Requêtes vides',
  k_spf_policy: 'Par défaut pour tous les autres',
  k_dkim_keys: 'Clés trouvées',
  k_dkim_tried: 'Sélecteurs essayés',
  k_dkim_strongest: 'Clé la plus forte',
  k_dmarc_policy: 'Politique',
  k_dmarc_subdomain: 'Politique pour les sous-domaines',
  k_dmarc_percent: 'Appliquée à',
  k_dmarc_alignment: 'Alignement (DKIM / SPF)',
  k_dmarc_rua: 'Rapports agrégés vers',
  k_dmarc_ruf: 'Rapports détaillés vers',
  k_dmarc_external: 'Rapports externes autorisés',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Mode',
  k_mtasts_id: 'Identifiant de la politique',
  k_mtasts_maxage: 'Conservée pendant',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Serveurs couverts',
  k_starttls: 'STARTTLS',
  k_port25: 'Port 25 sortant',
  k_open_relay: 'Relais ouvert',
  k_rdns_confirmed: 'Confirmé dans les deux sens',
  k_queries: 'Requêtes effectuées',

  th_priority: 'Priorité',
  th_host: 'Hôte',
  th_addresses: 'Adresses',
  th_port: 'Port',
  th_tls: 'TLS',
  th_banner: 'Bannière',
  th_extensions: 'Annoncé',
  th_selector: 'Sélecteur',
  th_key_type: 'Clé',
  th_bits: 'Bits',
  th_state: 'État',
  th_address: 'Adresse',
  th_ptr: 'PTR',
  th_confirmed: 'Confirmé',
  th_term: 'Terme',
  th_lookup: 'Requête',

  pol_none: 'none — observation seule',
  pol_quarantine: 'quarantine — vers les indésirables',
  pol_reject: 'reject — rejeter',
  spfp_pass: 'accepter tout le monde (+all)',
  spfp_fail: 'rejeter (-all)',
  spfp_softfail: 'échec souple (~all)',
  spfp_neutral: 'neutre (?all)',
  spfp_redirect: 'délégué par redirect',
  spfterm_no_target: 'sans cible',
  spfterm_loop: 'boucle — déjà visité',
  spfterm_lookup_failed: 'la requête a échoué',
  spfterm_no_spf_record: 'pas d’enregistrement SPF là-bas',

  stsmode_enforce: 'enforce — appliquer',
  stsmode_testing: 'testing — rapports seuls',
  stsmode_none: 'none — désactivée',
  rdns_confirmed: 'confirmé',
  rdns_unconfirmed: 'ne résout pas en retour',
  rdns_missing: 'pas de PTR',
  rdns_unknown: 'non contrôlé',
  v_of_limit: '{used} sur {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} j',
  v_blocked_here: 'bloqué depuis notre réseau',
  v_no_selector_found: 'aucun des {n} sélecteurs connus',

  note_spf: 'Le RFC 7208 autorise dix termes engendrant une requête DNS sur l’ensemble de l’évaluation, en suivant chaque include à l’intérieur de chaque include. Au-delà de dix, un destinataire doit renvoyer permerror — et un permerror signifie que SPF ne s’applique pas du tout, exactement comme s’il n’y avait aucun enregistrement.',
  note_dmarc: 'Avec p=none, rien n’est appliqué : un message qui échoue à l’alignement SPF comme DKIM est délivré comme avant. C’est le bon endroit pour commencer et le mauvais pour rester.',
  note_transport: 'STARTTLS est opportuniste : un expéditeur à qui l’on retire l’offre continue simplement en clair. MTA-STS et DANE sont ce qui transforme cette possibilité en garantie.',
  note_sessions: 'Toutes les sessions sont en lecture seule. La sonde de relais s’arrête à RCPT TO et envoie RSET ; aucune commande DATA n’est jamais émise, donc aucun message ne peut partir.',
  note_rdns: 'Un enregistrement PTR ne prouve rien à lui seul — le propriétaire d’un bloc d’adresses peut y mettre n’importe quel nom. Ce que les destinataires vérifient, c’est que ce nom résout en retour vers la même adresse.',

  err_smtp_timeout: 'Le serveur de messagerie n’a pas répondu à temps.',
  err_smtp_network: 'Le serveur de messagerie n’a pas pu être joint.',
  err_smtp_refused: 'Le serveur de messagerie a refusé la connexion.',
  err_tls_failed: 'La poignée de main TLS avec le serveur de messagerie a échoué.',

  inc_mx_lookup_failed: 'les enregistrements MX n’ont pas pu être lus',
  inc_spf_lookup_failed: 'l’enregistrement SPF n’a pas pu être lu',
  inc_dmarc_lookup_failed: 'l’enregistrement DMARC n’a pas pu être lu',
  inc_port_25_unreachable_from_this_network: 'le port 25 sortant est bloqué là où ce service s’exécute, si bien que STARTTLS, la vérification DANE contre le certificat réel et le test de relais n’ont pas pu être faits',
  inc_not_every_mx_was_probed: 'seuls les serveurs de plus haute priorité ont été contactés',

  cap_open_relay: 'le serveur relaie le courrier d’inconnus',
  cap_spf_authorises_everyone: 'SPF autorise l’internet entier',
  cap_no_mail_servers: 'pas de serveurs de messagerie',
  cap_mail_servers_unreachable: 'aucun serveur de messagerie n’a répondu sur le port 25',
  cap_dane_mismatch: 'DANE ne correspond pas au certificat présenté',
  cap_mtasts_policy_contradicts_dns: 'la politique MTA-STS omet un serveur de messagerie réel',
  cap_spf_over_the_lookup_limit: 'SPF dépasse la limite de requêtes',
  cap_spf_permerror: 'SPF est une erreur permanente',
  cap_dmarc_permerror: 'DMARC est une erreur permanente',
  cap_mail_in_the_clear: 'le courrier est accepté sans chiffrement',
  cap_no_spf: 'pas d’enregistrement SPF',
  cap_no_dmarc: 'pas d’enregistrement DMARC',
  cap_starttls_broken: 'STARTTLS est proposé et ne fonctionne pas',
  cap_dmarc_not_enforcing: 'DMARC n’applique rien',
  cap_no_reverse_dns: 'pas de DNS inverse confirmé',
  cap_spf_without_a_default: 'SPF n’a pas de valeur par défaut',
  cap_weak_dkim_key: 'une clé DKIM trop courte',
  cap_dmarc_reports_go_nowhere: 'les rapports DMARC ne sont pas autorisés',
  cap_mail_server_does_not_resolve: 'un serveur de messagerie ne résout pas',
  cap_scan_incomplete: 'le contrôle est resté incomplet, aucune note n’a donc été attribuée',

  flag_null_mx: 'Le domaine déclare ne pas gérer de courrier',
  fd_null_mx: 'Un unique MX de priorité 0 pointant vers la racine, c’est le RFC 7505 pour « ce domaine n’envoie ni ne reçoit de courrier ». Délibéré, et bien meilleur que l’absence totale de MX — sans lui, les expéditeurs se rabattent sur l’enregistrement d’adresse.',

  flag_no_mx: 'Aucun enregistrement MX',
  fd_no_mx: 'Rien n’indique où doit aller le courrier de ce domaine, et il n’y a pas non plus d’adresse de repli : il est donc tout simplement impossible de le délivrer.',

  flag_no_mx_falls_back_to_a: 'Sans enregistrement MX, les expéditeurs se rabattent sur l’enregistrement A',
  fd_no_mx_falls_back_to_a: 'Le RFC 5321 §5.1 demande à un expéditeur sans MX d’essayer l’enregistrement d’adresse. Le courrier de ce domaine sera délivré à ce qui écoute sur le port 25 du serveur web — ce qui est rarement l’intention.',

  flag_duplicate_mx_host: 'Le même hôte est listé deux fois',
  fd_duplicate_mx_host: 'Un hôte apparaît à plusieurs priorités. Ce n’est pas de la redondance ; c’est la même machine essayée deux fois.',

  flag_mx_does_not_resolve: 'Le nom d’un serveur de messagerie ne résout pas',
  fd_mx_does_not_resolve: 'Le MX nomme un hôte sans enregistrement d’adresse. Chaque expéditeur qui atteint cette priorité attend la requête, n’obtient rien et passe à la suite — retardant du courrier qui aurait dû arriver tout de suite.',

  flag_mx_points_at_cname: 'Un enregistrement MX pointe vers un alias',
  fd_mx_points_at_cname: 'Le RFC 2181 §10.3 exige qu’un MX nomme un hôte doté d’enregistrements d’adresse, pas un CNAME. Certains expéditeurs s’en accommodent, d’autres refusent, et la répartition change avec le temps.',

  flag_single_mx: 'Un seul serveur de messagerie',
  fd_single_mx: 'Avec un seul MX, la moindre panne fait que les expéditeurs mettent en file et réessaient — pendant des heures ou des jours, selon leur propre politique — et une partie de ce courrier finira en échec.',

  flag_no_ipv6_mx: 'Aucun serveur de messagerie n’est joignable en IPv6',
  fd_no_ipv6_mx: 'Les expéditeurs sur des réseaux IPv6 seuls atteignent ce domaine via un traducteur, quand ils y parviennent.',

  flag_spf_missing: 'Pas d’enregistrement SPF',
  fd_spf_missing: 'Rien n’indique quels serveurs peuvent envoyer du courrier au nom de ce domaine, il n’y a donc rien à vérifier. SPF, c’est un enregistrement TXT et la chose la moins coûteuse de toute cette page.',

  flag_spf_multiple_records: 'Plus d’un enregistrement SPF',
  fd_spf_multiple_records: 'Le RFC 7208 §4.5 fait de deux enregistrements une erreur permanente, et un permerror signifie aucun résultat SPF — l’inverse de ce que visait l’ajout du second. Il faut les fondre en un seul.',

  flag_spf_too_many_lookups: 'SPF exige plus de dix requêtes DNS',
  fd_spf_too_many_lookups: 'La limite du RFC 7208 §4.6.4 est de dix termes engendrant une requête sur l’ensemble de l’évaluation, en suivant chaque include dans chaque include. Au-delà, un destinataire doit renvoyer permerror et SPF cesse de s’appliquer — l’enregistrement pourrait aussi bien ne pas exister. On dépasse facilement en ajoutant un prestataire de plus, et cela reste totalement invisible sur l’enregistrement lui-même.',

  flag_spf_lookups_near_limit: 'SPF approche la limite de dix requêtes',
  fd_spf_lookups_near_limit: 'Il ne reste guère de marge. Le prochain service ajouté — ou un changement dans l’include de quelqu’un d’autre, que vous ne maîtrisez pas — la fera dépasser.',

  flag_spf_too_many_void_lookups: 'Trop de requêtes SPF ne renvoient rien',
  fd_spf_too_many_void_lookups: 'Le RFC 7208 tolère deux requêtes qui ne résolvent vers rien ; au-delà, c’est une erreur permanente. Il s’agit d’ordinaire d’un include oublié pour un service qui n’est plus utilisé.',

  flag_spf_no_all: 'SPF n’a pas de valeur par défaut',
  fd_spf_no_all: 'Sans mécanisme « all » ni redirect, un expéditeur qui ne correspond à rien obtient un résultat neutre — c’est-à-dire aucune opinion du tout.',

  flag_spf_plus_all: 'SPF autorise l’internet entier',
  fd_spf_plus_all: '« +all » dit que n’importe quel hôte, n’importe où, peut écrire au nom de ce domaine. C’est presque toujours un malentendu sur le qualificateur, et c’est pire que l’absence de SPF, car cela cautionne explicitement le faussaire.',

  flag_spf_neutral_all: 'SPF se termine par ?all',
  fd_spf_neutral_all: '« ?all » refuse explicitement de se prononcer sur les expéditeurs qui ne correspondent à rien. Les destinataires traitent cela comme une absence de résultat.',

  flag_spf_softfail_all: 'SPF se termine par ~all plutôt que par -all',
  fd_spf_softfail_all: 'L’échec souple demande aux destinataires d’accepter mais de marquer. C’est le bon réglage tant que vous cherchez encore qui envoie en votre nom, et ce qu’il faut resserrer une fois que vous le savez.',

  flag_spf_uses_ptr: 'SPF utilise le mécanisme ptr',
  fd_spf_uses_ptr: 'Le RFC 7208 §5.5 le déclare obsolète sans détour : lent, peu fiable, et il reporte le travail sur qui gère la zone inverse. Certains destinataires l’ignorent purement et simplement.',

  flag_spf_unknown_mechanism: 'SPF contient un terme que personne ne comprend',
  fd_spf_unknown_mechanism: 'Un mécanisme non reconnu est une erreur permanente selon le RFC 7208 §4.6.1, et il fait rejeter l’enregistrement entier. C’est en général une faute de frappe.',

  flag_spf_duplicate_redirect: 'Plus d’un modificateur redirect',
  fd_spf_duplicate_redirect: 'Un second redirect fait de l’enregistrement une erreur permanente.',

  flag_spf_redirect_after_all: 'Un redirect que l’on n’atteindra jamais',
  fd_spf_redirect_after_all: 'L’enregistrement comporte à la fois un mécanisme « all » et un redirect. « all » correspond toujours, l’évaluation s’arrête donc là et le redirect est du texte mort.',

  flag_spf_record_long: 'L’enregistrement SPF est long',
  fd_spf_record_long: 'Les enregistrements longs sont découpés en plusieurs chaînes sur le fil. Cela ne pose pas de problème en soi — les destinataires les recollent sans rien entre elles — mais c’est là que les analyseurs qui les joignent par une espace commencent à corrompre l’enregistrement.',

  flag_spf_include_loop: 'Un include renvoie vers quelque chose de déjà visité',
  fd_spf_include_loop: 'Le déploiement boucle. Un destinataire s’arrête à la limite de requêtes et renvoie une erreur permanente.',

  flag_spf_include_without_record: 'Un include pointe vers un domaine sans enregistrement SPF',
  fd_spf_include_without_record: 'Le RFC 7208 §5.2 en fait une erreur permanente, et non une simple requête gaspillée. C’est en général un service retiré d’un côté et pas de l’autre.',

  flag_dkim_no_known_selector: 'Aucune clé DKIM sur les sélecteurs que nous connaissons',
  fd_dkim_no_known_selector: 'Les sélecteurs sont choisis par celui qui signe et n’apparaissent que dans l’en-tête d’un message signé : on ne peut donc pas les énumérer de l’extérieur. Cela ne prouve pas que DKIM est absent — si vous connaissez le vôtre, passez-le avec ?selector= et le contrôle devient concluant.',

  flag_dkim_key_revoked: 'Une clé DKIM a été révoquée',
  fd_dkim_key_revoked: 'L’enregistrement est publié avec un p= vide, ce qui révoque la clé. C’est la bonne manière d’en retirer une — et un enregistrement laissé ainsi pendant des mois est d’ordinaire un renouvellement que personne n’a terminé.',

  flag_dkim_key_malformed: 'Une clé DKIM ne peut pas être analysée',
  fd_dkim_key_malformed: 'La valeur de p= n’est pas un matériel de clé valide. Toute signature faite avec elle échouera à la vérification.',

  flag_dkim_in_test_mode: 'Un enregistrement DKIM est en mode test',
  fd_dkim_in_test_mode: 't=y demande aux destinataires de traiter une signature en échec comme si DKIM n’était pas utilisé. Sa place est dans un déploiement en cours et nulle part ailleurs.',

  flag_dkim_key_too_short: 'Une clé DKIM fait moins de 1024 bits',
  fd_dkim_key_too_short: 'En dessous de 1024 bits, la signature n’est pas vraiment difficile à forger, et beaucoup de destinataires ignorent ces clés d’emblée.',

  flag_dkim_key_1024_bit: 'Une clé DKIM fait 1024 bits',
  fd_dkim_key_1024_bit: 'Encore acceptée partout, et en dessous des recommandations actuelles. 2048 est la taille normale ; le renouvellement, c’est un nouveau sélecteur et un enregistrement DNS.',

  flag_dmarc_missing: 'Pas d’enregistrement DMARC',
  fd_dmarc_missing: 'Sans DMARC, les résultats de SPF et de DKIM sont indicatifs : rien ne les rattache à l’adresse que le lecteur voit réellement, et rien ne dit aux destinataires quoi faire lorsqu’ils échouent.',

  flag_dmarc_inherited: 'DMARC est hérité du domaine parent',
  fd_dmarc_inherited: 'Ce nom n’a pas d’enregistrement propre : la politique du domaine organisationnel s’applique — sa valeur sp= s’il en a une, sinon son p=.',

  flag_dmarc_multiple_records: 'Plus d’un enregistrement DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3 : avec plus d’un enregistrement, la politique est entièrement écartée, comme si aucune n’avait été publiée.',

  flag_dmarc_no_policy: 'L’enregistrement DMARC n’a pas d’étiquette p=',
  fd_dmarc_no_policy: 'p= est obligatoire. Sans elle, l’enregistrement est ignoré.',

  flag_dmarc_invalid_policy: 'La politique DMARC n’est pas une valeur reconnue',
  fd_dmarc_invalid_policy: 'p= doit valoir none, quarantine ou reject. Avec toute autre valeur, les destinataires écartent l’enregistrement.',

  flag_dmarc_policy_none: 'DMARC n’applique rien',
  fd_dmarc_policy_none: 'p=none demande aux destinataires de rapporter et de ne rien changer. Un message qui échoue à l’alignement SPF comme DKIM est délivré exactement comme il le serait sans DMARC. C’est la bonne façon de commencer — et un très grand nombre de domaines campent là depuis des années en se croyant protégés.',

  flag_dmarc_policy_quarantine: 'DMARC met en quarantaine plutôt que de rejeter',
  fd_dmarc_policy_quarantine: 'Le courrier en échec part dans les indésirables au lieu d’être refusé. Une étape raisonnable vers reject, et un endroit où du courrier falsifié atteint encore les gens.',

  flag_dmarc_subdomain_policy_none: 'Les sous-domaines échappent à la politique',
  fd_dmarc_subdomain_policy_none: 'sp=none laisse chaque sous-domaine — y compris ceux qui n’ont jamais existé — disponible pour l’usurpation, alors que le domaine lui-même est protégé.',

  flag_dmarc_partial_percentage: 'La politique ne s’applique qu’à une partie du courrier',
  fd_dmarc_partial_percentage: 'pct= inférieur à 100 demande aux destinataires d’appliquer la politique à cette proportion des messages en échec et de traiter le reste plus souplement. Utile pendant le déploiement, et une brèche tant que c’est en place.',

  flag_dmarc_no_reporting: 'Aucune adresse pour les rapports agrégés',
  fd_dmarc_no_reporting: 'Sans rua=, aucun rapport ne vous parvient : impossible de savoir qui écrit au nom de votre domaine, ni ce qui casserait si vous resserriez la politique.',

  flag_dmarc_external_reporting_unauthorised: 'L’adresse de rapport externe ne vous a pas autorisé',
  fd_dmarc_external_reporting_unauthorised: 'Les rapports sont dirigés vers un autre domaine, et ce domaine ne publie pas l’enregistrement par lequel il accepte de les recevoir (RFC 7489 §7.1). Les destinataires conformes n’envoient rien. L’enregistrement DMARC paraît parfait et les rapports n’arrivent jamais — ce que l’on met presque toujours sur le compte de rapports « qui mettent du temps ».',

  flag_mtasts_missing: 'Pas de politique MTA-STS',
  fd_mtasts_missing: 'STARTTLS est opportuniste : un expéditeur qui ne voit pas l’offre envoie en clair, et retirer cette offre est facile pour quiconque se trouve entre les deux serveurs. MTA-STS publie en HTTPS que ce domaine parle toujours TLS, ce qui oblige désormais l’attaque à casser la PKI du web.',

  flag_mtasts_multiple_records: 'Plus d’un enregistrement TXT MTA-STS',
  fd_mtasts_multiple_records: 'Les expéditeurs ne peuvent pas savoir quel identifiant est le bon, si bien que la politique risque de ne pas être rafraîchie lorsqu’elle change.',

  flag_mtasts_no_id: 'L’enregistrement MTA-STS n’a pas d’identifiant',
  fd_mtasts_no_id: 'L’identifiant est ce qui indique à un expéditeur que sa copie de la politique est périmée. Sans lui, une politique modifiée peut n’être reprise qu’à l’expiration de max_age.',

  flag_mtasts_policy_host_missing: 'L’hôte de la politique ne résout pas',
  fd_mtasts_policy_host_missing: 'L’enregistrement TXT annonce une politique, et mta-sts.<domaine> n’a pas d’adresse : aucun expéditeur ne peut donc la récupérer.',

  flag_mtasts_policy_host_private: 'L’hôte de la politique résout vers un espace d’adressage privé',
  fd_mtasts_policy_host_private: 'La politique n’a pas été récupérée : l’hôte pointe vers une adresse à laquelle ce service ne se connecte pas.',

  flag_mtasts_policy_unreachable: 'La politique MTA-STS n’a pas pu être récupérée',
  fd_mtasts_policy_unreachable: 'L’enregistrement TXT promet une politique qui n’est pas là, ou dont le certificat ne valide pas. Comme tout le mécanisme repose sur ce certificat HTTPS, un échec ici signifie que les expéditeurs retombent sur du TLS opportuniste.',

  flag_mtasts_policy_wrong_content_type: 'La politique n’est pas servie en text/plain',
  fd_mtasts_policy_wrong_content_type: 'Le RFC 8461 exige text/plain. Les expéditeurs stricts la refuseront.',

  flag_mtasts_policy_bad_version: 'La version de la politique n’est pas STSv1',
  fd_mtasts_policy_bad_version: 'Les expéditeurs n’utiliseront pas une politique dont ils ne reconnaissent pas la version.',

  flag_mtasts_policy_bad_mode: 'Le mode de la politique n’est pas une valeur reconnue',
  fd_mtasts_policy_bad_mode: 'mode doit valoir enforce, testing ou none.',

  flag_mtasts_mode_testing: 'MTA-STS est en mode test',
  fd_mtasts_mode_testing: 'Les échecs sont rapportés et le courrier est délivré quand même : la politique ne protège donc encore rien. Une étape, pas une destination.',

  flag_mtasts_mode_none: 'MTA-STS est désactivé par sa propre politique',
  fd_mtasts_mode_none: 'mode=none retire la politique. Cela existe pour qu’un domaine puisse abandonner MTA-STS proprement ; laissé en place, cela signifie simplement que l’enregistrement ne fait rien.',

  flag_mtasts_no_max_age: 'La politique n’a pas de max_age',
  fd_mtasts_no_max_age: 'max_age est obligatoire, et c’est lui qui rend la politique résistante à la suppression : un expéditeur qui l’a mise en cache continuera de l’appliquer.',

  flag_mtasts_max_age_short: 'La politique est conservée moins d’une journée',
  fd_mtasts_max_age_short: 'Un max_age court rétrécit la fenêtre pendant laquelle une politique en cache protège un expéditeur. Quelques semaines est le choix habituel une fois la politique stable.',

  flag_mtasts_mx_not_in_policy: 'Un serveur de messagerie réel manque à la politique',
  fd_mtasts_mx_not_in_policy: 'Le jeu MX contient un hôte auquel ne correspond aucun motif mx: de la politique. Tout expéditeur qui applique cette politique refusera de délivrer vers cet hôte — le courrier échoue donc précisément chez les expéditeurs qui font attention.',

  flag_mtasts_policy_lists_unknown_mx: 'La politique liste des motifs qui ne correspondent à aucun MX actuel',
  fd_mtasts_policy_lists_unknown_mx: 'Sans danger, et c’est en général un reste de migration. Cela vaut la peine d’être nettoyé pour que la politique continue de décrire la réalité.',

  flag_mtasts_policy_no_mx: 'La politique ne liste aucun serveur de messagerie',
  fd_mtasts_policy_no_mx: 'Une politique sans entrée mx: ne correspond à rien : les expéditeurs qui l’appliquent n’ont donc nulle part où délivrer.',

  flag_tlsrpt_missing: 'Pas d’enregistrement TLS-RPT',
  fd_tlsrpt_missing: 'Un enregistrement TXT, et le seul moyen d’apprendre que des expéditeurs n’arrivent pas à négocier TLS avec vos serveurs. Sans lui, un certificat expiré ou un STARTTLS cassé est invisible de votre côté.',

  flag_tlsrpt_no_rua: 'L’enregistrement TLS-RPT n’a pas de destination',
  fd_tlsrpt_no_rua: 'Sans rua=, les rapports n’ont nulle part où aller : l’enregistrement ne fait donc rien.',

  flag_dane_missing: 'Pas d’enregistrement DANE',
  fd_dane_missing: 'Les enregistrements TLSA épinglent le certificat qu’un serveur de messagerie doit présenter, en s’appuyant sur DNSSEC plutôt que sur les autorités publiques. C’est le plus solide des deux mécanismes de transport — et il exige une zone signée, ce qui est d’ordinaire la raison pour laquelle il n’est pas utilisé.',

  flag_dane_partial: 'Seuls certains serveurs de messagerie ont des enregistrements DANE',
  fd_dane_partial: 'Les expéditeurs choisissent un serveur par priorité : un jeu où seuls certains hôtes sont épinglés n’est protégé qu’une partie du temps.',

  flag_dane_without_dnssec: 'Un enregistrement TLSA dans une zone non signée',
  fd_dane_without_dnssec: 'DANE repose entièrement sur DNSSEC. Sans signatures, quiconque peut remplacer l’enregistrement MX peut aussi remplacer le TLSA : l’épinglage ne protège rien tout en en donnant l’apparence.',

  flag_dane_mismatch: 'L’enregistrement TLSA ne correspond pas au certificat présenté',
  fd_dane_mismatch: 'Le serveur présente un certificat que son propre enregistrement DANE n’autorise pas. Tout expéditeur qui valide DANE refusera de délivrer — cela arrête le courrier.',

  flag_dane_pkix_usage: 'Un enregistrement TLSA utilise un usage PKIX',
  fd_dane_pkix_usage: 'Les usages 0 et 1 exigent en plus que le certificat valide auprès des autorités publiques. Le RFC 7672 §3.1 interdit les deux pour SMTP, faute de manière convenue de faire cette vérification pour le courrier.',

  flag_dane_full_certificate: 'Un enregistrement TLSA épingle le certificat entier',
  fd_dane_full_certificate: 'Le type de correspondance 0 stocke le certificat complet plutôt qu’une empreinte. Cela fonctionne, cela alourdit l’enregistrement, et cela oblige à le remplacer à chaque renouvellement.',

  flag_port_25_blocked_from_here: 'Le port 25 sortant est bloqué là où ce service s’exécute',
  fd_port_25_blocked_from_here: 'Il s’agit de notre réseau, pas du vôtre. La plupart des hébergeurs bloquent par défaut les connexions sortantes vers le port 25. STARTTLS, la vérification DANE contre un certificat réel et le test de relais n’ont donc pas pu être faits, et la note est retenue plutôt que calculée à partir de ce qui était joignable.',

  flag_mx_not_reachable_on_25: 'Aucun serveur de messagerie n’a répondu sur le port 25',
  fd_mx_not_reachable_on_25: 'Les enregistrements MX nomment des hôtes qui n’acceptent pas de connexion sur le port par lequel le courrier est délivré. Rien ne peut être délivré à ce domaine.',

  flag_no_starttls: 'Un serveur de messagerie ne propose pas STARTTLS',
  fd_no_starttls: 'Chaque message délivré à ce serveur traverse internet sans chiffrement, lisible par tout ce qui se trouve sur le chemin. Proposer STARTTLS coûte un certificat et une ligne de configuration.',

  flag_starttls_fails: 'STARTTLS est proposé et ne fonctionne pas',
  fd_starttls_fails: 'Le serveur annonce STARTTLS et la poignée de main échoue. Les expéditeurs prudents peuvent refuser de retomber en clair et différer le courrier — c’est donc pire que de ne pas le proposer du tout.',

  flag_starttls_legacy_protocol: 'Le serveur de messagerie négocie une version obsolète de TLS',
  fd_starttls_legacy_protocol: 'TLS 1.0 et 1.1 sont obsolètes depuis le RFC 8996. Les expéditeurs en retirent progressivement la prise en charge, et le jour où ils le feront, le courrier cessera d’arriver.',

  flag_mx_certificate_not_trusted: 'Le certificat du serveur de messagerie ne valide pas',
  fd_mx_certificate_not_trusted: 'Le TLS opportuniste ordinaire ne vérifie pas les certificats : cela n’empêche donc pas la délivrance aujourd’hui. Cela l’empêche complètement dès que MTA-STS en mode enforce ou DANE entre en jeu.',

  flag_banner_reveals_version: 'La bannière nomme le logiciel et sa version',
  fd_banner_reveals_version: 'Un petit cadeau pour qui cherche des hôtes affectés par un défaut connu de cette version exacte. La bannière peut dire n’importe quoi.',

  flag_open_relay: 'Le serveur relaie le courrier d’inconnus',
  fd_open_relay: 'Il a accepté un message d’un expéditeur étranger vers un destinataire étranger. N’importe qui peut s’en servir pour envoyer du spam en votre nom, et il sera sur des listes de blocage en quelques heures s’il n’y est pas déjà. Cela se répare aujourd’hui. (La sonde s’est arrêtée à RCPT TO et a envoyé RSET — aucun message n’a été envoyé.)',

  flag_no_size_extension: 'Le serveur n’annonce pas SIZE',
  fd_no_size_extension: 'Sans SIZE, un expéditeur ne peut pas savoir si un gros message sera accepté avant de l’avoir transféré en entier.',

  flag_submission_without_starttls: 'Le port de soumission ne propose pas STARTTLS',
  fd_submission_without_starttls: 'Le port 587 est celui où les clients de messagerie s’authentifient. Sans STARTTLS, ces identifiants traversent le réseau en clair.',

  flag_rdns_missing: 'Une adresse de serveur de messagerie n’a pas d’enregistrement PTR',
  fd_rdns_missing: 'L’absence de DNS inverse est l’une des raisons les plus fréquentes pour lesquelles le courrier d’un serveur neuf est différé ou classé en indésirable — et l’une des moins souvent expliquées par le destinataire.',

  flag_rdns_not_confirmed: 'Le DNS inverse ne résout pas en retour',
  fd_rdns_not_confirmed: 'L’enregistrement PTR donne un nom, et ce nom ne résout pas vers cette adresse. Les destinataires vérifient l’aller-retour précisément parce qu’il exige que deux parties différentes aient fait leur part.',

  flag_rdns_none_confirmed: 'Aucun serveur de messagerie n’a de DNS inverse confirmé',
  fd_rdns_none_confirmed: 'Pas une seule adresse ne passe la vérification aller-retour. Attendez-vous à des retards de délivrance et à un classement en indésirable chez les destinataires qui en tiennent compte.',
};

OWN.de = {
  title: 'Mail-Prüfung — SPF, DKIM, DMARC, MTA-STS und DANE für jede Domain',
  title_short: 'Mail-Prüfung',
  h1: 'Mail-Prüfung',
  subtitle: 'SPF durch jedes include hindurch aufgelöst und gegen das Limit von zehn gezählt, DMARC-Ausrichtung und Berichte, und die Transportsicherheit an der echten Verbindung geprüft',
  ph_host: 'example.com',
  hero_label: 'Geprüfte Domain',
  empty_hint: 'Geben Sie einen Domainnamen ein. Die Prüfung löst den SPF-Eintrag durch jedes include hindurch auf, probiert die DKIM-Selektoren der großen Plattformen, liest die DMARC-Richtlinie, holt die MTA-STS-Richtlinie über HTTPS und öffnet ausschließlich lesende SMTP-Sitzungen zu den Mailservern. Es wird niemals eine Nachricht versendet.',

  stage_resolve: 'Mailserver werden gesucht',
  stage_mx: 'MX-Satz wird geprüft',
  stage_spf: 'SPF wird aufgelöst',
  stage_dkim: 'DKIM-Schlüssel werden gesucht',
  stage_dmarc: 'DMARC-Richtlinie wird gelesen',
  stage_mtasts: 'MTA-STS-Richtlinie wird geholt',
  stage_dane: 'DANE wird geprüft',
  stage_starttls: 'Gespräch mit den Mailservern',
  stage_grade: 'Note wird gebildet',

  card_grade: 'Zusammensetzung der Note',
  card_mx: 'Mailserver',
  card_spf: 'SPF',
  card_spf_tree: 'SPF-Auflösung',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Transportsicherheit',
  card_sessions: 'SMTP-Sitzungen',
  card_rdns: 'Reverse-DNS',

  comp_authentication: 'Authentifizierung',
  comp_transport: 'Transport',
  comp_hygiene: 'Hygiene',

  k_mx_count: 'MX-Einträge',
  k_null_mx: 'Null-MX',
  k_ipv6_mx: 'Über IPv6 erreichbar',
  k_spf_record: 'Eintrag',
  k_spf_lookups: 'Verbrauchte DNS-Abfragen',
  k_spf_voids: 'Leere Abfragen',
  k_spf_policy: 'Vorgabe für alle übrigen',
  k_dkim_keys: 'Gefundene Schlüssel',
  k_dkim_tried: 'Probierte Selektoren',
  k_dkim_strongest: 'Stärkster Schlüssel',
  k_dmarc_policy: 'Richtlinie',
  k_dmarc_subdomain: 'Richtlinie für Subdomains',
  k_dmarc_percent: 'Angewendet auf',
  k_dmarc_alignment: 'Ausrichtung (DKIM / SPF)',
  k_dmarc_rua: 'Sammelberichte an',
  k_dmarc_ruf: 'Einzelberichte an',
  k_dmarc_external: 'Externe Berichte genehmigt',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Modus',
  k_mtasts_id: 'Kennung der Richtlinie',
  k_mtasts_maxage: 'Vorgehalten für',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Abgedeckte Server',
  k_starttls: 'STARTTLS',
  k_port25: 'Ausgehender Port 25',
  k_open_relay: 'Offenes Relay',
  k_rdns_confirmed: 'In beide Richtungen bestätigt',
  k_queries: 'Gestellte Abfragen',

  th_priority: 'Priorität',
  th_host: 'Host',
  th_addresses: 'Adressen',
  th_port: 'Port',
  th_tls: 'TLS',
  th_banner: 'Begrüßung',
  th_extensions: 'Angekündigt',
  th_selector: 'Selektor',
  th_key_type: 'Schlüssel',
  th_bits: 'Bit',
  th_state: 'Zustand',
  th_address: 'Adresse',
  th_ptr: 'PTR',
  th_confirmed: 'Bestätigt',
  th_term: 'Term',
  th_lookup: 'Abfrage',

  pol_none: 'none — nur Beobachtung',
  pol_quarantine: 'quarantine — in den Spam-Ordner',
  pol_reject: 'reject — abweisen',
  spfp_pass: 'alle durchlassen (+all)',
  spfp_fail: 'abweisen (-all)',
  spfp_softfail: 'weicher Fehlschlag (~all)',
  spfp_neutral: 'neutral (?all)',
  spfp_redirect: 'per redirect delegiert',
  spfterm_no_target: 'ohne Ziel',
  spfterm_loop: 'Schleife — bereits besucht',
  spfterm_lookup_failed: 'Abfrage fehlgeschlagen',
  spfterm_no_spf_record: 'dort gibt es keinen SPF-Eintrag',

  stsmode_enforce: 'enforce — durchsetzen',
  stsmode_testing: 'testing — nur Berichte',
  stsmode_none: 'none — abgeschaltet',
  rdns_confirmed: 'bestätigt',
  rdns_unconfirmed: 'löst nicht zurück auf',
  rdns_missing: 'kein PTR',
  rdns_unknown: 'nicht geprüft',
  v_of_limit: '{used} von {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} T',
  v_blocked_here: 'aus unserem Netz gesperrt',
  v_no_selector_found: 'keiner der {n} bekannten Selektoren',

  note_spf: 'RFC 7208 erlaubt zehn Terme mit DNS-Abfrage über die gesamte Auswertung hinweg, wobei jedes include innerhalb jedes include mitgezählt wird. Jenseits von zehn muss ein Empfänger permerror zurückgeben — und permerror heißt, dass SPF überhaupt nicht gilt, genau so, als gäbe es keinen Eintrag.',
  note_dmarc: 'Bei p=none wird nichts durchgesetzt: Eine Nachricht, die sowohl an der SPF- als auch an der DKIM-Ausrichtung scheitert, wird zugestellt wie zuvor. Das ist der richtige Ort zum Anfangen und der falsche zum Bleiben.',
  note_transport: 'STARTTLS ist opportunistisch: Ein Absender, dem das Angebot entzogen wird, macht schlicht im Klartext weiter. MTA-STS und DANE sind das, was aus dieser Möglichkeit eine Zusage macht.',
  note_sessions: 'Alle Sitzungen sind rein lesend. Die Relay-Probe hält bei RCPT TO an und schickt RSET; ein DATA-Befehl wird nie abgesetzt, es kann also keine Nachricht verschickt werden.',
  note_rdns: 'Ein PTR-Eintrag allein beweist nichts — wer einen Adressblock besitzt, kann dort jeden beliebigen Namen eintragen. Empfänger prüfen, ob dieser Name auf dieselbe Adresse zurück auflöst.',

  err_smtp_timeout: 'Der Mailserver hat nicht rechtzeitig geantwortet.',
  err_smtp_network: 'Der Mailserver war nicht erreichbar.',
  err_smtp_refused: 'Der Mailserver hat die Verbindung abgewiesen.',
  err_tls_failed: 'Der TLS-Handshake mit dem Mailserver ist fehlgeschlagen.',

  inc_mx_lookup_failed: 'die MX-Einträge ließen sich nicht lesen',
  inc_spf_lookup_failed: 'der SPF-Eintrag ließ sich nicht lesen',
  inc_dmarc_lookup_failed: 'der DMARC-Eintrag ließ sich nicht lesen',
  inc_port_25_unreachable_from_this_network: 'der ausgehende Port 25 ist dort gesperrt, wo dieser Dienst läuft, daher konnten STARTTLS, der Abgleich von DANE mit dem echten Zertifikat und die Relay-Probe nicht durchgeführt werden',
  inc_not_every_mx_was_probed: 'es wurde nur zu den Servern mit der höchsten Priorität verbunden',

  cap_open_relay: 'der Server leitet Post für Fremde weiter',
  cap_spf_authorises_everyone: 'SPF autorisiert das ganze Internet',
  cap_no_mail_servers: 'keine Mailserver',
  cap_mail_servers_unreachable: 'kein Mailserver hat auf Port 25 geantwortet',
  cap_dane_mismatch: 'DANE passt nicht zum vorgelegten Zertifikat',
  cap_mtasts_policy_contradicts_dns: 'die MTA-STS-Richtlinie lässt einen echten Mailserver aus',
  cap_spf_over_the_lookup_limit: 'SPF überschreitet das Abfragelimit',
  cap_spf_permerror: 'SPF ist ein dauerhafter Fehler',
  cap_dmarc_permerror: 'DMARC ist ein dauerhafter Fehler',
  cap_mail_in_the_clear: 'Post wird unverschlüsselt angenommen',
  cap_no_spf: 'kein SPF-Eintrag',
  cap_no_dmarc: 'kein DMARC-Eintrag',
  cap_starttls_broken: 'STARTTLS wird angeboten und funktioniert nicht',
  cap_dmarc_not_enforcing: 'DMARC setzt nichts durch',
  cap_no_reverse_dns: 'kein bestätigtes Reverse-DNS',
  cap_spf_without_a_default: 'SPF hat keine Vorgabe',
  cap_weak_dkim_key: 'ein zu kurzer DKIM-Schlüssel',
  cap_dmarc_reports_go_nowhere: 'die DMARC-Berichte sind nicht genehmigt',
  cap_mail_server_does_not_resolve: 'ein Mailserver löst nicht auf',
  cap_scan_incomplete: 'die Prüfung blieb unvollständig, daher wurde keine Note vergeben',

  flag_null_mx: 'Die Domain erklärt, dass sie keine Post bearbeitet',
  fd_null_mx: 'Ein einzelner MX mit Priorität 0, der auf die Wurzel zeigt, ist RFC 7505 für „diese Domain sendet und empfängt keine Post". Beabsichtigt, und weit besser als gar kein MX — ohne ihn weichen Absender auf den Adresseintrag aus.',

  flag_no_mx: 'Keine MX-Einträge',
  fd_no_mx: 'Nichts sagt, wohin Post für diese Domain gehen soll, und es gibt auch keine Ausweichadresse: Zustellen lässt sich schlicht nichts.',

  flag_no_mx_falls_back_to_a: 'Ohne MX-Einträge weichen Absender auf den A-Eintrag aus',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 weist einen Absender ohne MX an, den Adresseintrag zu versuchen. Post für diese Domain wird an das zugestellt, was auf Port 25 des Webservers lauscht — was selten beabsichtigt ist.',

  flag_duplicate_mx_host: 'Derselbe Host ist zweimal aufgeführt',
  fd_duplicate_mx_host: 'Ein Host erscheint unter mehr als einer Priorität. Das ist keine Redundanz, sondern dieselbe Maschine, die zweimal probiert wird.',

  flag_mx_does_not_resolve: 'Der Name eines Mailservers löst nicht auf',
  fd_mx_does_not_resolve: 'Der MX nennt einen Host ohne Adresseinträge. Jeder Absender, der diese Priorität erreicht, wartet auf die Abfrage, bekommt nichts und geht weiter — und verzögert damit Post, die sofort hätte ankommen sollen.',

  flag_mx_points_at_cname: 'Ein MX-Eintrag zeigt auf einen Alias',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 verlangt, dass ein MX einen Host mit Adresseinträgen nennt, keinen CNAME. Manche Absender kommen damit zurecht, manche weisen es ab, und wer was tut, ändert sich mit der Zeit.',

  flag_single_mx: 'Nur ein Mailserver',
  fd_single_mx: 'Mit einem einzigen MX bedeutet jeder Ausfall, dass Absender in die Warteschlange gehen und erneut versuchen — stunden- oder tagelang, je nach eigener Richtlinie — und ein Teil dieser Post wird am Ende zurückgehen.',

  flag_no_ipv6_mx: 'Kein Mailserver ist über IPv6 erreichbar',
  fd_no_ipv6_mx: 'Absender in reinen IPv6-Netzen erreichen diese Domain über einen Übersetzer, wenn überhaupt.',

  flag_spf_missing: 'Kein SPF-Eintrag',
  fd_spf_missing: 'Nichts sagt, welche Server als diese Domain Post versenden dürfen, es gibt also nichts, wogegen geprüft werden könnte. SPF ist ein TXT-Eintrag und das Billigste auf dieser ganzen Seite.',

  flag_spf_multiple_records: 'Mehr als ein SPF-Eintrag',
  fd_spf_multiple_records: 'RFC 7208 §4.5 macht zwei Einträge zu einem dauerhaften Fehler, und permerror heißt gar kein SPF-Ergebnis — das Gegenteil dessen, was das Hinzufügen des zweiten bezweckte. Sie gehören zu einem verschmolzen.',

  flag_spf_too_many_lookups: 'SPF braucht mehr als zehn DNS-Abfragen',
  fd_spf_too_many_lookups: 'Das Limit aus RFC 7208 §4.6.4 sind zehn abfragende Terme über die gesamte Auswertung, jedes include innerhalb jedes include mitgezählt. Darüber hinaus muss ein Empfänger permerror zurückgeben, und SPF gilt dann nicht mehr — der Eintrag könnte ebenso gut fehlen. Man überschreitet es leicht, indem man einen Anbieter mehr aufnimmt, und am Eintrag selbst ist davon nichts zu sehen.',

  flag_spf_lookups_near_limit: 'SPF ist nah am Limit von zehn Abfragen',
  fd_spf_lookups_near_limit: 'Es bleibt wenig Luft. Der nächste hinzugefügte Dienst — oder eine Änderung innerhalb des include eines anderen, über die Sie nicht bestimmen — bringt es darüber.',

  flag_spf_too_many_void_lookups: 'Zu viele SPF-Abfragen liefern nichts',
  fd_spf_too_many_void_lookups: 'RFC 7208 erlaubt zwei Abfragen, die zu nichts auflösen; darüber hinaus ist es ein dauerhafter Fehler. Meist ist es ein vergessenes include für einen Dienst, der nicht mehr benutzt wird.',

  flag_spf_no_all: 'SPF hat keine Vorgabe',
  fd_spf_no_all: 'Ohne „all"-Mechanismus und ohne redirect erhält ein Absender, auf den nichts passt, ein neutrales Ergebnis — was dasselbe ist wie gar keine Aussage.',

  flag_spf_plus_all: 'SPF autorisiert das ganze Internet',
  fd_spf_plus_all: '„+all" sagt, dass jeder Host irgendwo als diese Domain senden darf. Fast immer ist es ein Missverständnis des Qualifikators, und es ist schlimmer als gar kein SPF, weil es ausdrücklich für den Fälscher bürgt.',

  flag_spf_neutral_all: 'SPF endet auf ?all',
  fd_spf_neutral_all: '„?all" weigert sich ausdrücklich, über Absender etwas zu sagen, auf die nichts passt. Empfänger behandeln das als fehlendes Ergebnis.',

  flag_spf_softfail_all: 'SPF endet auf ~all statt auf -all',
  fd_spf_softfail_all: 'Der weiche Fehlschlag bittet Empfänger, anzunehmen und zu kennzeichnen. Das ist richtig, solange Sie noch herausfinden, wer in Ihrem Namen sendet, und das, was man anzieht, sobald man es weiß.',

  flag_spf_uses_ptr: 'SPF verwendet den ptr-Mechanismus',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 erklärt ihn rundheraus für veraltet: langsam, unzuverlässig, und er schiebt Arbeit auf den, der die Reverse-Zone betreibt. Manche Empfänger ignorieren ihn ganz.',

  flag_spf_unknown_mechanism: 'SPF enthält einen Term, den nichts versteht',
  fd_spf_unknown_mechanism: 'Ein unbekannter Mechanismus ist nach RFC 7208 §4.6.1 ein dauerhafter Fehler und verwirft den ganzen Eintrag. Meist ist es ein Tippfehler.',

  flag_spf_duplicate_redirect: 'Mehr als ein redirect-Modifikator',
  fd_spf_duplicate_redirect: 'Ein zweites redirect macht den Eintrag zu einem dauerhaften Fehler.',

  flag_spf_redirect_after_all: 'Ein redirect, das nie erreicht wird',
  fd_spf_redirect_after_all: 'Der Eintrag hat sowohl einen „all"-Mechanismus als auch ein redirect. „all" passt immer, die Auswertung endet also dort und das redirect ist toter Text.',

  flag_spf_record_long: 'Der SPF-Eintrag ist lang',
  fd_spf_record_long: 'Lange Einträge werden auf dem Draht in mehrere Zeichenketten geteilt. Das ist für sich in Ordnung — Empfänger fügen sie ohne Trennzeichen zusammen —, aber genau dort beginnen Parser, die sie mit einem Leerzeichen verbinden, den Eintrag zu zerstören.',

  flag_spf_include_loop: 'Ein include zeigt auf etwas bereits Besuchtes zurück',
  fd_spf_include_loop: 'Die Auflösung läuft im Kreis. Ein Empfänger bricht beim Abfragelimit ab und gibt einen dauerhaften Fehler zurück.',

  flag_spf_include_without_record: 'Ein include zeigt auf eine Domain ohne SPF-Eintrag',
  fd_spf_include_without_record: 'RFC 7208 §5.2 macht das zu einem dauerhaften Fehler, nicht bloß zu einer verschwendeten Abfrage. Meist ist es ein Dienst, der an einem Ende abgeschaltet wurde und am anderen nicht.',

  flag_dkim_no_known_selector: 'Bei keinem uns bekannten Selektor ein DKIM-Schlüssel',
  fd_dkim_no_known_selector: 'Selektoren wählt, wer signiert, und sie stehen nur im Kopf einer signierten Nachricht — von außen lassen sie sich also nicht aufzählen. Das ist kein Beweis, dass DKIM fehlt: Wenn Sie Ihren Selektor kennen, geben Sie ihn mit ?selector= an, und die Prüfung wird eindeutig.',

  flag_dkim_key_revoked: 'Ein DKIM-Schlüssel wurde widerrufen',
  fd_dkim_key_revoked: 'Der Eintrag ist mit leerem p= veröffentlicht, was den Schlüssel widerruft. Das ist der richtige Weg, einen auszumustern — und ein Eintrag, der monatelang so steht, ist meist ein Wechsel, den niemand zu Ende gebracht hat.',

  flag_dkim_key_malformed: 'Ein DKIM-Schlüssel lässt sich nicht lesen',
  fd_dkim_key_malformed: 'Der Wert von p= ist kein gültiges Schlüsselmaterial. Jede damit erzeugte Signatur wird die Prüfung nicht bestehen.',

  flag_dkim_in_test_mode: 'Ein DKIM-Eintrag steht im Testmodus',
  fd_dkim_in_test_mode: 't=y weist Empfänger an, eine gescheiterte Signatur so zu behandeln, als sei DKIM nicht im Einsatz. Sein Platz ist eine laufende Einführung und sonst nirgends.',

  flag_dkim_key_too_short: 'Ein DKIM-Schlüssel ist kürzer als 1024 Bit',
  fd_dkim_key_too_short: 'Unter 1024 Bit ist die Signatur nicht nennenswert schwer zu fälschen, und viele Empfänger ignorieren solche Schlüssel von vornherein.',

  flag_dkim_key_1024_bit: 'Ein DKIM-Schlüssel hat 1024 Bit',
  fd_dkim_key_1024_bit: 'Wird noch überall angenommen und liegt unter den heutigen Empfehlungen. 2048 ist die übliche Größe; der Wechsel besteht aus einem neuen Selektor und einem DNS-Eintrag.',

  flag_dmarc_missing: 'Kein DMARC-Eintrag',
  fd_dmarc_missing: 'Ohne DMARC sind die Ergebnisse von SPF und DKIM unverbindlich: Nichts bindet sie an die Adresse, die ein Leser tatsächlich sieht, und nichts sagt Empfängern, was bei einem Fehlschlag zu tun ist.',

  flag_dmarc_inherited: 'DMARC wird von der übergeordneten Domain geerbt',
  fd_dmarc_inherited: 'Dieser Name hat keinen eigenen Eintrag, es gilt also die Richtlinie der organisatorischen Domain — deren sp=, sofern gesetzt, sonst deren p=.',

  flag_dmarc_multiple_records: 'Mehr als ein DMARC-Eintrag',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: Bei mehr als einem Eintrag wird die Richtlinie vollständig verworfen, als wäre keine veröffentlicht worden.',

  flag_dmarc_no_policy: 'Der DMARC-Eintrag hat kein p=',
  fd_dmarc_no_policy: 'p= ist Pflicht. Ohne es wird der Eintrag ignoriert.',

  flag_dmarc_invalid_policy: 'Die DMARC-Richtlinie ist kein anerkannter Wert',
  fd_dmarc_invalid_policy: 'p= muss none, quarantine oder reject sein. Bei allem anderen verwerfen Empfänger den Eintrag.',

  flag_dmarc_policy_none: 'DMARC setzt nichts durch',
  fd_dmarc_policy_none: 'p=none bittet Empfänger zu berichten und nichts zu ändern. Eine Nachricht, die an der SPF- wie an der DKIM-Ausrichtung scheitert, wird genau so zugestellt wie ohne DMARC. Das ist der richtige Anfang — und sehr viele Domains sitzen seit Jahren hier und halten sich für geschützt.',

  flag_dmarc_policy_quarantine: 'DMARC stellt unter Quarantäne statt abzuweisen',
  fd_dmarc_policy_quarantine: 'Gescheiterte Post landet im Spam-Ordner statt abgewiesen zu werden. Ein vernünftiger Schritt auf dem Weg zu reject — und ein Ort, an dem gefälschte Post die Leute weiterhin erreicht.',

  flag_dmarc_subdomain_policy_none: 'Subdomains sind von der Richtlinie ausgenommen',
  fd_dmarc_subdomain_policy_none: 'sp=none lässt jede Subdomain — auch solche, die es nie gegeben hat — für Fälschungen offen, während die Domain selbst geschützt ist.',

  flag_dmarc_partial_percentage: 'Die Richtlinie gilt nur für einen Teil der Post',
  fd_dmarc_partial_percentage: 'pct= unter 100 weist Empfänger an, die Richtlinie auf diesen Anteil der gescheiterten Nachrichten anzuwenden und den Rest milder zu behandeln. Beim Ausrollen nützlich, und eine Lücke, solange es gesetzt ist.',

  flag_dmarc_no_reporting: 'Keine Adresse für Sammelberichte',
  fd_dmarc_no_reporting: 'Ohne rua= kommen keine Berichte, und damit gibt es keine Möglichkeit herauszufinden, wer als Ihre Domain sendet oder was beim Anziehen der Richtlinie kaputtginge.',

  flag_dmarc_external_reporting_unauthorised: 'Die externe Berichtsadresse hat Sie nicht genehmigt',
  fd_dmarc_external_reporting_unauthorised: 'Die Berichte gehen an eine andere Domain, und diese veröffentlicht nicht den Eintrag, mit dem sie dem zustimmt (RFC 7489 §7.1). Regelkonforme Empfänger senden gar nichts. Der DMARC-Eintrag sieht makellos aus, die Berichte kommen nie an — und das wird fast immer damit erklärt, dass Berichte „eine Weile brauchen".',

  flag_mtasts_missing: 'Keine MTA-STS-Richtlinie',
  fd_mtasts_missing: 'STARTTLS ist opportunistisch: Ein Absender, der das Angebot nicht sieht, sendet im Klartext, und dieses Angebot zu entfernen ist für jeden zwischen den beiden Servern leicht. MTA-STS veröffentlicht über HTTPS, dass diese Domain immer TLS spricht — womit der Angriff verlangt, stattdessen die Web-PKI zu brechen.',

  flag_mtasts_multiple_records: 'Mehr als ein MTA-STS-TXT-Eintrag',
  fd_mtasts_multiple_records: 'Absender können nicht erkennen, welche Kennung aktuell ist, die Richtlinie wird bei einer Änderung womöglich nicht aufgefrischt.',

  flag_mtasts_no_id: 'Der MTA-STS-Eintrag hat keine Kennung',
  fd_mtasts_no_id: 'An der Kennung erkennt ein Absender, dass seine Kopie der Richtlinie veraltet ist. Ohne sie wird eine geänderte Richtlinie vielleicht erst nach Ablauf von max_age übernommen.',

  flag_mtasts_policy_host_missing: 'Der Richtlinien-Host löst nicht auf',
  fd_mtasts_policy_host_missing: 'Der TXT-Eintrag kündigt eine Richtlinie an, und mta-sts.<domain> hat keine Adresse — kein Absender kann sie also holen.',

  flag_mtasts_policy_host_private: 'Der Richtlinien-Host löst in privaten Adressraum auf',
  fd_mtasts_policy_host_private: 'Die Richtlinie wurde nicht geholt: Der Host zeigt auf eine Adresse, zu der dieser Dienst keine Verbindung aufbaut.',

  flag_mtasts_policy_unreachable: 'Die MTA-STS-Richtlinie ließ sich nicht holen',
  fd_mtasts_policy_unreachable: 'Der TXT-Eintrag verspricht eine Richtlinie, die nicht da ist, oder deren Zertifikat nicht validiert. Da der ganze Mechanismus auf diesem HTTPS-Zertifikat ruht, bedeutet ein Fehler hier, dass Absender auf opportunistisches TLS zurückfallen.',

  flag_mtasts_policy_wrong_content_type: 'Die Richtlinie wird nicht als text/plain ausgeliefert',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 verlangt text/plain. Strenge Absender weisen sie zurück.',

  flag_mtasts_policy_bad_version: 'Die Version der Richtlinie ist nicht STSv1',
  fd_mtasts_policy_bad_version: 'Absender verwenden keine Richtlinie, deren Version sie nicht kennen.',

  flag_mtasts_policy_bad_mode: 'Der Modus der Richtlinie ist kein anerkannter Wert',
  fd_mtasts_policy_bad_mode: 'mode muss enforce, testing oder none sein.',

  flag_mtasts_mode_testing: 'MTA-STS steht im Testmodus',
  fd_mtasts_mode_testing: 'Fehlschläge werden gemeldet und die Post wird trotzdem zugestellt — die Richtlinie schützt also noch nichts. Eine Zwischenstation, kein Ziel.',

  flag_mtasts_mode_none: 'MTA-STS ist durch die eigene Richtlinie abgeschaltet',
  fd_mtasts_mode_none: 'mode=none zieht die Richtlinie zurück. Das gibt es, damit eine Domain MTA-STS geordnet aufgeben kann; stehen gelassen heißt es schlicht, dass der Eintrag nichts tut.',

  flag_mtasts_no_max_age: 'Die Richtlinie hat kein max_age',
  fd_mtasts_no_max_age: 'max_age ist Pflicht, und es ist das, was die Richtlinie gegen Unterdrückung widerstandsfähig macht: Ein Absender, der sie zwischengespeichert hat, wendet sie weiter an.',

  flag_mtasts_max_age_short: 'Die Richtlinie wird weniger als einen Tag vorgehalten',
  fd_mtasts_max_age_short: 'Ein kurzes max_age verengt das Fenster, in dem eine zwischengespeicherte Richtlinie einen Absender schützt. Einige Wochen sind üblich, sobald die Richtlinie stabil ist.',

  flag_mtasts_mx_not_in_policy: 'In der Richtlinie fehlt ein echter Mailserver',
  fd_mtasts_mx_not_in_policy: 'Im MX-Satz steht ein Host, auf den kein mx:-Muster der Richtlinie passt. Jeder Absender, der diese Richtlinie durchsetzt, wird die Zustellung an diesen Host verweigern — die Post scheitert also gerade bei denen, die sorgfältig sind.',

  flag_mtasts_policy_lists_unknown_mx: 'Die Richtlinie nennt Muster, auf die kein aktueller MX passt',
  fd_mtasts_policy_lists_unknown_mx: 'Harmlos, und meist ein Rest aus einem Umzug. Es lohnt sich aufzuräumen, damit die Richtlinie weiter die Wirklichkeit beschreibt.',

  flag_mtasts_policy_no_mx: 'Die Richtlinie nennt keinen einzigen Mailserver',
  fd_mtasts_policy_no_mx: 'Eine Richtlinie ohne mx:-Einträge passt auf nichts — Absender, die sie durchsetzen, haben also nirgendwohin zuzustellen.',

  flag_tlsrpt_missing: 'Kein TLS-RPT-Eintrag',
  fd_tlsrpt_missing: 'Ein TXT-Eintrag, und die einzige Möglichkeit zu erfahren, dass Absender TLS mit Ihren Servern nicht aushandeln können. Ohne ihn sind ein abgelaufenes Zertifikat oder ein kaputtes STARTTLS von Ihrer Seite aus unsichtbar.',

  flag_tlsrpt_no_rua: 'Der TLS-RPT-Eintrag hat kein Ziel',
  fd_tlsrpt_no_rua: 'Ohne rua= haben die Berichte kein Ziel, der Eintrag tut also nichts.',

  flag_dane_missing: 'Keine DANE-Einträge',
  fd_dane_missing: 'TLSA-Einträge legen fest, welches Zertifikat ein Mailserver vorlegen muss, und stützen sich dabei auf DNSSEC statt auf die öffentlichen Zertifizierungsstellen. Es ist der stärkere der beiden Transportmechanismen — und er verlangt eine signierte Zone, was meist der Grund ist, warum er nicht im Einsatz ist.',

  flag_dane_partial: 'Nur ein Teil der Mailserver hat DANE-Einträge',
  fd_dane_partial: 'Absender wählen einen Server nach Priorität; ein Satz, in dem nur manche Hosts festgelegt sind, ist also nur einen Teil der Zeit geschützt.',

  flag_dane_without_dnssec: 'Ein TLSA-Eintrag in einer unsignierten Zone',
  fd_dane_without_dnssec: 'DANE ruht vollständig auf DNSSEC. Ohne Signaturen kann jeder, der den MX-Eintrag ersetzen kann, auch den TLSA-Eintrag ersetzen — die Festlegung schützt also nichts, sieht aber so aus.',

  flag_dane_mismatch: 'Der TLSA-Eintrag passt nicht zum vorgelegten Zertifikat',
  fd_dane_mismatch: 'Der Server legt ein Zertifikat vor, das sein eigener DANE-Eintrag nicht erlaubt. Jeder Absender, der DANE prüft, verweigert die Zustellung — das hält die Post an.',

  flag_dane_pkix_usage: 'Ein TLSA-Eintrag nutzt einen PKIX-Modus',
  fd_dane_pkix_usage: 'Die Verwendungen 0 und 1 verlangen zusätzlich, dass das Zertifikat auch über die öffentlichen Stellen validiert. RFC 7672 §3.1 verbietet beide für SMTP, weil es dafür bei E-Mail kein vereinbartes Verfahren gibt.',

  flag_dane_full_certificate: 'Ein TLSA-Eintrag legt das ganze Zertifikat fest',
  fd_dane_full_certificate: 'Abgleichtyp 0 speichert das vollständige Zertifikat statt eines Hashwerts. Das funktioniert, macht den Eintrag groß und erzwingt einen Austausch bei jeder Erneuerung.',

  flag_port_25_blocked_from_here: 'Der ausgehende Port 25 ist dort gesperrt, wo dieser Dienst läuft',
  fd_port_25_blocked_from_here: 'Das betrifft unser Netz, nicht Ihres. Die meisten Hoster sperren ausgehende Verbindungen zu Port 25 standardmäßig. STARTTLS, der DANE-Abgleich mit einem echten Zertifikat und die Relay-Probe konnten daher nicht durchgeführt werden, und die Note wird zurückgehalten, statt aus dem berechnet zu werden, was zufällig erreichbar war.',

  flag_mx_not_reachable_on_25: 'Kein Mailserver hat auf Port 25 geantwortet',
  fd_mx_not_reachable_on_25: 'Die MX-Einträge nennen Hosts, die auf dem Port, über den Post zugestellt wird, keine Verbindung annehmen. An diese Domain lässt sich nichts zustellen.',

  flag_no_starttls: 'Ein Mailserver bietet kein STARTTLS an',
  fd_no_starttls: 'Jede an diesen Server zugestellte Nachricht quert das Internet unverschlüsselt und ist für alles auf dem Weg lesbar. STARTTLS anzubieten kostet ein Zertifikat und eine Zeile Konfiguration.',

  flag_starttls_fails: 'STARTTLS wird angeboten und funktioniert nicht',
  fd_starttls_fails: 'Der Server kündigt STARTTLS an, und der Handshake scheitert. Sorgfältige Absender weigern sich möglicherweise, auf Klartext zurückzufallen, und stellen die Post zurück — das ist also schlimmer, als es gar nicht anzubieten.',

  flag_starttls_legacy_protocol: 'Der Mailserver handelt eine veraltete TLS-Version aus',
  fd_starttls_legacy_protocol: 'TLS 1.0 und 1.1 sind seit RFC 8996 abgekündigt. Absender ziehen die Unterstützung nach und nach zurück, und wenn sie es tun, kommt keine Post mehr an.',

  flag_mx_certificate_not_trusted: 'Das Zertifikat des Mailservers validiert nicht',
  fd_mx_certificate_not_trusted: 'Gewöhnliches opportunistisches TLS prüft keine Zertifikate, das verhindert die Zustellung heute also nicht. Es verhindert sie vollständig, sobald MTA-STS im Modus enforce oder DANE ins Spiel kommt.',

  flag_banner_reveals_version: 'Die Begrüßung nennt Software und Version',
  fd_banner_reveals_version: 'Ein kleines Geschenk an jeden, der nach Hosts mit einem bekannten Fehler in genau dieser Version sucht. In der Begrüßung kann alles Mögliche stehen.',

  flag_open_relay: 'Der Server leitet Post für Fremde weiter',
  fd_open_relay: 'Er hat eine Nachricht von einem unbeteiligten Absender an einen unbeteiligten Empfänger angenommen. Jeder kann ihn benutzen, um in Ihrem Namen Spam zu verschicken, und er steht binnen Stunden auf Sperrlisten, falls nicht schon. Das repariert man heute. (Die Probe hielt bei RCPT TO an und schickte RSET — es wurde keine Nachricht versendet.)',

  flag_no_size_extension: 'Der Server kündigt SIZE nicht an',
  fd_no_size_extension: 'Ohne SIZE kann ein Absender nicht wissen, ob eine große Nachricht angenommen wird, bevor er sie vollständig übertragen hat.',

  flag_submission_without_starttls: 'Der Einlieferungsport bietet kein STARTTLS an',
  fd_submission_without_starttls: 'Port 587 ist der Ort, an dem sich Mailprogramme anmelden. Ohne STARTTLS queren diese Zugangsdaten das Netz im Klartext.',

  flag_rdns_missing: 'Eine Mailserver-Adresse hat keinen PTR-Eintrag',
  fd_rdns_missing: 'Fehlendes Reverse-DNS ist einer der häufigsten Gründe, warum Post von einem neuen Server zurückgestellt oder als Spam einsortiert wird — und einer der am seltensten erklärten auf der Empfängerseite.',

  flag_rdns_not_confirmed: 'Das Reverse-DNS löst nicht zurück auf',
  fd_rdns_not_confirmed: 'Der PTR-Eintrag liefert einen Namen, und dieser Name löst nicht auf diese Adresse auf. Empfänger prüfen den Rückweg gerade deshalb, weil er verlangt, dass zwei verschiedene Parteien ihren Teil getan haben.',

  flag_rdns_none_confirmed: 'Kein Mailserver hat bestätigtes Reverse-DNS',
  fd_rdns_none_confirmed: 'Nicht eine einzige Adresse besteht die Hin-und-zurück-Prüfung. Rechnen Sie mit Zustellverzögerungen und Spam-Einsortierung bei Empfängern, die das gewichten.',
};

OWN.uk = {
  title: 'Перевірка пошти — SPF, DKIM, DMARC, MTA-STS і DANE для будь-якого домену',
  title_short: 'Перевірка пошти',
  h1: 'Перевірка пошти',
  subtitle: 'SPF розкривається через усі include і звіряється з лімітом у десять запитів, вирівнювання і звітність DMARC, транспортний захист перевіряється на живому зʼєднанні',
  ph_host: 'example.com',
  hero_label: 'Домен, який перевіряють',
  empty_hint: 'Введіть доменне імʼя. Перевірка розкриває запис SPF через кожен include, перебирає селектори DKIM, якими користуються великі платформи, читає політику DMARC, забирає політику MTA-STS через HTTPS і відкриває SMTP-сесії до поштових серверів лише на читання. Жодного листа при цьому не надсилається.',

  stage_resolve: 'пошук поштових серверів',
  stage_mx: 'перевірка набору MX',
  stage_spf: 'розкриття SPF',
  stage_dkim: 'пошук ключів DKIM',
  stage_dmarc: 'читання політики DMARC',
  stage_mtasts: 'завантаження політики MTA-STS',
  stage_dane: 'перевірка DANE',
  stage_starttls: 'розмова з поштовими серверами',
  stage_grade: 'виставлення оцінки',

  card_grade: 'З чого склалася оцінка',
  card_mx: 'Поштові сервери',
  card_spf: 'SPF',
  card_spf_tree: 'Розкриття SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Захист транспорту',
  card_sessions: 'SMTP-сесії',
  card_rdns: 'Зворотний DNS',

  comp_authentication: 'Автентифікація',
  comp_transport: 'Транспорт',
  comp_hygiene: 'Гігієна',

  k_mx_count: 'Записів MX',
  k_null_mx: 'Null MX',
  k_ipv6_mx: 'Доступні через IPv6',
  k_spf_record: 'Запис',
  k_spf_lookups: 'Витрачено DNS-запитів',
  k_spf_voids: 'Порожніх запитів',
  k_spf_policy: 'Що робити з усіма іншими',
  k_dkim_keys: 'Знайдено ключів',
  k_dkim_tried: 'Перебрано селекторів',
  k_dkim_strongest: 'Найсильніший ключ',
  k_dmarc_policy: 'Політика',
  k_dmarc_subdomain: 'Політика для піддоменів',
  k_dmarc_percent: 'Застосовується до',
  k_dmarc_alignment: 'Вирівнювання (DKIM / SPF)',
  k_dmarc_rua: 'Зведені звіти на',
  k_dmarc_ruf: 'Звіти про збої на',
  k_dmarc_external: 'Зовнішню звітність дозволено',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Режим',
  k_mtasts_id: 'Ідентифікатор політики',
  k_mtasts_maxage: 'Кешується на',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Покрито серверів',
  k_starttls: 'STARTTLS',
  k_port25: 'Вихідний порт 25',
  k_open_relay: 'Відкритий релей',
  k_rdns_confirmed: 'Підтверджено прямим запитом',
  k_queries: 'Зроблено запитів',

  th_priority: 'Пріоритет',
  th_host: 'Хост',
  th_addresses: 'Адреси',
  th_port: 'Порт',
  th_tls: 'TLS',
  th_banner: 'Привітання',
  th_extensions: 'Оголошено',
  th_selector: 'Селектор',
  th_key_type: 'Ключ',
  th_bits: 'Біт',
  th_state: 'Стан',
  th_address: 'Адреса',
  th_ptr: 'PTR',
  th_confirmed: 'Підтверджений',
  th_term: 'Терм',
  th_lookup: 'Запит',

  pol_none: 'none — лише спостереження',
  pol_quarantine: 'quarantine — у спам',
  pol_reject: 'reject — відхиляти',
  spfp_pass: 'пропускати всіх (+all)',
  spfp_fail: 'відхиляти (-all)',
  spfp_softfail: 'мʼяка відмова (~all)',
  spfp_neutral: 'нейтрально (?all)',
  spfp_redirect: 'делеговано через redirect',
  spfterm_no_target: 'немає цілі',
  spfterm_loop: 'цикл — уже відвідували',
  spfterm_lookup_failed: 'запит не вдався',
  spfterm_no_spf_record: 'там немає запису SPF',

  stsmode_enforce: 'enforce — застосовувати',
  stsmode_testing: 'testing — лише звіти',
  stsmode_none: 'none — вимкнено',
  rdns_confirmed: 'підтверджений',
  rdns_unconfirmed: 'не розвʼязується назад',
  rdns_missing: 'немає PTR',
  rdns_unknown: 'не перевірялося',
  v_of_limit: '{used} з {limit}',
  v_percent: '{n} %',
  v_days_short: '{n} дн.',
  v_blocked_here: 'закритий з нашої мережі',
  v_no_selector_found: 'жодного з {n} відомих селекторів',

  note_spf: 'RFC 7208 дозволяє десять термінів із DNS-запитами на всю перевірку, рахуючи всередині кожного include кожен вкладений include. За десятим одержувач зобовʼязаний повернути permerror — а permerror означає, що SPF не застосовується взагалі, так само, ніби запису не було.',
  note_dmarc: 'За p=none не застосовується нічого: лист, який не пройшов вирівнювання ні за SPF, ні за DKIM, доставляється як раніше. Це правильне місце, щоб почати, і неправильне, щоб залишитися.',
  note_transport: 'STARTTLS необовʼязковий: відправник, у якого вирізали оголошення про шифрування, просто продовжить відкритим текстом. MTA-STS і DANE — це те, що перетворює можливість на гарантію.',
  note_sessions: 'Усі сесії лише на читання. Перевірка релея зупиняється на RCPT TO і надсилає RSET; команда DATA не видається ніколи, тож надіслати листа неможливо.',
  note_rdns: 'Сам по собі запис PTR нічого не доводить — власник блоку адрес може написати там будь-яке імʼя. Одержувачі перевіряють, чи розвʼязується це імʼя назад у ту саму адресу.',

  err_smtp_timeout: 'Поштовий сервер не відповів вчасно.',
  err_smtp_network: 'До поштового сервера не вдалося достукатися.',
  err_smtp_refused: 'Поштовий сервер відхилив зʼєднання.',
  err_tls_failed: 'Рукостискання TLS із поштовим сервером не вдалося.',

  inc_mx_lookup_failed: 'не вдалося прочитати записи MX',
  inc_spf_lookup_failed: 'не вдалося прочитати запис SPF',
  inc_dmarc_lookup_failed: 'не вдалося прочитати запис DMARC',
  inc_port_25_unreachable_from_this_network: 'вихідний порт 25 закритий там, де працює сервіс, тому STARTTLS, звірку DANE з живим сертифікатом і перевірку релея зробити не вдалося',
  inc_not_every_mx_was_probed: 'підключалися лише до серверів із найвищим пріоритетом',

  cap_open_relay: 'сервер пересилає пошту для сторонніх',
  cap_spf_authorises_everyone: 'SPF дозволяє надсилання всьому інтернету',
  cap_no_mail_servers: 'немає поштових серверів',
  cap_mail_servers_unreachable: 'жоден поштовий сервер не відповів на порту 25',
  cap_dane_mismatch: 'DANE не збігається з наданим сертифікатом',
  cap_mtasts_policy_contradicts_dns: 'у політиці MTA-STS бракує справжнього поштового сервера',
  cap_spf_over_the_lookup_limit: 'SPF вийшов за ліміт запитів',
  cap_spf_permerror: 'SPF — постійна помилка',
  cap_dmarc_permerror: 'DMARC — постійна помилка',
  cap_mail_in_the_clear: 'пошта приймається без шифрування',
  cap_no_spf: 'немає запису SPF',
  cap_no_dmarc: 'немає запису DMARC',
  cap_starttls_broken: 'STARTTLS пропонується і не працює',
  cap_dmarc_not_enforcing: 'DMARC нічого не застосовує',
  cap_no_reverse_dns: 'немає підтвердженого зворотного DNS',
  cap_spf_without_a_default: 'у SPF немає значення за умовчанням',
  cap_weak_dkim_key: 'закороткий ключ DKIM',
  cap_dmarc_reports_go_nowhere: 'звіти DMARC не дозволені одержувачем',
  cap_mail_server_does_not_resolve: 'поштовий сервер не розвʼязується в адресу',
  cap_scan_incomplete: 'перевірка неповна, тому оцінку не виставлено',

  flag_null_mx: 'Домен оголошує, що поштою не займається',
  fd_null_mx: 'Єдиний запис MX із пріоритетом 0, що вказує на корінь, — це описаний у RFC 7505 спосіб сказати, що домен не надсилає і не приймає пошту. Свідоме рішення, і значно краще, ніж повна відсутність MX: без нього відправники відкочуються на A-запис.',

  flag_no_mx: 'Немає записів MX',
  fd_no_mx: 'Ніщо не говорить, куди доставляти пошту для цього домену, і адресного запису для відкату теж немає, тож доставити листа просто нікуди.',

  flag_no_mx_falls_back_to_a: 'Записів MX немає, відправники відкочуються на запис A',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 наказує відправнику без MX пробувати адресний запис. Пошта для домену піде на те, що слухає порт 25 у вебсервера, — а цього майже ніколи не хотіли.',

  flag_duplicate_mx_host: 'Той самий хост указано двічі',
  fd_duplicate_mx_host: 'Один хост трапляється з різними пріоритетами. Це не резервування, а та сама машина, до якої спробують двічі.',

  flag_mx_does_not_resolve: 'Імʼя поштового сервера не розвʼязується',
  fd_mx_does_not_resolve: 'MX вказує на хост без адресних записів. Кожен відправник, що дійшов до цього пріоритету, чекає відповіді, не отримує нічого і йде далі — затримуючи пошту, яка мала прийти одразу.',

  flag_mx_points_at_cname: 'Запис MX вказує на псевдонім',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 вимагає, щоб MX називав хост з адресними записами, а не CNAME. Частина відправників дає раду, частина відмовляється, і склад цих частин з часом змінюється.',

  flag_single_mx: 'Єдиний поштовий сервер',
  fd_single_mx: 'З одним MX будь-яка недоступність означає, що відправники накопичують листи в черзі й повторюють спроби — годинами або добами, за власною політикою, — і частина цієї пошти зрештою повернеться відправнику.',

  flag_no_ipv6_mx: 'Жоден поштовий сервер недоступний через IPv6',
  fd_no_ipv6_mx: 'Відправники в IPv6-only мережах дістануться домену через трансляцію, якщо дістануться взагалі.',

  flag_spf_missing: 'Немає запису SPF',
  fd_spf_missing: 'Ніщо не говорить, які сервери мають право надсилати пошту від імені домену, тож і звіряти нема з чим. SPF — це один TXT-запис і найдешевше з усього, що є на цій сторінці.',

  flag_spf_multiple_records: 'Більше одного запису SPF',
  fd_spf_multiple_records: 'RFC 7208 §4.5 робить два записи постійною помилкою, а permerror означає відсутність результату SPF узагалі — прямо протилежне тому, заради чого додавали другий. Їх треба обʼєднати в один.',

  flag_spf_too_many_lookups: 'SPF потребує більше ніж десять DNS-запитів',
  fd_spf_too_many_lookups: 'Ліміт у RFC 7208 §4.6.4 — десять термінів, що звертаються до DNS, на всю перевірку, рахуючи всередині кожного include кожен вкладений include. За ним одержувач зобовʼязаний повернути permerror, і SPF перестає застосовуватися — запису з тим самим успіхом могло не бути. Вийти за ліміт легко, додавши ще одного провайдера, і за самим записом цього зовсім не видно.',

  flag_spf_lookups_near_limit: 'SPF близький до ліміту в десять запитів',
  fd_spf_lookups_near_limit: 'Запасу майже не лишилося. Наступний доданий сервіс — або зміна всередині чужого include, яким ви не керуєте, — виведе запис за ліміт.',

  flag_spf_too_many_void_lookups: 'Забагато запитів SPF повертають порожнечу',
  fd_spf_too_many_void_lookups: 'RFC 7208 допускає два запити, що не дали нічого; понад це — постійна помилка. Зазвичай це забутий include для сервісу, яким більше не користуються.',

  flag_spf_no_all: 'У SPF немає значення за умовчанням',
  fd_spf_no_all: 'Без механізму «all» і без redirect відправник, який не збігся ні з чим, отримує нейтральний результат — тобто те саме, що відсутність думки.',

  flag_spf_plus_all: 'SPF дозволяє надсилання всьому інтернету',
  fd_spf_plus_all: '«+all» каже, що надсилати від імені домену може будь-який хост будь-де. Це майже завжди нерозуміння того, що означає кваліфікатор, і це гірше за відсутність SPF: запис прямо ручається за того, хто підробляє.',

  flag_spf_neutral_all: 'SPF закінчується на ?all',
  fd_spf_neutral_all: '«?all» прямо відмовляється щось казати про відправників, які не збіглися ні з чим. Одержувачі трактують це як відсутність результату.',

  flag_spf_softfail_all: 'SPF закінчується на ~all, а не на -all',
  fd_spf_softfail_all: 'Мʼяка відмова просить одержувачів прийняти листа, але позначити. Це правильне налаштування, поки ви ще зʼясовуєте, хто надсилає від вашого імені, і те, що варто затягнути, коли зʼясували.',

  flag_spf_uses_ptr: 'SPF використовує механізм ptr',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 оголошує ptr застарілим: він повільний, ненадійний і перекладає роботу на того, хто тримає зворотну зону. Частина одержувачів ігнорує його повністю.',

  flag_spf_unknown_mechanism: 'У SPF є термін, якого ніхто не розуміє',
  fd_spf_unknown_mechanism: 'Нерозпізнаний механізм за RFC 7208 §4.6.1 — постійна помилка, що відкидає весь запис цілком. Зазвичай це друкарська помилка.',

  flag_spf_duplicate_redirect: 'Більше одного модифікатора redirect',
  fd_spf_duplicate_redirect: 'Другий redirect робить запис постійною помилкою.',

  flag_spf_redirect_after_all: 'Redirect, до якого ніколи не дійдуть',
  fd_spf_redirect_after_all: 'У записі є і механізм «all», і redirect. «all» збігається завжди, тож обчислення зупиняється на ньому, а redirect лишається мертвим текстом.',

  flag_spf_record_long: 'Запис SPF довгий',
  fd_spf_record_long: 'Довгі записи під час передавання розбиваються на кілька рядків. Саме собою це нормально — одержувачі склеюють їх без роздільника, — але саме тут парсери, що зʼєднують їх пробілом, починають псувати запис.',

  flag_spf_include_loop: 'Include вказує на те, де вже були',
  fd_spf_include_loop: 'Розкриття зациклюється. Одержувач дійде до ліміту запитів і поверне постійну помилку.',

  flag_spf_include_without_record: 'Include вказує на домен без запису SPF',
  fd_spf_include_without_record: 'RFC 7208 §5.2 вважає це постійною помилкою, а не просто змарнованим запитом. Зазвичай це сервіс, який прибрали з одного боку і не прибрали з іншого.',

  flag_dkim_no_known_selector: 'На жодному відомому нам селекторі ключа DKIM немає',
  fd_dkim_no_known_selector: 'Селектор обирає той, хто підписує, і видно його лише в заголовку підписаного листа, тож зовні перебрати їх не можна. Це не доказ відсутності DKIM — якщо ви знаєте свій селектор, передайте його через ?selector=, і перевірка стане однозначною.',

  flag_dkim_key_revoked: 'Ключ DKIM відкликано',
  fd_dkim_key_revoked: 'Запис опубліковано з порожнім p=, що відкликає ключ. Це правильний спосіб вивести ключ з обігу — і запис, що лишився в такому вигляді на місяці, зазвичай означає незавершену зміну ключа.',

  flag_dkim_key_malformed: 'Ключ DKIM не розбирається',
  fd_dkim_key_malformed: 'Значення p= не розбирається як ключ. Будь-який підпис, зроблений ним, перевірку не пройде.',

  flag_dkim_in_test_mode: 'Запис DKIM у тестовому режимі',
  fd_dkim_in_test_mode: 't=y просить одержувачів ставитися до невірного підпису так, ніби DKIM не використовується. Місце такому прапорцю — під час впровадження і більше ніде.',

  flag_dkim_key_too_short: 'Ключ DKIM коротший за 1024 біти',
  fd_dkim_key_too_short: 'Нижче 1024 бітів підпис підробити не так уже й важко, і багато одержувачів просто ігнорують такі ключі.',

  flag_dkim_key_1024_bit: 'Ключ DKIM на 1024 біти',
  fd_dkim_key_1024_bit: 'Поки приймається всюди і нижче за поточні рекомендації. Нормальний розмір — 2048; зміна зводиться до нового селектора і DNS-запису.',

  flag_dmarc_missing: 'Немає запису DMARC',
  fd_dmarc_missing: 'Без DMARC результати SPF і DKIM мають дорадчий характер: ніщо не повʼязує їх з адресою, яку бачить читач, і ніщо не каже одержувачам, що робити за розбіжності.',

  flag_dmarc_inherited: 'DMARC успадковано від батьківського домену',
  fd_dmarc_inherited: 'У цього імені власного запису немає, тож діє політика організаційного домену — його sp=, якщо задано, інакше p=.',

  flag_dmarc_multiple_records: 'Більше одного запису DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: за кількох записів політика відкидається цілком, ніби її не публікували.',

  flag_dmarc_no_policy: 'У записі DMARC немає тега p=',
  fd_dmarc_no_policy: 'Тег p= обовʼязковий. Без нього запис ігнорується.',

  flag_dmarc_invalid_policy: 'Значення політики DMARC не розпізнано',
  fd_dmarc_invalid_policy: 'p= має бути none, quarantine або reject. За будь-якого іншого значення одержувачі відкидають запис.',

  flag_dmarc_policy_none: 'DMARC нічого не застосовує',
  fd_dmarc_policy_none: 'p=none просить одержувачів надсилати звіти й нічого не змінювати. Лист, який не пройшов вирівнювання ні за SPF, ні за DKIM, доставляється рівно так само, як без DMARC. Це правильний спосіб почати — і дуже багато доменів сидять так роками, вважаючи себе захищеними.',

  flag_dmarc_policy_quarantine: 'DMARC відправляє в карантин, а не відхиляє',
  fd_dmarc_policy_quarantine: 'Пошта, що не пройшла перевірку, потрапляє в теку зі спамом, а не відхиляється. Розумний крок на шляху до reject — і місце, де підроблені листи все ще доходять до людей.',

  flag_dmarc_subdomain_policy_none: 'Піддомени виведено з-під політики',
  fd_dmarc_subdomain_policy_none: 'sp=none лишає будь-який піддомен — включно з тими, яких ніколи не існувало, — доступним для підробки, тоді як сам домен захищено.',

  flag_dmarc_partial_percentage: 'Політика застосовується лише до частини пошти',
  fd_dmarc_partial_percentage: 'pct= менше за 100 каже одержувачам застосовувати політику до цієї частки невдалих листів, а з рештою поводитися мʼякше. Корисно під час впровадження і лишається дірою весь той час, поки стоїть.',

  flag_dmarc_no_reporting: 'Не вказано адреси для зведених звітів',
  fd_dmarc_no_reporting: 'Без rua= звітів не буде, а отже, не буде й способу дізнатися, хто надсилає від імені вашого домену і що зламається, якщо політику затягнути.',

  flag_dmarc_external_reporting_unauthorised: 'Зовнішня адреса для звітів вас не авторизувала',
  fd_dmarc_external_reporting_unauthorised: 'Звіти спрямовані в інший домен, а той не публікує запису, яким погоджується їх приймати (RFC 7489 §7.1). Одержувачі, що дотримуються стандарту, не надішлють нічого. Запис DMARC при цьому виглядає бездоганно, а звіти не приходять — і це майже завжди списують на те, що «звіти йдуть не одразу».',

  flag_mtasts_missing: 'Немає політики MTA-STS',
  fd_mtasts_missing: 'STARTTLS необовʼязковий: якщо відправник не побачив, що сервер оголошує шифрування, він надішле лист відкритим текстом, — а прибрати це оголошення з відповіді може будь-хто, хто стоїть між серверами. MTA-STS викладає через HTTPS політику: домен завжди приймає пошту по TLS. Щоб обійти її, атакувальникові доведеться ламати вже не один рядок у діалозі, а веб-PKI.',

  flag_mtasts_multiple_records: 'Більше одного TXT-запису MTA-STS',
  fd_mtasts_multiple_records: 'Відправники не можуть зрозуміти, який ідентифікатор актуальний, тож політика може не оновитися при зміні.',

  flag_mtasts_no_id: 'У записі MTA-STS немає ідентифікатора',
  fd_mtasts_no_id: 'Ідентифікатор — це те, за чим відправник розуміє, що його копія політики застаріла. Без нього змінена політика може не підхопитися, доки не спливе max_age.',

  flag_mtasts_policy_host_missing: 'Хост політики не розвʼязується',
  fd_mtasts_policy_host_missing: 'TXT-запис оголошує політику, а в mta-sts.<домен> немає адреси, тож забрати її не зможе жоден відправник.',

  flag_mtasts_policy_host_private: 'Хост політики розвʼязується в приватну адресу',
  fd_mtasts_policy_host_private: 'Політику не завантажували: хост указує на адресу, до якої сервіс не підключається.',

  flag_mtasts_policy_unreachable: 'Політику MTA-STS не вдалося завантажити',
  fd_mtasts_policy_unreachable: 'TXT-запис обіцяє політику, якої там немає, або сертифікат хоста політики не проходить перевірку. Оскільки весь механізм тримається на цьому сертифікаті HTTPS, збій тут означає, що відправники відкотяться на необовʼязкове шифрування.',

  flag_mtasts_policy_wrong_content_type: 'Політика віддається не як text/plain',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 вимагає text/plain. Суворі відправники таку політику відхилять.',

  flag_mtasts_policy_bad_version: 'Версія політики не STSv1',
  fd_mtasts_policy_bad_version: 'Відправники не використовуватимуть політику, версії якої не розуміють.',

  flag_mtasts_policy_bad_mode: 'Режим політики не розпізнано',
  fd_mtasts_policy_bad_mode: 'mode має бути enforce, testing або none.',

  flag_mtasts_mode_testing: 'MTA-STS у тестовому режимі',
  fd_mtasts_mode_testing: 'Про збої повідомляється, пошта все одно доставляється, тобто політика поки нічого не захищає. Проміжна станція, а не кінцева.',

  flag_mtasts_mode_none: 'MTA-STS вимкнено власною політикою',
  fd_mtasts_mode_none: 'mode=none відкликає політику. Так передбачено акуратний вивід MTA-STS з обігу; залишений на місці, він просто означає, що запис нічого не робить.',

  flag_mtasts_no_max_age: 'У політиці немає max_age',
  fd_mtasts_no_max_age: 'max_age обовʼязковий, і саме він робить політику стійкою до придушення: відправник, що встиг її закешувати, продовжить її застосовувати.',

  flag_mtasts_max_age_short: 'Політика кешується менше ніж добу',
  fd_mtasts_max_age_short: 'Короткий max_age звужує вікно, у якому закешована політика захищає відправника. Звичайний вибір для усталеної політики — кілька тижнів.',

  flag_mtasts_mx_not_in_policy: 'У політиці бракує справжнього поштового сервера',
  fd_mtasts_mx_not_in_policy: 'У наборі MX є хост, який не покриває жоден шаблон mx: з політики. Будь-який відправник, що застосовує цю політику, відмовиться доставляти на цей хост — тобто пошта ламається саме в тих відправників, які поводяться акуратно.',

  flag_mtasts_policy_lists_unknown_mx: 'У політиці є шаблони, під які не підходить жоден MX',
  fd_mtasts_policy_lists_unknown_mx: 'Нешкідливо і зазвичай лишилося від переїзду. Варто прибрати, щоб політика й далі описувала дійсність.',

  flag_mtasts_policy_no_mx: 'У політиці не перелічено жодного поштового сервера',
  fd_mtasts_policy_no_mx: 'Політика без записів mx: не підходить ні під що, тож відправникам, які її застосовують, доставляти нікуди.',

  flag_tlsrpt_missing: 'Немає запису TLS-RPT',
  fd_tlsrpt_missing: 'Один TXT-запис, і це єдиний спосіб дізнатися, що у відправників не виходить домовитися про TLS із вашими серверами. Без нього застарілий сертифікат або зламаний STARTTLS з вашого боку не видно взагалі.',

  flag_tlsrpt_no_rua: 'У записі TLS-RPT немає адреси призначення',
  fd_tlsrpt_no_rua: 'Без rua= звітам нікуди йти, тож запис нічого не робить.',

  flag_dane_missing: 'Немає записів DANE',
  fd_dane_missing: 'Записи TLSA задають, який сертифікат зобовʼязаний надати поштовий сервер, і спираються при цьому на DNSSEC, а не на публічні засвідчувальні центри. З двох транспортних механізмів цей сильніший — і він вимагає підписаної зони, що зазвичай і є причина, з якої його не використовують.',

  flag_dane_partial: 'Записи DANE є лише в частини поштових серверів',
  fd_dane_partial: 'Відправники обирають сервер за пріоритетом, тож набір, де закріплено лише частину хостів, захищений лише частину часу.',

  flag_dane_without_dnssec: 'Запис TLSA у непідписаній зоні',
  fd_dane_without_dnssec: 'DANE цілком тримається на DNSSEC. Без підписів той, хто здатен підмінити запис MX, підмінить і TLSA, тож закріплення нічого не захищає, хоча й виглядає так, ніби захищає.',

  flag_dane_mismatch: 'Запис TLSA не збігається з наданим сертифікатом',
  fd_dane_mismatch: 'Сервер надає сертифікат, якого його ж запис DANE не дозволяє. Будь-який відправник, що перевіряє DANE, відмовиться доставляти — це зупиняє пошту.',

  flag_dane_pkix_usage: 'У записі TLSA використано PKIX-режим',
  fd_dane_pkix_usage: 'Режими 0 і 1 вимагають, щоб сертифікат додатково проходив перевірку через публічні центри. RFC 7672 §3.1 забороняє обидва для SMTP, бо загальноприйнятого способу робити таку перевірку для пошти немає.',

  flag_dane_full_certificate: 'Запис TLSA закріплює сертифікат цілком',
  fd_dane_full_certificate: 'Тип зіставлення 0 зберігає весь сертифікат, а не хеш. Працює, робить запис великим і потребує заміни при кожному продовженні.',

  flag_port_25_blocked_from_here: 'Вихідний порт 25 закритий там, де працює сервіс',
  fd_port_25_blocked_from_here: 'Це про нашу мережу, не про вашу. Більшість хостерів закривають вихідні зʼєднання на порт 25 за умовчанням. Тому STARTTLS, звірку DANE з живим сертифікатом і перевірку релея зробити не вдалося, і оцінка не виставляється замість того, щоб рахуватися за тим, до чого дотягнулися.',

  flag_mx_not_reachable_on_25: 'Жоден поштовий сервер не відповів на порту 25',
  fd_mx_not_reachable_on_25: 'Записи MX називають хости, які не приймають зʼєднання на порту доставки пошти. Доставити в цей домен нічого не можна.',

  flag_no_starttls: 'Поштовий сервер не пропонує STARTTLS',
  fd_no_starttls: 'Кожен доставлений на цей сервер лист іде через інтернет незашифрованим і читається всім, що стоїть на шляху. Запропонувати STARTTLS коштує сертифіката і рядка конфігурації.',

  flag_starttls_fails: 'STARTTLS пропонується і не працює',
  fd_starttls_fails: 'Сервер оголошує STARTTLS, а рукостискання зривається. Акуратні відправники можуть відмовитися відкочуватися на відкритий текст і відкласти листа — тож це гірше, ніж не пропонувати STARTTLS зовсім.',

  flag_starttls_legacy_protocol: 'Поштовий сервер домовляється на застарілій версії TLS',
  fd_starttls_legacy_protocol: 'TLS 1.0 і 1.1 оголошено застарілими в RFC 8996. Відправники послідовно знімають їх підтримку, і коли знімуть — пошта перестане ходити.',

  flag_mx_certificate_not_trusted: 'Сертифікат поштового сервера не проходить перевірку',
  fd_mx_certificate_not_trusted: 'Сам по собі STARTTLS сертифікати не перевіряє, тож сьогодні доставці це не заважає. Заважати почне рівно тоді, коли зʼявиться MTA-STS у режимі enforce або DANE.',

  flag_banner_reveals_version: 'У привітанні названо програму і її версію',
  fd_banner_reveals_version: 'Невеликий подарунок тому, хто шукає хости з відомою помилкою саме в цій версії. У банері можна написати будь-що.',

  flag_open_relay: 'Сервер пересилає пошту для сторонніх',
  fd_open_relay: 'Він прийняв листа від стороннього відправника сторонньому одержувачу. Будь-хто може слати через нього спам від вашого імені, і він опиниться в чорних списках протягом доби, якщо вже не там. Лагодити це потрібно сьогодні ж. (Перевірка зупинилася на RCPT TO і надіслала RSET — жодного листа надіслано не було.)',

  flag_no_size_extension: 'Сервер не оголошує SIZE',
  fd_no_size_extension: 'Без SIZE відправник не може дізнатися, чи приймуть великий лист, поки не передасть його цілком.',

  flag_submission_without_starttls: 'Порт надсилання не пропонує STARTTLS',
  fd_submission_without_starttls: 'Порт 587 — це те місце, де поштові клієнти проходять автентифікацію. Без STARTTLS їхні облікові дані йдуть мережею відкритим текстом.',

  flag_rdns_missing: 'В адреси поштового сервера немає запису PTR',
  fd_rdns_missing: 'Відсутність зворотного DNS — одна з найчастіших причин, з яких пошту з нового сервера відкладають або кладуть у спам, і одна з тих, які одержувальна сторона пояснює найрідше.',

  flag_rdns_not_confirmed: 'Зворотний DNS не розвʼязується назад',
  fd_rdns_not_confirmed: 'Запис PTR дає імʼя, і це імʼя не розвʼязується в цю адресу. Одержувачі перевіряють саме круговий запит — якраз тому, що для його проходження свою частину роботи мають зробити дві різні сторони.',

  flag_rdns_none_confirmed: 'Жоден поштовий сервер не має підтвердженого зворотного DNS',
  fd_rdns_none_confirmed: 'Кругову перевірку не проходить жодна адреса. Чекайте затримок доставки і потрапляння в спам в одержувачів, які це враховують.',
};

OWN.tr = {
  title: 'Posta denetimi — herhangi bir alan adı için SPF, DKIM, DMARC, MTA-STS ve DANE',
  title_short: 'Posta denetimi',
  h1: 'Posta denetimi',
  subtitle: 'SPF her include boyunca açılır ve on sınırına karşı sayılır, DMARC hizalaması ve raporlaması, taşıma güvenliği ise gerçek bağlantı üzerinde denetlenir',
  ph_host: 'example.com',
  hero_label: 'Denetlenen alan adı',
  empty_hint: 'Bir alan adı girin. Denetim, SPF kaydını her include boyunca açar, büyük platformların kullandığı DKIM seçicilerini dener, DMARC ilkesini okur, MTA-STS ilkesini HTTPS üzerinden alır ve posta sunucularına yalnızca okuyan SMTP oturumları açar. Hiçbir zaman ileti gönderilmez.',

  stage_resolve: 'posta sunucuları aranıyor',
  stage_mx: 'MX kümesi denetleniyor',
  stage_spf: 'SPF açılıyor',
  stage_dkim: 'DKIM anahtarları aranıyor',
  stage_dmarc: 'DMARC ilkesi okunuyor',
  stage_mtasts: 'MTA-STS ilkesi alınıyor',
  stage_dane: 'DANE denetleniyor',
  stage_starttls: 'posta sunucularıyla konuşuluyor',
  stage_grade: 'not veriliyor',

  card_grade: 'Notun dökümü',
  card_mx: 'Posta sunucuları',
  card_spf: 'SPF',
  card_spf_tree: 'SPF açılımı',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'Taşıma güvenliği',
  card_sessions: 'SMTP oturumları',
  card_rdns: 'Ters DNS',

  comp_authentication: 'Kimlik doğrulama',
  comp_transport: 'Taşıma',
  comp_hygiene: 'Hijyen',

  k_mx_count: 'MX kayıtları',
  k_null_mx: 'Boş MX',
  k_ipv6_mx: 'IPv6 ile erişilebilir',
  k_spf_record: 'Kayıt',
  k_spf_lookups: 'Kullanılan DNS sorgusu',
  k_spf_voids: 'Boş dönen sorgu',
  k_spf_policy: 'Geri kalan herkes için varsayılan',
  k_dkim_keys: 'Bulunan anahtar',
  k_dkim_tried: 'Denenen seçici',
  k_dkim_strongest: 'En güçlü anahtar',
  k_dmarc_policy: 'İlke',
  k_dmarc_subdomain: 'Alt alan adları için ilke',
  k_dmarc_percent: 'Uygulandığı oran',
  k_dmarc_alignment: 'Hizalama (DKIM / SPF)',
  k_dmarc_rua: 'Toplu raporlar şuraya',
  k_dmarc_ruf: 'Ayrıntılı raporlar şuraya',
  k_dmarc_external: 'Dış raporlama yetkilendirilmiş',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'Kip',
  k_mtasts_id: 'İlke kimliği',
  k_mtasts_maxage: 'Saklanma süresi',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'Kapsanan sunucu',
  k_starttls: 'STARTTLS',
  k_port25: 'Giden 25 numaralı bağlantı noktası',
  k_open_relay: 'Açık aktarıcı',
  k_rdns_confirmed: 'Geri dönüşle doğrulanmış',
  k_queries: 'Yapılan sorgu',

  th_priority: 'Öncelik',
  th_host: 'Makine',
  th_addresses: 'Adresler',
  th_port: 'Bağlantı noktası',
  th_tls: 'TLS',
  th_banner: 'Karşılama',
  th_extensions: 'Duyurulan',
  th_selector: 'Seçici',
  th_key_type: 'Anahtar',
  th_bits: 'Bit',
  th_state: 'Durum',
  th_address: 'Adres',
  th_ptr: 'PTR',
  th_confirmed: 'Doğrulanmış',
  th_term: 'Terim',
  th_lookup: 'Sorgu',

  pol_none: 'none — yalnızca gözlem',
  pol_quarantine: 'quarantine — gereksiz klasörüne',
  pol_reject: 'reject — reddet',
  spfp_pass: 'herkesi geçir (+all)',
  spfp_fail: 'reddet (-all)',
  spfp_softfail: 'yumuşak başarısızlık (~all)',
  spfp_neutral: 'yansız (?all)',
  spfp_redirect: 'redirect ile devredilmiş',
  spfterm_no_target: 'hedefi yok',
  spfterm_loop: 'döngü — zaten uğranmış',
  spfterm_lookup_failed: 'sorgu başarısız',
  spfterm_no_spf_record: 'orada SPF kaydı yok',

  stsmode_enforce: 'enforce — uygula',
  stsmode_testing: 'testing — yalnızca rapor',
  stsmode_none: 'none — kapalı',
  rdns_confirmed: 'doğrulanmış',
  rdns_unconfirmed: 'geri çözümlenmiyor',
  rdns_missing: 'PTR yok',
  rdns_unknown: 'denetlenmedi',
  v_of_limit: '{limit} sorgunun {used} tanesi',
  v_percent: '%{n}',
  v_days_short: '{n} g',
  v_blocked_here: 'ağımızdan engelli',
  v_no_selector_found: 'bilinen {n} seçicinin hiçbiri',

  note_spf: 'RFC 7208, değerlendirmenin tamamında DNS sorgusu doğuran on terime izin verir; her include içindeki her include de sayılır. Onu aştığında alıcı permerror döndürmek zorundadır — ve permerror, SPF’in hiç uygulanmadığı anlamına gelir, tam olarak kayıt hiç yokmuş gibi.',
  note_dmarc: 'p=none ile hiçbir şey uygulanmaz: hem SPF hem DKIM hizalamasında başarısız olan bir ileti eskisi gibi teslim edilir. Başlamak için doğru, kalmak için yanlış yerdir.',
  note_transport: 'STARTTLS fırsatçıdır: teklifi elinden alınan bir gönderici düpedüz açık metinle devam eder. MTA-STS ve DANE, bu olasılığı bir güvenceye çeviren şeydir.',
  note_sessions: 'Bütün oturumlar salt okunurdur. Aktarma yoklaması RCPT TO’da durur ve RSET gönderir; hiçbir zaman DATA komutu verilmez, dolayısıyla hiçbir ileti gönderilemez.',
  note_rdns: 'Tek başına bir PTR kaydı hiçbir şey kanıtlamaz — bir adres bloğunun sahibi oraya istediği adı yazabilir. Alıcıların denetlediği şey, o adın aynı adrese geri çözümlenip çözümlenmediğidir.',

  err_smtp_timeout: 'Posta sunucusu zamanında yanıt vermedi.',
  err_smtp_network: 'Posta sunucusuna ulaşılamadı.',
  err_smtp_refused: 'Posta sunucusu bağlantıyı reddetti.',
  err_tls_failed: 'Posta sunucusuyla TLS el sıkışması başarısız oldu.',

  inc_mx_lookup_failed: 'MX kayıtları okunamadı',
  inc_spf_lookup_failed: 'SPF kaydı okunamadı',
  inc_dmarc_lookup_failed: 'DMARC kaydı okunamadı',
  inc_port_25_unreachable_from_this_network: 'bu hizmetin çalıştığı yerde giden 25 numaralı bağlantı noktası engelli, bu yüzden STARTTLS, DANE’in gerçek sertifikayla karşılaştırılması ve aktarma yoklaması yapılamadı',
  inc_not_every_mx_was_probed: 'yalnızca en yüksek öncelikli sunuculara bağlanıldı',

  cap_open_relay: 'sunucu yabancıların postasını aktarıyor',
  cap_spf_authorises_everyone: 'SPF bütün interneti yetkilendiriyor',
  cap_no_mail_servers: 'posta sunucusu yok',
  cap_mail_servers_unreachable: 'hiçbir posta sunucusu 25 numaralı bağlantı noktasında yanıt vermedi',
  cap_dane_mismatch: 'DANE sunulan sertifikayla eşleşmiyor',
  cap_mtasts_policy_contradicts_dns: 'MTA-STS ilkesi gerçek bir posta sunucusunu atlıyor',
  cap_spf_over_the_lookup_limit: 'SPF sorgu sınırını aşıyor',
  cap_spf_permerror: 'SPF kalıcı bir hata',
  cap_dmarc_permerror: 'DMARC kalıcı bir hata',
  cap_mail_in_the_clear: 'posta şifresiz kabul ediliyor',
  cap_no_spf: 'SPF kaydı yok',
  cap_no_dmarc: 'DMARC kaydı yok',
  cap_starttls_broken: 'STARTTLS sunuluyor ve çalışmıyor',
  cap_dmarc_not_enforcing: 'DMARC hiçbir şey uygulamıyor',
  cap_no_reverse_dns: 'doğrulanmış ters DNS yok',
  cap_spf_without_a_default: 'SPF’in varsayılanı yok',
  cap_weak_dkim_key: 'fazla kısa bir DKIM anahtarı',
  cap_dmarc_reports_go_nowhere: 'DMARC raporları yetkilendirilmemiş',
  cap_mail_server_does_not_resolve: 'bir posta sunucusu çözümlenmiyor',
  cap_scan_incomplete: 'denetim eksik kaldı, bu yüzden not verilmedi',

  flag_null_mx: 'Alan adı postayla ilgilenmediğini bildiriyor',
  fd_null_mx: 'Köke işaret eden 0 öncelikli tek bir MX, RFC 7505’in «bu alan adı posta göndermez ve almaz» ifadesidir. Bilinçli bir tercih ve hiç MX olmamasından çok daha iyi — MX yoksa göndericiler adres kaydına düşer.',

  flag_no_mx: 'MX kaydı yok',
  fd_no_mx: 'Bu alan adının postasının nereye gideceğini hiçbir şey söylemiyor ve geri düşülecek bir adres de yok, dolayısıyla teslim etmek düpedüz olanaksız.',

  flag_no_mx_falls_back_to_a: 'MX kaydı yok, göndericiler A kaydına düşüyor',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1, MX’i olmayan bir göndericiye adres kaydını denemesini söyler. Bu alan adının postası web sunucusunun 25 numaralı bağlantı noktasında ne dinliyorsa ona teslim edilecektir — ki bu nadiren kastedilen şeydir.',

  flag_duplicate_mx_host: 'Aynı makine iki kez listelenmiş',
  fd_duplicate_mx_host: 'Bir makine birden fazla öncelikte görünüyor. Bu yedeklilik değil; aynı makinenin iki kez denenmesidir.',

  flag_mx_does_not_resolve: 'Bir posta sunucusunun adı çözümlenmiyor',
  fd_mx_does_not_resolve: 'MX, adres kaydı olmayan bir makineyi adlandırıyor. Bu önceliğe ulaşan her gönderici sorguyu bekler, hiçbir şey alamaz ve devam eder — hemen ulaşması gereken postayı geciktirerek.',

  flag_mx_points_at_cname: 'Bir MX kaydı takma ada işaret ediyor',
  fd_mx_points_at_cname: 'RFC 2181 §10.3, bir MX’in CNAME değil adres kayıtları olan bir makineyi adlandırmasını ister. Kimi göndericiler idare eder, kimileri reddeder ve hangisinin ne yaptığı zamanla değişir.',

  flag_single_mx: 'Yalnızca bir posta sunucusu',
  fd_single_mx: 'Tek bir MX ile herhangi bir kesinti, göndericilerin kuyruğa alıp yeniden denemesi demektir — kendi ilkelerine göre saatlerce ya da günlerce — ve o postanın bir kısmı sonunda geri döner.',

  flag_no_ipv6_mx: 'Hiçbir posta sunucusuna IPv6 ile erişilemiyor',
  fd_no_ipv6_mx: 'Yalnızca IPv6 olan ağlardaki göndericiler bu alan adına bir çevirici üzerinden ulaşır, ulaşabilirlerse.',

  flag_spf_missing: 'SPF kaydı yok',
  fd_spf_missing: 'Bu alan adı olarak hangi sunucuların posta gönderebileceğini hiçbir şey söylemiyor, dolayısıyla karşılaştırılacak bir şey de yok. SPF tek bir TXT kaydıdır ve bu sayfadaki en ucuz şeydir.',

  flag_spf_multiple_records: 'Birden fazla SPF kaydı',
  fd_spf_multiple_records: 'RFC 7208 §4.5, iki kaydı kalıcı hataya dönüştürür ve permerror hiç SPF sonucu olmaması demektir — ikincisini eklemenin amacının tam tersi. Tek kayıtta birleştirmek gerekir.',

  flag_spf_too_many_lookups: 'SPF onun üzerinde DNS sorgusu gerektiriyor',
  fd_spf_too_many_lookups: 'RFC 7208 §4.6.4’teki sınır, değerlendirmenin tamamında sorgu doğuran on terimdir; her include içindeki her include de sayılır. Bunun ötesinde alıcı permerror döndürmek zorundadır ve SPF uygulanmaz olur — kayıt hiç olmasa da olurdu. Bir sağlayıcı daha ekleyerek aşmak kolaydır ve kaydın kendisine bakınca hiç görünmez.',

  flag_spf_lookups_near_limit: 'SPF, on sorgu sınırına yakın',
  fd_spf_lookups_near_limit: 'Pek pay kalmadı. Eklenecek bir sonraki hizmet — ya da denetiminizde olmayan, başkasının include’unun içindeki bir değişiklik — sınırı aştıracak.',

  flag_spf_too_many_void_lookups: 'Çok fazla SPF sorgusu boş dönüyor',
  fd_spf_too_many_void_lookups: 'RFC 7208 hiçbir şeye çözümlenmeyen iki sorguya izin verir; ötesi kalıcı hatadır. Genellikle artık kullanılmayan bir hizmet için kalmış bir include’dur.',

  flag_spf_no_all: 'SPF’in varsayılanı yok',
  fd_spf_no_all: '«all» mekanizması ya da redirect olmadan, hiçbir şeyle eşleşmeyen bir gönderici yansız sonuç alır — bu da hiç görüş bildirmemekle aynı şeydir.',

  flag_spf_plus_all: 'SPF bütün interneti yetkilendiriyor',
  fd_spf_plus_all: '«+all», herhangi bir yerdeki herhangi bir makinenin bu alan adı olarak gönderebileceğini söyler. Neredeyse her zaman niteleyicinin yanlış anlaşılmasıdır ve hiç SPF olmamasından kötüdür, çünkü sahtekâra açıkça kefil olur.',

  flag_spf_neutral_all: 'SPF ?all ile bitiyor',
  fd_spf_neutral_all: '«?all», hiçbir şeyle eşleşmeyen göndericiler hakkında bir şey söylemeyi açıkça reddeder. Alıcılar bunu sonuç yokluğu sayar.',

  flag_spf_softfail_all: 'SPF -all yerine ~all ile bitiyor',
  fd_spf_softfail_all: 'Yumuşak başarısızlık, alıcılardan kabul etmelerini ama işaretlemelerini ister. Adınıza kimin gönderdiğini hâlâ öğrenirken doğru ayardır; öğrendikten sonra sıkılaştırılacak olandır.',

  flag_spf_uses_ptr: 'SPF ptr mekanizmasını kullanıyor',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 onu açıkça geçersiz ilan eder: yavaştır, güvenilmezdir ve işi ters bölgeyi işleten tarafa yükler. Kimi alıcılar tümüyle yok sayar.',

  flag_spf_unknown_mechanism: 'SPF’te hiçbir şeyin anlamadığı bir terim var',
  fd_spf_unknown_mechanism: 'Tanınmayan bir mekanizma, RFC 7208 §4.6.1’e göre kalıcı hatadır ve kaydın tamamını çöpe atar. Genellikle bir yazım yanlışıdır.',

  flag_spf_duplicate_redirect: 'Birden fazla redirect değiştiricisi',
  fd_spf_duplicate_redirect: 'İkinci bir redirect kaydı kalıcı hataya dönüştürür.',

  flag_spf_redirect_after_all: 'Hiçbir zaman ulaşılmayacak bir redirect',
  fd_spf_redirect_after_all: 'Kayıtta hem bir «all» mekanizması hem de bir redirect var. «all» her zaman eşleşir, dolayısıyla değerlendirme orada durur ve redirect ölü metin olur.',

  flag_spf_record_long: 'SPF kaydı uzun',
  fd_spf_record_long: 'Uzun kayıtlar aktarımda birkaç dizeye bölünür. Bu kendi başına sorun değil — alıcılar aralarına hiçbir şey koymadan birleştirir — ama onları boşlukla birleştiren ayrıştırıcıların kaydı bozmaya başladığı yer tam da burasıdır.',

  flag_spf_include_loop: 'Bir include daha önce uğranmış bir yere geri işaret ediyor',
  fd_spf_include_loop: 'Açılım döngüye giriyor. Alıcı sorgu sınırında durur ve kalıcı hata döndürür.',

  flag_spf_include_without_record: 'Bir include, SPF kaydı olmayan bir alan adına işaret ediyor',
  fd_spf_include_without_record: 'RFC 7208 §5.2 bunu boşa giden bir sorgu değil, kalıcı hata sayar. Genellikle bir uçta kaldırılıp öbüründe kaldırılmamış bir hizmettir.',

  flag_dkim_no_known_selector: 'Bildiğimiz hiçbir seçicide DKIM anahtarı yok',
  fd_dkim_no_known_selector: 'Seçicileri imzalayan taraf seçer ve yalnızca imzalı bir iletinin başlığında görünürler, dolayısıyla dışarıdan sayılamazlar. Bu, DKIM’in eksik olduğunun kanıtı değildir — seçicinizi biliyorsanız ?selector= ile geçirin, denetim kesinleşir.',

  flag_dkim_key_revoked: 'Bir DKIM anahtarı iptal edilmiş',
  fd_dkim_key_revoked: 'Kayıt boş bir p= ile yayımlanmış, bu da anahtarı iptal eder. Bir anahtarı emekliye ayırmanın doğru yolu budur — ve aylarca bu durumda bırakılmış bir kayıt genellikle kimsenin tamamlamadığı bir değişimdir.',

  flag_dkim_key_malformed: 'Bir DKIM anahtarı ayrıştırılamıyor',
  fd_dkim_key_malformed: 'p= değeri geçerli anahtar malzemesi değil. Onunla üretilen her imza doğrulamada başarısız olur.',

  flag_dkim_in_test_mode: 'Bir DKIM kaydı deneme kipinde',
  fd_dkim_in_test_mode: 't=y, alıcılara başarısız bir imzayı DKIM kullanılmıyormuş gibi ele almalarını söyler. Yeri devreye alma sürecidir, başka hiçbir yer değil.',

  flag_dkim_key_too_short: 'Bir DKIM anahtarı 1024 bitten kısa',
  fd_dkim_key_too_short: '1024 bitin altında imzayı taklit etmek anlamlı ölçüde zor değildir ve birçok alıcı böyle anahtarları doğrudan yok sayar.',

  flag_dkim_key_1024_bit: 'Bir DKIM anahtarı 1024 bit',
  fd_dkim_key_1024_bit: 'Hâlâ her yerde kabul ediliyor ve bugünün önerilerinin altında. Olağan boyut 2048’dir; değişim yeni bir seçici ve bir DNS kaydından ibarettir.',

  flag_dmarc_missing: 'DMARC kaydı yok',
  fd_dmarc_missing: 'DMARC olmadan SPF ve DKIM sonuçları yol göstericidir: hiçbir şey onları okuyucunun gerçekten gördüğü adrese bağlamaz ve hiçbir şey alıcılara başarısız olduklarında ne yapacaklarını söylemez.',

  flag_dmarc_inherited: 'DMARC üst alan adından devralınıyor',
  fd_dmarc_inherited: 'Bu adın kendi kaydı yok, dolayısıyla kurumsal alan adının ilkesi geçerlidir — varsa sp= değeri, yoksa p= değeri.',

  flag_dmarc_multiple_records: 'Birden fazla DMARC kaydı',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: birden fazla kayıt varsa ilke tümüyle çöpe atılır, hiç yayımlanmamış gibi.',

  flag_dmarc_no_policy: 'DMARC kaydında p= etiketi yok',
  fd_dmarc_no_policy: 'p= zorunludur. Onsuz kayıt yok sayılır.',

  flag_dmarc_invalid_policy: 'DMARC ilkesi tanınan bir değer değil',
  fd_dmarc_invalid_policy: 'p= none, quarantine ya da reject olmalıdır. Başka herhangi bir şeyde alıcılar kaydı çöpe atar.',

  flag_dmarc_policy_none: 'DMARC hiçbir şey uygulamıyor',
  fd_dmarc_policy_none: 'p=none, alıcılardan rapor vermelerini ve hiçbir şeyi değiştirmemelerini ister. Hem SPF hem DKIM hizalamasında başarısız olan bir ileti, DMARC yokmuş gibi teslim edilir. Başlamanın doğru yolu budur — ve pek çok alan adı yıllardır burada oturup korunduğunu sanır.',

  flag_dmarc_policy_quarantine: 'DMARC reddetmek yerine karantinaya alıyor',
  fd_dmarc_policy_quarantine: 'Başarısız olan posta reddedilmek yerine gereksiz klasörüne gider. reject’e giden yolda makul bir adım ve sahte postanın hâlâ insanlara ulaştığı bir yer.',

  flag_dmarc_subdomain_policy_none: 'Alt alan adları ilkenin dışında',
  fd_dmarc_subdomain_policy_none: 'sp=none, alan adının kendisi korunurken her alt alan adını — hiç var olmamış olanlar dahil — sahteciliğe açık bırakır.',

  flag_dmarc_partial_percentage: 'İlke postanın yalnızca bir kısmına uygulanıyor',
  fd_dmarc_partial_percentage: '100’ün altındaki pct=, alıcılara ilkeyi başarısız iletilerin o oranına uygulamalarını, geri kalanına daha hoşgörülü davranmalarını söyler. Devreye alırken yararlıdır ve durduğu sürece bir açıktır.',

  flag_dmarc_no_reporting: 'Toplu raporlar için adres yok',
  fd_dmarc_no_reporting: 'rua= olmadan rapor gelmez; bu da alan adınız olarak kimin gönderdiğini ya da ilkeyi sıkılaştırırsanız neyin bozulacağını öğrenmenin yolu yok demektir.',

  flag_dmarc_external_reporting_unauthorised: 'Dış rapor adresi size yetki vermemiş',
  fd_dmarc_external_reporting_unauthorised: 'Raporlar başka bir alan adına yönlendirilmiş ve o alan adı, onları almayı kabul ettiği kaydı yayımlamıyor (RFC 7489 §7.1). Standarda uyan alıcılar hiçbir şey göndermez. DMARC kaydı kusursuz görünür ve raporlar hiç gelmez — bu da neredeyse her zaman raporların «biraz zaman aldığına» yorulur.',

  flag_mtasts_missing: 'MTA-STS ilkesi yok',
  fd_mtasts_missing: 'STARTTLS fırsatçıdır: teklifi görmeyen bir gönderici açık metinle gönderir ve o teklifi kaldırmak iki sunucu arasındaki herkes için kolaydır. MTA-STS, bu alan adının her zaman TLS konuştuğunu HTTPS üzerinden yayımlar; böylece saldırı bunun yerine web PKI’sini kırmayı gerektirir.',

  flag_mtasts_multiple_records: 'Birden fazla MTA-STS TXT kaydı',
  fd_mtasts_multiple_records: 'Göndericiler hangi kimliğin güncel olduğunu anlayamaz, dolayısıyla ilke değiştiğinde tazelenmeyebilir.',

  flag_mtasts_no_id: 'MTA-STS kaydında kimlik yok',
  fd_mtasts_no_id: 'Kimlik, bir göndericinin elindeki ilke kopyasının eskidiğini anlamasını sağlar. Onsuz, değişmiş bir ilke max_age dolana dek alınmayabilir.',

  flag_mtasts_policy_host_missing: 'İlke makinesi çözümlenmiyor',
  fd_mtasts_policy_host_missing: 'TXT kaydı bir ilke duyuruyor ve mta-sts.<alanadı>’nın adresi yok, dolayısıyla hiçbir gönderici onu alamaz.',

  flag_mtasts_policy_host_private: 'İlke makinesi özel adres alanına çözümleniyor',
  fd_mtasts_policy_host_private: 'İlke alınmadı: makine, bu hizmetin bağlanmayacağı bir adresi gösteriyor.',

  flag_mtasts_policy_unreachable: 'MTA-STS ilkesi alınamadı',
  fd_mtasts_policy_unreachable: 'TXT kaydı orada olmayan ya da sertifikası doğrulanmayan bir ilke vaat ediyor. Mekanizmanın tamamı o HTTPS sertifikasına dayandığından, buradaki bir başarısızlık göndericilerin fırsatçı TLS’e geri düşmesi demektir.',

  flag_mtasts_policy_wrong_content_type: 'İlke text/plain olarak sunulmuyor',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 text/plain ister. Katı göndericiler reddedecektir.',

  flag_mtasts_policy_bad_version: 'İlkenin sürümü STSv1 değil',
  fd_mtasts_policy_bad_version: 'Göndericiler sürümünü tanımadıkları bir ilkeyi kullanmaz.',

  flag_mtasts_policy_bad_mode: 'İlkenin kipi tanınan bir değer değil',
  fd_mtasts_policy_bad_mode: 'mode enforce, testing ya da none olmalıdır.',

  flag_mtasts_mode_testing: 'MTA-STS deneme kipinde',
  fd_mtasts_mode_testing: 'Başarısızlıklar raporlanır ve posta yine de teslim edilir, yani ilke henüz hiçbir şeyi korumuyor. Bir durak, varış noktası değil.',

  flag_mtasts_mode_none: 'MTA-STS kendi ilkesiyle kapatılmış',
  fd_mtasts_mode_none: 'mode=none ilkeyi geri çeker. Bir alan adının MTA-STS’i düzgünce bırakabilmesi için vardır; öylece bırakıldığında yalnızca kaydın hiçbir şey yapmadığı anlamına gelir.',

  flag_mtasts_no_max_age: 'İlkede max_age yok',
  fd_mtasts_no_max_age: 'max_age zorunludur ve ilkeyi bastırılmaya karşı dirençli kılan da odur: onu önbelleğe almış bir gönderici uygulamayı sürdürür.',

  flag_mtasts_max_age_short: 'İlke bir günden kısa süre saklanıyor',
  fd_mtasts_max_age_short: 'Kısa bir max_age, önbellekteki bir ilkenin bir göndericiyi koruduğu pencereyi daraltır. İlke oturduktan sonra birkaç hafta olağan seçimdir.',

  flag_mtasts_mx_not_in_policy: 'İlkede gerçek bir posta sunucusu eksik',
  fd_mtasts_mx_not_in_policy: 'MX kümesinde, ilkedeki hiçbir mx: örüntüsüyle eşleşmeyen bir makine var. Bu ilkeyi uygulayan her gönderici o makineye teslimi reddedecek — yani posta tam da dikkatli davranan göndericilerde başarısız olur.',

  flag_mtasts_policy_lists_unknown_mx: 'İlke, hiçbir güncel MX ile eşleşmeyen örüntüler listeliyor',
  fd_mtasts_policy_lists_unknown_mx: 'Zararsız ve genellikle bir taşınmadan kalmadır. İlkenin gerçekliği anlatmayı sürdürmesi için toparlamaya değer.',

  flag_mtasts_policy_no_mx: 'İlke hiçbir posta sunucusu listelemiyor',
  fd_mtasts_policy_no_mx: 'mx: girdisi olmayan bir ilke hiçbir şeyle eşleşmez, dolayısıyla onu uygulayan göndericilerin teslim edecek yeri yoktur.',

  flag_tlsrpt_missing: 'TLS-RPT kaydı yok',
  fd_tlsrpt_missing: 'Tek bir TXT kaydı ve göndericilerin sunucularınızla TLS anlaşamadığını öğrenmenin tek yolu. Onsuz, süresi dolmuş bir sertifika ya da bozuk bir STARTTLS sizin tarafınızdan görünmez.',

  flag_tlsrpt_no_rua: 'TLS-RPT kaydının hedefi yok',
  fd_tlsrpt_no_rua: 'rua= olmadan raporların gidecek yeri yoktur, dolayısıyla kayıt hiçbir şey yapmaz.',

  flag_dane_missing: 'DANE kaydı yok',
  fd_dane_missing: 'TLSA kayıtları, bir posta sunucusunun sunması gereken sertifikayı, genel sertifika otoritelerine değil DNSSEC’e dayanarak sabitler. İki taşıma mekanizmasından daha güçlü olanıdır — ve imzalı bir bölge gerektirir, ki kullanılmamasının olağan nedeni de budur.',

  flag_dane_partial: 'Yalnızca bazı posta sunucularının DANE kaydı var',
  fd_dane_partial: 'Göndericiler sunucuyu önceliğe göre seçer, dolayısıyla yalnızca bazı makinelerin sabitlendiği bir küme yalnızca zamanın bir kısmında korunur.',

  flag_dane_without_dnssec: 'İmzasız bir bölgede TLSA kaydı',
  fd_dane_without_dnssec: 'DANE tümüyle DNSSEC’e dayanır. İmzalar olmadan, MX kaydını değiştirebilen TLSA kaydını da değiştirebilir; yani sabitleme hiçbir şeyi korumaz, korurmuş gibi görünür.',

  flag_dane_mismatch: 'TLSA kaydı sunulan sertifikayla eşleşmiyor',
  fd_dane_mismatch: 'Sunucu, kendi DANE kaydının yetkilendirmediği bir sertifika sunuyor. DANE’i doğrulayan her gönderici teslimi reddedecek — bu postayı durdurur.',

  flag_dane_pkix_usage: 'Bir TLSA kaydı PKIX kullanımı içeriyor',
  fd_dane_pkix_usage: '0 ve 1 numaralı kullanımlar, sertifikanın ayrıca genel otoriteler üzerinden de doğrulanmasını ister. RFC 7672 §3.1 ikisini de SMTP için yasaklar, çünkü posta için bu denetimi yapmanın üzerinde anlaşılmış bir yolu yoktur.',

  flag_dane_full_certificate: 'Bir TLSA kaydı sertifikanın tamamını sabitliyor',
  fd_dane_full_certificate: '0 numaralı eşleşme türü, bir özet yerine sertifikanın tamamını saklar. Çalışır, kaydı büyütür ve her yenilemede değiştirilmesini gerektirir.',

  flag_port_25_blocked_from_here: 'Bu hizmetin çalıştığı yerde giden 25 numaralı bağlantı noktası engelli',
  fd_port_25_blocked_from_here: 'Bu bizim ağımızla ilgili, sizinkiyle değil. Çoğu barındırma sağlayıcısı 25 numaralı bağlantı noktasına giden bağlantıları varsayılan olarak engeller. Bu yüzden STARTTLS, DANE’in gerçek bir sertifikayla karşılaştırılması ve aktarma yoklaması yapılamadı; not da rastgele erişilebilen şeylerden hesaplanmak yerine verilmedi.',

  flag_mx_not_reachable_on_25: 'Hiçbir posta sunucusu 25 numaralı bağlantı noktasında yanıt vermedi',
  fd_mx_not_reachable_on_25: 'MX kayıtları, postanın teslim edildiği bağlantı noktasında bağlantı kabul etmeyen makineleri adlandırıyor. Bu alan adına hiçbir şey teslim edilemez.',

  flag_no_starttls: 'Bir posta sunucusu STARTTLS sunmuyor',
  fd_no_starttls: 'Bu sunucuya teslim edilen her ileti interneti şifresiz geçer ve yol üstündeki her şey tarafından okunabilir. STARTTLS sunmak bir sertifika ve bir satır yapılandırmaya mal olur.',

  flag_starttls_fails: 'STARTTLS sunuluyor ve çalışmıyor',
  fd_starttls_fails: 'Sunucu STARTTLS duyuruyor ve el sıkışma başarısız oluyor. Dikkatli göndericiler açık metne düşmeyi reddedip postayı erteleyebilir — yani bu, hiç sunmamaktan kötüdür.',

  flag_starttls_legacy_protocol: 'Posta sunucusu eskimiş bir TLS sürümü üzerinde anlaşıyor',
  fd_starttls_legacy_protocol: 'TLS 1.0 ve 1.1, RFC 8996’dan beri geçersizdir. Göndericiler desteği kademeli olarak kaldırıyor ve kaldırdıklarında posta gelmeyi bırakır.',

  flag_mx_certificate_not_trusted: 'Posta sunucusunun sertifikası doğrulanmıyor',
  fd_mx_certificate_not_trusted: 'Sıradan fırsatçı TLS sertifikaları doğrulamaz, dolayısıyla bugün teslimi engellemez. MTA-STS enforce kipinde ya da DANE devreye girdiği anda tümüyle engeller.',

  flag_banner_reveals_version: 'Karşılama yazılımı ve sürümünü söylüyor',
  fd_banner_reveals_version: 'Tam o sürümde bilinen bir hata arayan birine küçük bir armağan. Karşılamaya istenen her şey yazılabilir.',

  flag_open_relay: 'Sunucu yabancıların postasını aktarıyor',
  fd_open_relay: 'İlgisiz bir göndericiden ilgisiz bir alıcıya ileti kabul etti. Herkes onu sizin adınıza istenmeyen posta göndermek için kullanabilir ve zaten değilse birkaç saat içinde engelleme listelerine düşer. Bu bugün onarılır. (Yoklama RCPT TO’da durdu ve RSET gönderdi — hiçbir ileti gönderilmedi.)',

  flag_no_size_extension: 'Sunucu SIZE duyurmuyor',
  fd_no_size_extension: 'SIZE olmadan bir gönderici, büyük bir iletinin kabul edilip edilmeyeceğini tümünü aktarmadan bilemez.',

  flag_submission_without_starttls: 'Gönderim bağlantı noktası STARTTLS sunmuyor',
  fd_submission_without_starttls: '587 numaralı bağlantı noktası, posta istemcilerinin kimlik doğruladığı yerdir. STARTTLS olmadan o kimlik bilgileri ağı açık metin olarak geçer.',

  flag_rdns_missing: 'Bir posta sunucusu adresinin PTR kaydı yok',
  fd_rdns_missing: 'Ters DNS eksikliği, yeni bir sunucudan gelen postanın ertelenmesinin ya da gereksiz klasörüne düşmesinin en yaygın nedenlerinden biridir — ve alıcı tarafın en az açıkladıklarından.',

  flag_rdns_not_confirmed: 'Ters DNS geri çözümlenmiyor',
  fd_rdns_not_confirmed: 'PTR kaydı bir ad veriyor ve o ad bu adrese çözümlenmiyor. Alıcılar gidiş dönüşü tam da iki farklı tarafın üzerine düşeni yapmasını gerektirdiği için denetler.',

  flag_rdns_none_confirmed: 'Hiçbir posta sunucusunun doğrulanmış ters DNS’i yok',
  fd_rdns_none_confirmed: 'Tek bir adres bile gidiş dönüş denetimini geçmiyor. Bunu tartan alıcılarda teslim gecikmeleri ve gereksiz klasörüne düşme bekleyin.',
};

OWN.zh = {
  title: '邮件检测 — 任意域名的 SPF、DKIM、DMARC、MTA-STS 与 DANE',
  title_short: '邮件检测',
  h1: '邮件检测',
  subtitle: 'SPF 逐层展开每一个 include 并按十次上限计数，DMARC 对齐与报告，传输层安全则在真实连接上验证',
  ph_host: 'example.com',
  hero_label: '被检测的域名',
  empty_hint: '输入一个域名。检测会逐层展开 SPF 记录的每一个 include，尝试各大平台使用的 DKIM 选择器，读取 DMARC 策略，经 HTTPS 取回 MTA-STS 策略，并与邮件服务器建立只读的 SMTP 会话。全过程不会发出任何一封邮件。',

  stage_resolve: '正在查找邮件服务器',
  stage_mx: '正在检查 MX 集合',
  stage_spf: '正在展开 SPF',
  stage_dkim: '正在查找 DKIM 密钥',
  stage_dmarc: '正在读取 DMARC 策略',
  stage_mtasts: '正在取回 MTA-STS 策略',
  stage_dane: '正在检查 DANE',
  stage_starttls: '正在与邮件服务器对话',
  stage_grade: '正在评级',

  card_grade: '评级构成',
  card_mx: '邮件服务器',
  card_spf: 'SPF',
  card_spf_tree: 'SPF 展开',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: '传输安全',
  card_sessions: 'SMTP 会话',
  card_rdns: '反向 DNS',

  comp_authentication: '身份认证',
  comp_transport: '传输',
  comp_hygiene: '整洁度',

  k_mx_count: 'MX 记录',
  k_null_mx: '空 MX',
  k_ipv6_mx: '可经 IPv6 访问',
  k_spf_record: '记录',
  k_spf_lookups: '已用 DNS 查询',
  k_spf_voids: '空查询',
  k_spf_policy: '对其余所有人的默认处置',
  k_dkim_keys: '找到的密钥',
  k_dkim_tried: '尝试的选择器',
  k_dkim_strongest: '最强的密钥',
  k_dmarc_policy: '策略',
  k_dmarc_subdomain: '子域策略',
  k_dmarc_percent: '适用比例',
  k_dmarc_alignment: '对齐方式（DKIM / SPF）',
  k_dmarc_rua: '汇总报告发往',
  k_dmarc_ruf: '故障报告发往',
  k_dmarc_external: '外部报告已获授权',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: '模式',
  k_mtasts_id: '策略标识',
  k_mtasts_maxage: '缓存时长',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE（TLSA）',
  k_dane_covered: '覆盖的服务器',
  k_starttls: 'STARTTLS',
  k_port25: '出站 25 端口',
  k_open_relay: '开放中继',
  k_rdns_confirmed: '正向确认通过',
  k_queries: '发出的查询',

  th_priority: '优先级',
  th_host: '主机',
  th_addresses: '地址',
  th_port: '端口',
  th_tls: 'TLS',
  th_banner: '问候语',
  th_extensions: '已声明',
  th_selector: '选择器',
  th_key_type: '密钥',
  th_bits: '位数',
  th_state: '状态',
  th_address: '地址',
  th_ptr: 'PTR',
  th_confirmed: '已确认',
  th_term: '项',
  th_lookup: '查询',

  pol_none: 'none — 仅作观察',
  pol_quarantine: 'quarantine — 投入垃圾邮件',
  pol_reject: 'reject — 拒收',
  spfp_pass: '放行所有人（+all）',
  spfp_fail: '拒收（-all）',
  spfp_softfail: '软失败（~all）',
  spfp_neutral: '中立（?all）',
  spfp_redirect: '经 redirect 委派',
  spfterm_no_target: '没有目标',
  spfterm_loop: '成环 — 已经来过',
  spfterm_lookup_failed: '查询失败',
  spfterm_no_spf_record: '那里没有 SPF 记录',

  stsmode_enforce: 'enforce — 强制执行',
  stsmode_testing: 'testing — 仅报告',
  stsmode_none: 'none — 已关闭',
  rdns_confirmed: '已确认',
  rdns_unconfirmed: '不能解析回来',
  rdns_missing: '没有 PTR',
  rdns_unknown: '未检测',
  v_of_limit: '{limit} 次中的 {used} 次',
  v_percent: '{n}%',
  v_days_short: '{n} 天',
  v_blocked_here: '从我们的网络被封锁',
  v_no_selector_found: '{n} 个已知选择器一个都没有',

  note_spf: 'RFC 7208 允许整个求值过程中共十个会触发 DNS 查询的项，并且要逐层深入每一个 include 之中的每一个 include。超过十个，接收方必须返回 permerror — 而 permerror 意味着 SPF 根本不适用，与压根没有记录完全一样。',
  note_dmarc: 'p=none 时什么都不会执行：一封 SPF 与 DKIM 对齐双双失败的邮件照旧投递。这是个正确的起点，却是个错误的落脚处。',
  note_transport: 'STARTTLS 是机会性的：被剥掉这项提议的发送方只会照常以明文继续。MTA-STS 与 DANE 才是把这种可能性变成保证的东西。',
  note_sessions: '所有会话都是只读的。中继探测在 RCPT TO 处停下并发送 RSET；绝不会发出 DATA 命令，因此不可能发出任何邮件。',
  note_rdns: '单凭一条 PTR 记录什么也证明不了 —— 地址块的持有者可以在那里写下任何名字。接收方真正检查的，是这个名字能否解析回同一个地址。',

  err_smtp_timeout: '邮件服务器未能及时应答。',
  err_smtp_network: '无法连通邮件服务器。',
  err_smtp_refused: '邮件服务器拒绝了连接。',
  err_tls_failed: '与邮件服务器的 TLS 握手失败。',

  inc_mx_lookup_failed: '无法读取 MX 记录',
  inc_spf_lookup_failed: '无法读取 SPF 记录',
  inc_dmarc_lookup_failed: '无法读取 DMARC 记录',
  inc_port_25_unreachable_from_this_network: '本服务运行处的出站 25 端口被封锁，因此 STARTTLS、用真实证书核对 DANE 以及中继探测都无法进行',
  inc_not_every_mx_was_probed: '只连接了优先级最高的几台服务器',

  cap_open_relay: '服务器为陌生人转发邮件',
  cap_spf_authorises_everyone: 'SPF 授权了整个互联网',
  cap_no_mail_servers: '没有邮件服务器',
  cap_mail_servers_unreachable: '没有邮件服务器在 25 端口作答',
  cap_dane_mismatch: 'DANE 与所出示的证书不符',
  cap_mtasts_policy_contradicts_dns: 'MTA-STS 策略漏掉了一台真实的邮件服务器',
  cap_spf_over_the_lookup_limit: 'SPF 超出查询上限',
  cap_spf_permerror: 'SPF 是永久性错误',
  cap_dmarc_permerror: 'DMARC 是永久性错误',
  cap_mail_in_the_clear: '邮件以明文被接收',
  cap_no_spf: '没有 SPF 记录',
  cap_no_dmarc: '没有 DMARC 记录',
  cap_starttls_broken: 'STARTTLS 有提供却不可用',
  cap_dmarc_not_enforcing: 'DMARC 什么都不执行',
  cap_no_reverse_dns: '没有经确认的反向 DNS',
  cap_spf_without_a_default: 'SPF 没有默认处置',
  cap_weak_dkim_key: 'DKIM 密钥过短',
  cap_dmarc_reports_go_nowhere: 'DMARC 报告未获授权',
  cap_mail_server_does_not_resolve: '有邮件服务器无法解析',
  cap_scan_incomplete: '检测不完整，因此未给出评级',

  flag_null_mx: '该域名声明自己不处理邮件',
  fd_null_mx: '仅有一条优先级为 0、指向根的 MX，正是 RFC 7505 所说的「本域名既不发信也不收信」。这是有意为之，而且比完全没有 MX 好得多 —— 没有 MX 时，发送方会退回到地址记录。',

  flag_no_mx: '没有 MX 记录',
  fd_no_mx: '没有任何东西说明这个域名的邮件该送往何处，也没有可退回的地址，因此根本无从投递。',

  flag_no_mx_falls_back_to_a: '没有 MX 记录，发送方退回到 A 记录',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 要求没有 MX 的发送方去试地址记录。这个域名的邮件会被送到 Web 服务器 25 端口上监听的任何东西 —— 而这几乎从来不是本意。',

  flag_duplicate_mx_host: '同一台主机被列了两次',
  fd_duplicate_mx_host: '一台主机出现在不止一个优先级上。这不是冗余，而是同一台机器被试了两遍。',

  flag_mx_does_not_resolve: '有邮件服务器的名称无法解析',
  fd_mx_does_not_resolve: 'MX 指向了一台没有地址记录的主机。每个走到这个优先级的发送方都要等这次查询，什么也拿不到，然后往下走 —— 于是本该立刻送达的邮件被拖延。',

  flag_mx_points_at_cname: '一条 MX 记录指向别名',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 要求 MX 指向带地址记录的主机，而不是 CNAME。有的发送方能应付，有的直接拒绝，而谁是哪一类还会随时间变化。',

  flag_single_mx: '只有一台邮件服务器',
  fd_single_mx: '只有一条 MX 时，任何一次中断都意味着发送方排队重试 —— 按各自的策略，几小时或几天 —— 而其中一部分邮件最终会被退回。',

  flag_no_ipv6_mx: '没有邮件服务器可经 IPv6 访问',
  fd_no_ipv6_mx: '纯 IPv6 网络中的发送方要经由转换器才能到达这个域名，如果到得了的话。',

  flag_spf_missing: '没有 SPF 记录',
  fd_spf_missing: '没有任何东西说明哪些服务器可以以这个域名的名义发信，因此也就无从比对。SPF 只是一条 TXT 记录，是整个页面上最便宜的一件事。',

  flag_spf_multiple_records: '不止一条 SPF 记录',
  fd_spf_multiple_records: 'RFC 7208 §4.5 让两条记录成为永久性错误，而 permerror 意味着完全没有 SPF 结果 —— 与添加第二条的初衷正好相反。应当合并成一条。',

  flag_spf_too_many_lookups: 'SPF 需要超过十次 DNS 查询',
  fd_spf_too_many_lookups: 'RFC 7208 §4.6.4 的上限是整个求值过程中十个会触发查询的项，且要逐层深入每一个 include 之中的每一个 include。超过之后接收方必须返回 permerror，SPF 随之不再适用 —— 这条记录不存在也罢。多加一家服务商就很容易超出，而单看记录本身完全看不出来。',

  flag_spf_lookups_near_limit: 'SPF 已接近十次查询的上限',
  fd_spf_lookups_near_limit: '余量所剩无几。下一个加进来的服务 —— 或者别人 include 内部一次你管不着的改动 —— 就会把它顶出去。',

  flag_spf_too_many_void_lookups: '太多 SPF 查询什么都没返回',
  fd_spf_too_many_void_lookups: 'RFC 7208 允许两次解析不到任何东西的查询；再多就是永久性错误。通常是某个已经不用的服务留下的 include。',

  flag_spf_no_all: 'SPF 没有默认处置',
  fd_spf_no_all: '既没有「all」机制也没有 redirect 时，任何都匹配不上的发送方得到的是中立结果 —— 这跟没有任何意见是一回事。',

  flag_spf_plus_all: 'SPF 授权了整个互联网',
  fd_spf_plus_all: '「+all」等于说任何地方的任何主机都可以用这个域名发信。这几乎总是对限定符的误解，而且比没有 SPF 更糟，因为它明确为伪造者背书。',

  flag_spf_neutral_all: 'SPF 以 ?all 结尾',
  fd_spf_neutral_all: '「?all」明确拒绝对匹配不上的发送方表态。接收方把它当作没有结果。',

  flag_spf_softfail_all: 'SPF 以 ~all 而非 -all 结尾',
  fd_spf_softfail_all: '软失败请求接收方收下但打上标记。在你还在摸清谁在以你的名义发信时，这是正确的设置；摸清之后，它就是该收紧的地方。',

  flag_spf_uses_ptr: 'SPF 使用了 ptr 机制',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 直截了当地将其废弃：慢、不可靠，还把负担推给运行反向区域的人。有些接收方干脆完全忽略它。',

  flag_spf_unknown_mechanism: 'SPF 中有谁也看不懂的项',
  fd_spf_unknown_mechanism: '按 RFC 7208 §4.6.1，无法识别的机制是永久性错误，会让整条记录作废。通常是个拼写错误。',

  flag_spf_duplicate_redirect: '不止一个 redirect 修饰符',
  fd_spf_duplicate_redirect: '第二个 redirect 会让整条记录变成永久性错误。',

  flag_spf_redirect_after_all: '永远走不到的 redirect',
  fd_spf_redirect_after_all: '这条记录既有「all」机制又有 redirect。「all」永远匹配，求值到此为止，redirect 便成了死文本。',

  flag_spf_record_long: 'SPF 记录很长',
  fd_spf_record_long: '长记录在传输时会被拆成多个字符串。这本身没问题 —— 接收方会不加分隔地拼回去 —— 但正是在这里，用空格连接它们的解析器开始悄悄毁掉这条记录。',

  flag_spf_include_loop: '有 include 指回了已经来过的地方',
  fd_spf_include_loop: '展开成了环。接收方会在查询上限处停下并返回永久性错误。',

  flag_spf_include_without_record: '有 include 指向了没有 SPF 记录的域名',
  fd_spf_include_without_record: 'RFC 7208 §5.2 把这算作永久性错误，而不只是浪费一次查询。通常是一端下线、另一端忘了同步的服务。',

  flag_dkim_no_known_selector: '我们知道的选择器里都没有 DKIM 密钥',
  fd_dkim_no_known_selector: '选择器由签名方选定，只出现在已签名邮件的头部，因此从外部无法枚举。这并不能证明 DKIM 缺失 —— 如果你知道自己的选择器，用 ?selector= 传进来，这项检测就能给出确定结论。',

  flag_dkim_key_revoked: '有一把 DKIM 密钥已被吊销',
  fd_dkim_key_revoked: '记录以空的 p= 发布，这就是吊销密钥。这是让一把密钥退役的正确做法 —— 而一条这样搁了几个月的记录，通常意味着一次没人收尾的轮换。',

  flag_dkim_key_malformed: '有一把 DKIM 密钥无法解析',
  fd_dkim_key_malformed: 'p= 的值不是有效的密钥材料。用它做出的每个签名都通不过验证。',

  flag_dkim_in_test_mode: '有一条 DKIM 记录处于测试模式',
  fd_dkim_in_test_mode: 't=y 告诉接收方把验签失败当作压根没用 DKIM。它该出现的地方只有上线过程中，别处都不该有。',

  flag_dkim_key_too_short: '有一把 DKIM 密钥短于 1024 位',
  fd_dkim_key_too_short: '低于 1024 位时签名并不难以伪造，而且许多接收方干脆忽略这样的密钥。',

  flag_dkim_key_1024_bit: '有一把 DKIM 密钥是 1024 位',
  fd_dkim_key_1024_bit: '目前各处仍然接受，但低于当下的建议值。常见的尺寸是 2048；轮换无非是一个新选择器加一条 DNS 记录。',

  flag_dmarc_missing: '没有 DMARC 记录',
  fd_dmarc_missing: '没有 DMARC，SPF 和 DKIM 的结果就只是参考：没有任何东西把它们和读者真正看到的地址绑在一起，也没有任何东西告诉接收方在失败时该怎么办。',

  flag_dmarc_inherited: 'DMARC 继承自上级域名',
  fd_dmarc_inherited: '这个名称没有自己的记录，因此适用组织域的策略 —— 有 sp= 就用 sp=，否则用 p=。',

  flag_dmarc_multiple_records: '不止一条 DMARC 记录',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3：记录多于一条时，整条策略被完全丢弃，如同从未发布过。',

  flag_dmarc_no_policy: 'DMARC 记录里没有 p= 标签',
  fd_dmarc_no_policy: 'p= 是必填的。没有它，这条记录会被忽略。',

  flag_dmarc_invalid_policy: 'DMARC 策略不是可识别的取值',
  fd_dmarc_invalid_policy: 'p= 必须是 none、quarantine 或 reject。取其他值时接收方会丢弃这条记录。',

  flag_dmarc_policy_none: 'DMARC 什么都不执行',
  fd_dmarc_policy_none: 'p=none 请求接收方只报告、不改变任何处置。一封 SPF 与 DKIM 对齐双双失败的邮件，其投递结果与没有 DMARC 时一模一样。这是正确的起步方式 —— 而相当多的域名在这里一待就是几年，还以为自己受到保护。',

  flag_dmarc_policy_quarantine: 'DMARC 只隔离而不拒收',
  fd_dmarc_policy_quarantine: '未通过的邮件进入垃圾邮件夹而非被拒收。这是通往 reject 的合理一步，也是伪造邮件仍然会送到人眼前的地方。',

  flag_dmarc_subdomain_policy_none: '子域被排除在策略之外',
  fd_dmarc_subdomain_policy_none: 'sp=none 让每一个子域 —— 包括从未存在过的那些 —— 都对伪造敞开，而域名本身却是受保护的。',

  flag_dmarc_partial_percentage: '策略只适用于一部分邮件',
  fd_dmarc_partial_percentage: 'pct= 小于 100 是让接收方对这一比例的失败邮件执行策略，其余从宽处理。上线期间有用，而只要它还在，就是一个缺口。',

  flag_dmarc_no_reporting: '没有接收汇总报告的地址',
  fd_dmarc_no_reporting: '没有 rua= 就收不到报告，也就无从知道谁在以你的域名发信，更无从知道收紧策略会打断什么。',

  flag_dmarc_external_reporting_unauthorised: '外部报告地址并未授权给你',
  fd_dmarc_external_reporting_unauthorised: '报告被指向了另一个域名，而那个域名并未发布同意接收的记录（RFC 7489 §7.1）。守规矩的接收方什么也不会发。DMARC 记录看上去完美无缺，报告却始终不来 —— 而这几乎总是被归因于「报告要等一阵子」。',

  flag_mtasts_missing: '没有 MTA-STS 策略',
  fd_mtasts_missing: 'STARTTLS 是机会性的：看不到这项提议的发送方就以明文发送，而对夹在两台服务器之间的任何人来说，抹掉这项提议轻而易举。MTA-STS 通过 HTTPS 公布本域名始终使用 TLS，于是这种攻击转而需要击破 Web PKI。',

  flag_mtasts_multiple_records: '不止一条 MTA-STS TXT 记录',
  fd_mtasts_multiple_records: '发送方分不清哪个标识才是当前的，策略变更时可能不会被刷新。',

  flag_mtasts_no_id: 'MTA-STS 记录没有标识',
  fd_mtasts_no_id: '标识是发送方判断自己手上的策略副本已经过时的依据。没有它，改动过的策略可能要等到 max_age 到期才被取回。',

  flag_mtasts_policy_host_missing: '策略主机无法解析',
  fd_mtasts_policy_host_missing: 'TXT 记录宣告了一份策略，而 mta-sts.<域名> 没有地址，于是没有任何发送方能取到它。',

  flag_mtasts_policy_host_private: '策略主机解析到私有地址空间',
  fd_mtasts_policy_host_private: '策略未被取回：该主机指向了本服务不会连接的地址。',

  flag_mtasts_policy_unreachable: 'MTA-STS 策略无法取回',
  fd_mtasts_policy_unreachable: 'TXT 记录承诺了一份并不存在、或者其证书通不过验证的策略。由于整套机制都倚仗那张 HTTPS 证书，这里的失败意味着发送方退回到机会性 TLS。',

  flag_mtasts_policy_wrong_content_type: '策略未以 text/plain 提供',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 要求 text/plain。严格的发送方会拒收。',

  flag_mtasts_policy_bad_version: '策略版本不是 STSv1',
  fd_mtasts_policy_bad_version: '发送方不会使用自己不认识版本的策略。',

  flag_mtasts_policy_bad_mode: '策略模式不是可识别的取值',
  fd_mtasts_policy_bad_mode: 'mode 必须是 enforce、testing 或 none。',

  flag_mtasts_mode_testing: 'MTA-STS 处于测试模式',
  fd_mtasts_mode_testing: '失败会被报告，邮件照样投递，所以这份策略眼下什么也没保护。它是一个中转站，不是终点。',

  flag_mtasts_mode_none: 'MTA-STS 被自己的策略关掉了',
  fd_mtasts_mode_none: 'mode=none 撤回策略。它的存在是为了让一个域名能体面地停用 MTA-STS；就这么留着，只不过意味着这条记录什么也不做。',

  flag_mtasts_no_max_age: '策略没有 max_age',
  fd_mtasts_no_max_age: 'max_age 是必填的，也正是它让策略难以被压制：已经缓存过它的发送方会继续执行下去。',

  flag_mtasts_max_age_short: '策略的缓存时间不到一天',
  fd_mtasts_max_age_short: '较短的 max_age 会缩小缓存策略保护发送方的时间窗。策略稳定之后，通常会设成几周。',

  flag_mtasts_mx_not_in_policy: '策略里少了一台真实的邮件服务器',
  fd_mtasts_mx_not_in_policy: 'MX 集合里有一台主机，策略中没有任何 mx: 模式与之匹配。每个执行这份策略的发送方都会拒绝向那台主机投递 —— 也就是说，恰恰是那些谨慎的发送方投不进来。',

  flag_mtasts_policy_lists_unknown_mx: '策略里的模式匹配不上任何现有的 MX',
  fd_mtasts_policy_lists_unknown_mx: '无害，通常是迁移留下的残余。值得清理一下，好让这份策略仍然描述现实。',

  flag_mtasts_policy_no_mx: '策略没有列出任何邮件服务器',
  fd_mtasts_policy_no_mx: '没有 mx: 条目的策略什么也匹配不上，执行它的发送方便无处投递。',

  flag_tlsrpt_missing: '没有 TLS-RPT 记录',
  fd_tlsrpt_missing: '一条 TXT 记录，也是你得知发送方无法与你的服务器协商 TLS 的唯一途径。没有它，过期的证书或者坏掉的 STARTTLS 在你这一侧完全看不见。',

  flag_tlsrpt_no_rua: 'TLS-RPT 记录没有目的地',
  fd_tlsrpt_no_rua: '没有 rua=，报告无处可去，这条记录也就什么都不做。',

  flag_dane_missing: '没有 DANE 记录',
  fd_dane_missing: 'TLSA 记录钉住邮件服务器必须出示的证书，依靠的是 DNSSEC 而不是公共证书颁发机构。它是两种传输机制中更强的一种 —— 而它需要区域已签名，这通常也正是它没被启用的原因。',

  flag_dane_partial: '只有部分邮件服务器有 DANE 记录',
  fd_dane_partial: '发送方按优先级挑服务器，所以只钉住了一部分主机的集合，也只有一部分时间是受保护的。',

  flag_dane_without_dnssec: '未签名区域中的 TLSA 记录',
  fd_dane_without_dnssec: 'DANE 完全倚仗 DNSSEC。没有签名，能替换 MX 记录的人同样能替换 TLSA 记录，于是这份钉扎什么也保护不了，却看上去像保护了。',

  flag_dane_mismatch: 'TLSA 记录与所出示的证书不符',
  fd_dane_mismatch: '服务器出示的证书，是它自己的 DANE 记录所不认可的。每个验证 DANE 的发送方都会拒绝投递 —— 这会让邮件停摆。',

  flag_dane_pkix_usage: '有 TLSA 记录使用了 PKIX 用法',
  fd_dane_pkix_usage: '用法 0 和 1 要求证书同时还能通过公共机构验证。RFC 7672 §3.1 明令禁止在 SMTP 中使用这两者，因为对邮件而言并无公认的做法来完成这项检查。',

  flag_dane_full_certificate: '有 TLSA 记录钉住了整张证书',
  fd_dane_full_certificate: '匹配类型 0 存的是完整证书而不是散列值。可以工作，会让记录变大，而且每次续期都得替换。',

  flag_port_25_blocked_from_here: '本服务运行处的出站 25 端口被封锁',
  fd_port_25_blocked_from_here: '这说的是我们的网络，不是你的。多数主机商默认封锁到 25 端口的出站连接。因此 STARTTLS、用真实证书核对 DANE 以及中继探测都无法进行，评级也被扣下，而不是拿凑巧够得着的那点东西凑出一个分数。',

  flag_mx_not_reachable_on_25: '没有邮件服务器在 25 端口作答',
  fd_mx_not_reachable_on_25: 'MX 记录指向的主机在投递邮件所用的端口上不接受连接。什么都送不进这个域名。',

  flag_no_starttls: '有邮件服务器不提供 STARTTLS',
  fd_no_starttls: '投递到这台服务器的每一封邮件都以未加密的方式穿过互联网，途中任何东西都能读到。提供 STARTTLS 的代价是一张证书和一行配置。',

  flag_starttls_fails: 'STARTTLS 有提供却不可用',
  fd_starttls_fails: '服务器声明了 STARTTLS，握手却失败。谨慎的发送方可能拒绝退回明文而把邮件延后 —— 所以这比完全不提供还要糟。',

  flag_starttls_legacy_protocol: '邮件服务器协商出了过时的 TLS 版本',
  fd_starttls_legacy_protocol: 'TLS 1.0 和 1.1 自 RFC 8996 起已被废弃。发送方正在逐步撤掉对它们的支持，撤掉之时，邮件也就送不到了。',

  flag_mx_certificate_not_trusted: '邮件服务器的证书通不过验证',
  fd_mx_certificate_not_trusted: '寻常的机会性 TLS 并不校验证书，所以今天这并不妨碍投递。一旦 enforce 模式的 MTA-STS 或者 DANE 参与进来，它就会彻底阻断投递。',

  flag_banner_reveals_version: '问候语点明了软件及其版本',
  fd_banner_reveals_version: '这是送给那些正在搜寻恰好带有已知缺陷版本的人的小礼物。问候语里想写什么都可以。',

  flag_open_relay: '服务器为陌生人转发邮件',
  fd_open_relay: '它接受了一封由无关发送方寄给无关收件人的邮件。任何人都能借它以你的名义发垃圾邮件，若尚未上黑名单，数小时内也会上。这件事今天就该修。（探测在 RCPT TO 处停下并发送了 RSET —— 没有任何邮件被发出。）',

  flag_no_size_extension: '服务器没有声明 SIZE',
  fd_no_size_extension: '没有 SIZE，发送方要把一封大邮件整个传完才知道会不会被接受。',

  flag_submission_without_starttls: '投递端口不提供 STARTTLS',
  fd_submission_without_starttls: '587 端口是邮件客户端进行身份认证的地方。没有 STARTTLS，这些凭据就以明文穿过网络。',

  flag_rdns_missing: '有邮件服务器地址没有 PTR 记录',
  fd_rdns_missing: '缺少反向 DNS 是新服务器发出的邮件被延迟或投入垃圾箱最常见的原因之一 —— 也是接收方最少解释的原因之一。',

  flag_rdns_not_confirmed: '反向 DNS 不能解析回来',
  fd_rdns_not_confirmed: 'PTR 记录给出了一个名字，而这个名字并不解析到这个地址。接收方之所以检查这一来一回，正是因为它要求两个不同的当事方各自做好自己那一半。',

  flag_rdns_none_confirmed: '没有一台邮件服务器有经确认的反向 DNS',
  fd_rdns_none_confirmed: '没有任何一个地址通过来回检查。在把这一点纳入考量的接收方那里，可以预期投递延迟和被归入垃圾邮件。',
};

OWN.ja = {
  title: 'メール検査 — 任意のドメインの SPF・DKIM・DMARC・MTA-STS・DANE',
  title_short: 'メール検査',
  h1: 'メール検査',
  subtitle: 'SPF をすべての include まで展開して十回の上限に照らして数え、DMARC の整合と報告を読み、transport の保護は実際の接続で確かめます',
  ph_host: 'example.com',
  hero_label: '検査対象のドメイン',
  empty_hint: 'ドメイン名を入力してください。検査は SPF レコードをすべての include まで展開し、大手プラットフォームが使う DKIM セレクターを試し、DMARC ポリシーを読み、MTA-STS ポリシーを HTTPS で取得し、メールサーバーへ読み取り専用の SMTP セッションを開きます。メールを送信することは一切ありません。',

  stage_resolve: 'メールサーバーを探しています',
  stage_mx: 'MX の組を確認しています',
  stage_spf: 'SPF を展開しています',
  stage_dkim: 'DKIM 鍵を探しています',
  stage_dmarc: 'DMARC ポリシーを読んでいます',
  stage_mtasts: 'MTA-STS ポリシーを取得しています',
  stage_dane: 'DANE を確認しています',
  stage_starttls: 'メールサーバーと話しています',
  stage_grade: '評価しています',

  card_grade: '評価の内訳',
  card_mx: 'メールサーバー',
  card_spf: 'SPF',
  card_spf_tree: 'SPF の展開',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: '経路の保護',
  card_sessions: 'SMTP セッション',
  card_rdns: '逆引き DNS',

  comp_authentication: '認証',
  comp_transport: '経路',
  comp_hygiene: '衛生',

  k_mx_count: 'MX レコード',
  k_null_mx: 'null MX',
  k_ipv6_mx: 'IPv6 で到達可能',
  k_spf_record: 'レコード',
  k_spf_lookups: '使った DNS 問い合わせ',
  k_spf_voids: '空振りの問い合わせ',
  k_spf_policy: 'それ以外すべての既定の扱い',
  k_dkim_keys: '見つかった鍵',
  k_dkim_tried: '試したセレクター',
  k_dkim_strongest: '最も強い鍵',
  k_dmarc_policy: 'ポリシー',
  k_dmarc_subdomain: 'サブドメインのポリシー',
  k_dmarc_percent: '適用する割合',
  k_dmarc_alignment: '整合（DKIM / SPF）',
  k_dmarc_rua: '集計レポートの宛先',
  k_dmarc_ruf: '失敗レポートの宛先',
  k_dmarc_external: '外部への報告が許可済み',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'モード',
  k_mtasts_id: 'ポリシー ID',
  k_mtasts_maxage: '保持期間',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE（TLSA）',
  k_dane_covered: '対象のサーバー',
  k_starttls: 'STARTTLS',
  k_port25: '外向きのポート 25',
  k_open_relay: 'オープンリレー',
  k_rdns_confirmed: '正引きで確認済み',
  k_queries: '発行した問い合わせ',

  th_priority: '優先度',
  th_host: 'ホスト',
  th_addresses: 'アドレス',
  th_port: 'ポート',
  th_tls: 'TLS',
  th_banner: '挨拶',
  th_extensions: '告知',
  th_selector: 'セレクター',
  th_key_type: '鍵',
  th_bits: 'ビット',
  th_state: '状態',
  th_address: 'アドレス',
  th_ptr: 'PTR',
  th_confirmed: '確認済み',
  th_term: '項',
  th_lookup: '問い合わせ',

  pol_none: 'none — 観察のみ',
  pol_quarantine: 'quarantine — 迷惑メールへ',
  pol_reject: 'reject — 受け取らない',
  spfp_pass: '全員を通す（+all）',
  spfp_fail: '拒否する（-all）',
  spfp_softfail: 'ソフトフェイル（~all）',
  spfp_neutral: '中立（?all）',
  spfp_redirect: 'redirect による委任',
  spfterm_no_target: '宛先がない',
  spfterm_loop: '循環 — すでに通った',
  spfterm_lookup_failed: '問い合わせに失敗',
  spfterm_no_spf_record: 'そこに SPF レコードはない',

  stsmode_enforce: 'enforce — 適用する',
  stsmode_testing: 'testing — 報告のみ',
  stsmode_none: 'none — 無効',
  rdns_confirmed: '確認済み',
  rdns_unconfirmed: '戻りが一致しない',
  rdns_missing: 'PTR がない',
  rdns_unknown: '未確認',
  v_of_limit: '{limit} 回のうち {used} 回',
  v_percent: '{n}%',
  v_days_short: '{n} 日',
  v_blocked_here: '当方のネットワークから遮断',
  v_no_selector_found: '既知の {n} 個のセレクターすべてで見つからず',

  note_spf: 'RFC 7208 は、評価全体を通じて DNS 問い合わせを伴う項を十個まで許します。しかもすべての include の中のすべての include まで数えます。十を超えると受信側は permerror を返さなければならず、permerror とは SPF がまったく適用されないこと — レコードが存在しないのとまったく同じです。',
  note_dmarc: 'p=none では何も適用されません。SPF と DKIM の整合の両方に失敗したメールも、これまで通り配送されます。始める場所としては正しく、留まる場所としては間違っています。',
  note_transport: 'STARTTLS は日和見的です。提示を取り除かれた送信者はそのまま平文で続けます。MTA-STS と DANE は、その可能性を保証に変えるためのものです。',
  note_sessions: 'どのセッションも読み取り専用です。リレーの検査は RCPT TO で止めて RSET を送ります。DATA コマンドは決して出さないので、メールを送ることはできません。',
  note_rdns: 'PTR レコードだけでは何も証明できません — アドレス帯の持ち主はそこに好きな名前を書けます。受信側が確かめるのは、その名前が同じアドレスへ戻って解決するかどうかです。',

  err_smtp_timeout: 'メールサーバーが時間内に応答しませんでした。',
  err_smtp_network: 'メールサーバーに到達できませんでした。',
  err_smtp_refused: 'メールサーバーが接続を拒否しました。',
  err_tls_failed: 'メールサーバーとの TLS ハンドシェイクに失敗しました。',

  inc_mx_lookup_failed: 'MX レコードを読めませんでした',
  inc_spf_lookup_failed: 'SPF レコードを読めませんでした',
  inc_dmarc_lookup_failed: 'DMARC レコードを読めませんでした',
  inc_port_25_unreachable_from_this_network: 'このサービスが動いている場所では外向きのポート 25 が塞がれているため、STARTTLS、実際の証明書との DANE 照合、リレーの検査は行えませんでした',
  inc_not_every_mx_was_probed: '優先度の高いサーバーにのみ接続しました',

  cap_open_relay: 'サーバーが見ず知らずの相手のメールを中継している',
  cap_spf_authorises_everyone: 'SPF がインターネット全体を許可している',
  cap_no_mail_servers: 'メールサーバーがない',
  cap_mail_servers_unreachable: 'ポート 25 でどのメールサーバーも応答しなかった',
  cap_dane_mismatch: 'DANE が提示された証明書と一致しない',
  cap_mtasts_policy_contradicts_dns: 'MTA-STS ポリシーが実在のメールサーバーを取りこぼしている',
  cap_spf_over_the_lookup_limit: 'SPF が問い合わせの上限を超えている',
  cap_spf_permerror: 'SPF が恒久的なエラー',
  cap_dmarc_permerror: 'DMARC が恒久的なエラー',
  cap_mail_in_the_clear: 'メールが暗号化なしで受け付けられている',
  cap_no_spf: 'SPF レコードがない',
  cap_no_dmarc: 'DMARC レコードがない',
  cap_starttls_broken: 'STARTTLS を提示しているのに機能しない',
  cap_dmarc_not_enforcing: 'DMARC が何も適用していない',
  cap_no_reverse_dns: '確認済みの逆引き DNS がない',
  cap_spf_without_a_default: 'SPF に既定の扱いがない',
  cap_weak_dkim_key: '短すぎる DKIM 鍵',
  cap_dmarc_reports_go_nowhere: 'DMARC レポートが許可されていない',
  cap_mail_server_does_not_resolve: 'メールサーバーが名前解決できない',
  cap_scan_incomplete: '検査が不完全なため、評価は付けていません',

  flag_null_mx: 'このドメインはメールを扱わないと宣言しています',
  fd_null_mx: '優先度 0 でルートを指す MX が一つだけ、というのは RFC 7505 の「このドメインはメールを送りも受けもしない」です。意図的であり、MX がまったくないよりずっと良いものです — MX がなければ送信者はアドレスレコードに落ちてしまいます。',

  flag_no_mx: 'MX レコードがありません',
  fd_no_mx: 'このドメイン宛のメールをどこへ送るのか何も示されておらず、代わりに使えるアドレスもありません。つまり配送しようがありません。',

  flag_no_mx_falls_back_to_a: 'MX がないため送信者は A レコードに落ちます',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 は、MX のない送信者にアドレスレコードを試すよう定めています。このドメイン宛のメールは、ウェブサーバーのポート 25 で待ち受けている何かへ配送されます — それが意図であることはまずありません。',

  flag_duplicate_mx_host: '同じホストが二度挙げられています',
  fd_duplicate_mx_host: '一つのホストが複数の優先度に現れています。これは冗長化ではなく、同じ機械を二度試すだけです。',

  flag_mx_does_not_resolve: 'メールサーバーの名前が解決しません',
  fd_mx_does_not_resolve: 'MX がアドレスレコードを持たないホストを指しています。この優先度に達した送信者はいちいち問い合わせを待ち、何も得られず、次へ進みます — すぐ届くはずのメールが遅れます。',

  flag_mx_points_at_cname: 'MX レコードが別名を指しています',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 は、MX が CNAME ではなくアドレスレコードを持つホストを指すことを求めています。切り抜ける送信者もあれば拒む送信者もあり、その内訳は時とともに変わります。',

  flag_single_mx: 'メールサーバーが一台だけ',
  fd_single_mx: 'MX が一つだけなら、その停止はそのまま送信者側での滞留と再試行を意味します — 各社の方針しだいで数時間から数日 — そしてその一部は最終的に差し戻されます。',

  flag_no_ipv6_mx: 'IPv6 で到達できるメールサーバーがありません',
  fd_no_ipv6_mx: 'IPv6 のみの網にいる送信者は、翻訳装置を経てしかこのドメインに届きません（届けばの話です）。',

  flag_spf_missing: 'SPF レコードがありません',
  fd_spf_missing: 'どのサーバーがこのドメインとしてメールを送ってよいのか何も示されておらず、突き合わせる相手がありません。SPF は TXT レコード一つで、このページで最も安上がりなものです。',

  flag_spf_multiple_records: 'SPF レコードが複数あります',
  fd_spf_multiple_records: 'RFC 7208 §4.5 は二つのレコードを恒久的なエラーとし、permerror とは SPF の結果がまったく出ないこと — 二つ目を足したときの狙いとは正反対です。一つにまとめる必要があります。',

  flag_spf_too_many_lookups: 'SPF に十回を超える DNS 問い合わせが要ります',
  fd_spf_too_many_lookups: 'RFC 7208 §4.6.4 の上限は、評価全体を通じて問い合わせを伴う項が十個、しかもすべての include の中のすべての include まで数えます。それを超えると受信側は permerror を返さねばならず、SPF は適用されなくなります — レコードなど無くても同じです。事業者をもう一つ足すだけで簡単に超え、しかもレコード自体を見ても何も分かりません。',

  flag_spf_lookups_near_limit: 'SPF が十回の上限に近づいています',
  fd_spf_lookups_near_limit: '余裕がほとんど残っていません。次に足すサービス — あるいはあなたの手の届かない、他人の include の中の変更 — でそれを超えます。',

  flag_spf_too_many_void_lookups: '何も返さない SPF の問い合わせが多すぎます',
  fd_spf_too_many_void_lookups: 'RFC 7208 は何にも解決しない問い合わせを二回まで許します。それを超えると恒久的なエラーです。たいていは使わなくなったサービスの include が残っているだけです。',

  flag_spf_no_all: 'SPF に既定の扱いがありません',
  fd_spf_no_all: '「all」機構も redirect もなければ、どれにも当たらなかった送信者は中立という結果になります — 何の意見も持たないのと同じです。',

  flag_spf_plus_all: 'SPF がインターネット全体を許可しています',
  fd_spf_plus_all: '「+all」は、どこのどのホストでもこのドメインとして送ってよい、という意味です。ほとんどの場合は修飾子の誤解であり、SPF が無いよりも悪い — 偽装する側をはっきり保証してしまうからです。',

  flag_spf_neutral_all: 'SPF が ?all で終わっています',
  fd_spf_neutral_all: '「?all」は、どれにも当たらない送信者について何も言わないと明言するものです。受信側はこれを結果なしとして扱います。',

  flag_spf_softfail_all: 'SPF が -all ではなく ~all で終わっています',
  fd_spf_softfail_all: 'ソフトフェイルは、受け取ったうえで印を付けるよう受信側に求めます。誰が自分の名前で送っているかをまだ把握中なら正しい設定であり、把握できたら締めるべきところです。',

  flag_spf_uses_ptr: 'SPF が ptr 機構を使っています',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 はこれを率直に非推奨としています。遅く、当てにならず、逆引きゾーンを運用する側に手間を押しつけます。まったく無視する受信側もあります。',

  flag_spf_unknown_mechanism: 'SPF に誰にも分からない項があります',
  fd_spf_unknown_mechanism: '認識できない機構は RFC 7208 §4.6.1 により恒久的なエラーで、レコード全体が捨てられます。たいていは打ち間違いです。',

  flag_spf_duplicate_redirect: 'redirect 修飾子が複数あります',
  fd_spf_duplicate_redirect: '二つ目の redirect はレコードを恒久的なエラーにします。',

  flag_spf_redirect_after_all: '決してたどり着かない redirect',
  fd_spf_redirect_after_all: 'レコードに「all」機構と redirect の両方があります。「all」は必ず一致するので評価はそこで止まり、redirect は死んだ文字列になります。',

  flag_spf_record_long: 'SPF レコードが長い',
  fd_spf_record_long: '長いレコードは伝送時に複数の文字列へ分割されます。それ自体は問題なく — 受信側は何も挟まずに連結します — ただし、それらを空白でつなぐ実装がレコードを壊し始めるのはまさにここです。',

  flag_spf_include_loop: 'include がすでに通った先を指しています',
  fd_spf_include_loop: '展開が循環しています。受信側は問い合わせの上限で打ち切り、恒久的なエラーを返します。',

  flag_spf_include_without_record: 'include が SPF レコードのないドメインを指しています',
  fd_spf_include_without_record: 'RFC 7208 §5.2 はこれを、単に無駄な問い合わせではなく恒久的なエラーとします。片側で終了し、もう片側で消し忘れたサービスであることがほとんどです。',

  flag_dkim_no_known_selector: '知っているセレクターのどれにも DKIM 鍵がありません',
  fd_dkim_no_known_selector: 'セレクターは署名する側が決め、署名済みメールのヘッダーにしか現れないため、外から列挙することはできません。これは DKIM が無い証拠にはなりません — 自分のセレクターをご存じなら ?selector= で渡してください。検査は確定的になります。',

  flag_dkim_key_revoked: 'DKIM 鍵が失効させられています',
  fd_dkim_key_revoked: 'p= を空にしてレコードが公開されており、これは鍵の失効です。鍵を退役させる正しいやり方であり — 何か月もその状態のレコードは、たいてい誰も締めくくらなかった鍵交換です。',

  flag_dkim_key_malformed: 'DKIM 鍵が読み取れません',
  fd_dkim_key_malformed: 'p= の値が正しい鍵素材ではありません。それで作られた署名はすべて検証に通りません。',

  flag_dkim_in_test_mode: 'DKIM レコードがテストモードです',
  fd_dkim_in_test_mode: 't=y は、署名が失敗しても DKIM を使っていないかのように扱うよう受信側に伝えます。居場所は導入作業中だけで、ほかにはありません。',

  flag_dkim_key_too_short: 'DKIM 鍵が 1024 ビット未満です',
  fd_dkim_key_too_short: '1024 ビットを下回ると署名の偽造はさほど難しくなく、多くの受信側はそうした鍵をそもそも無視します。',

  flag_dkim_key_1024_bit: 'DKIM 鍵が 1024 ビットです',
  fd_dkim_key_1024_bit: 'いまもどこでも受け入れられますが、現在の推奨を下回ります。通常の大きさは 2048 で、交換は新しいセレクターと DNS レコード一つです。',

  flag_dmarc_missing: 'DMARC レコードがありません',
  fd_dmarc_missing: 'DMARC がなければ、SPF と DKIM の結果は参考にすぎません。読者が実際に見るアドレスと結びつけるものが何もなく、失敗したときにどうするかを受信側に伝えるものもありません。',

  flag_dmarc_inherited: 'DMARC は親ドメインから継承されています',
  fd_dmarc_inherited: 'この名前に独自のレコードはなく、組織ドメインのポリシーが適用されます — sp= があればその値、なければ p= の値です。',

  flag_dmarc_multiple_records: 'DMARC レコードが複数あります',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3：レコードが複数あるとポリシーは丸ごと捨てられ、何も公開していないのと同じ扱いになります。',

  flag_dmarc_no_policy: 'DMARC レコードに p= タグがありません',
  fd_dmarc_no_policy: 'p= は必須です。それがなければレコードは無視されます。',

  flag_dmarc_invalid_policy: 'DMARC ポリシーが認識できる値ではありません',
  fd_dmarc_invalid_policy: 'p= は none、quarantine、reject のいずれかでなければなりません。それ以外だと受信側はレコードを捨てます。',

  flag_dmarc_policy_none: 'DMARC が何も適用していません',
  fd_dmarc_policy_none: 'p=none は、報告だけして扱いは変えないよう受信側に求めます。SPF と DKIM の整合の両方に失敗したメールも、DMARC が無い場合とまったく同じに配送されます。始め方としては正しく — そして非常に多くのドメインが、守られているつもりで何年もここに留まっています。',

  flag_dmarc_policy_quarantine: 'DMARC が拒否ではなく隔離をしています',
  fd_dmarc_policy_quarantine: '失敗したメールは拒否されず迷惑メールフォルダーへ入ります。reject へ向かう妥当な一歩であり、偽装されたメールがなお人の目に届く場所でもあります。',

  flag_dmarc_subdomain_policy_none: 'サブドメインがポリシーの対象外です',
  fd_dmarc_subdomain_policy_none: 'sp=none は、ドメイン自体が守られている一方で、存在したことのないものも含めてあらゆるサブドメインを詐称に開いたままにします。',

  flag_dmarc_partial_percentage: 'ポリシーがメールの一部にしか適用されていません',
  fd_dmarc_partial_percentage: 'pct= が 100 未満だと、失敗したメールのうちその割合にだけポリシーを適用し、残りはより緩やかに扱うよう受信側に伝えます。導入中は便利で、置いてある間はずっと穴です。',

  flag_dmarc_no_reporting: '集計レポートの宛先がありません',
  fd_dmarc_no_reporting: 'rua= がないとレポートは届きません。つまり、誰があなたのドメインとして送っているのか、ポリシーを締めたら何が壊れるのかを知る手立てがないということです。',

  flag_dmarc_external_reporting_unauthorised: '外部のレポート宛先があなたを許可していません',
  fd_dmarc_external_reporting_unauthorised: 'レポートが別のドメインに向けられており、そのドメインは受け取りに同意するレコードを公開していません（RFC 7489 §7.1）。規格に従う受信側は何も送りません。DMARC レコードは申し分なく見え、レポートは永遠に来ない — そしてそれはほぼ必ず「レポートは時間がかかる」で片づけられます。',

  flag_mtasts_missing: 'MTA-STS ポリシーがありません',
  fd_mtasts_missing: 'STARTTLS は日和見的です。提示が見えない送信者は平文で送りますし、その提示を取り除くのは二つのサーバーの間にいる者にとって容易です。MTA-STS は、このドメインが常に TLS で話すことを HTTPS 上で公開し、その攻撃に代わりにウェブ PKI を破ることを要求します。',

  flag_mtasts_multiple_records: 'MTA-STS の TXT レコードが複数あります',
  fd_mtasts_multiple_records: 'どの ID が現行なのか送信側には分からず、ポリシーが変わっても更新されないおそれがあります。',

  flag_mtasts_no_id: 'MTA-STS レコードに ID がありません',
  fd_mtasts_no_id: 'ID は、手元のポリシーの写しが古いことを送信者が知る手がかりです。それがないと、変更したポリシーが max_age の満了まで取り込まれないことがあります。',

  flag_mtasts_policy_host_missing: 'ポリシーのホストが解決しません',
  fd_mtasts_policy_host_missing: 'TXT レコードはポリシーを宣言しているのに mta-sts.<ドメイン> にアドレスがなく、どの送信者もそれを取得できません。',

  flag_mtasts_policy_host_private: 'ポリシーのホストが私設アドレス空間に解決します',
  fd_mtasts_policy_host_private: 'ポリシーは取得していません。ホストが、このサービスが接続しないアドレスを指しています。',

  flag_mtasts_policy_unreachable: 'MTA-STS ポリシーを取得できませんでした',
  fd_mtasts_policy_unreachable: 'TXT レコードは、そこに無いか証明書が検証できないポリシーを約束しています。仕組み全体がその HTTPS 証明書に乗っているので、ここでの失敗は送信者が日和見的な TLS へ戻ることを意味します。',

  flag_mtasts_policy_wrong_content_type: 'ポリシーが text/plain で提供されていません',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 は text/plain を要求します。厳格な送信者は受け付けません。',

  flag_mtasts_policy_bad_version: 'ポリシーのバージョンが STSv1 ではありません',
  fd_mtasts_policy_bad_version: '送信者は、バージョンが分からないポリシーを使いません。',

  flag_mtasts_policy_bad_mode: 'ポリシーのモードが認識できる値ではありません',
  fd_mtasts_policy_bad_mode: 'mode は enforce、testing、none のいずれかでなければなりません。',

  flag_mtasts_mode_testing: 'MTA-STS がテストモードです',
  fd_mtasts_mode_testing: '失敗は報告されますがメールはそのまま配送されるので、このポリシーはまだ何も守っていません。途中の駅であって、目的地ではありません。',

  flag_mtasts_mode_none: 'MTA-STS が自らのポリシーで無効化されています',
  fd_mtasts_mode_none: 'mode=none はポリシーを撤回します。ドメインが MTA-STS をきれいにやめられるようにするためのもので、そのまま置いておくと、単にレコードが何もしないという意味になります。',

  flag_mtasts_no_max_age: 'ポリシーに max_age がありません',
  fd_mtasts_no_max_age: 'max_age は必須で、ポリシーを握りつぶされにくくしているのもこれです — 一度取り込んだ送信者は適用を続けます。',

  flag_mtasts_max_age_short: 'ポリシーの保持期間が一日未満です',
  fd_mtasts_max_age_short: '短い max_age は、取り込まれたポリシーが送信者を守る窓を狭めます。ポリシーが安定したら数週間にするのが普通です。',

  flag_mtasts_mx_not_in_policy: 'ポリシーに実在のメールサーバーが欠けています',
  fd_mtasts_mx_not_in_policy: 'MX の組に、ポリシーのどの mx: パターンにも当たらないホストがあります。このポリシーを守る送信者はそのホストへの配送を拒みます — つまり、慎重にふるまう送信者に限ってメールが失敗します。',

  flag_mtasts_policy_lists_unknown_mx: 'ポリシーに、現在の MX のどれにも当たらないパターンがあります',
  fd_mtasts_policy_lists_unknown_mx: '無害で、たいていは移行の名残です。ポリシーが現実を語り続けるよう、片づける価値はあります。',

  flag_mtasts_policy_no_mx: 'ポリシーにメールサーバーが一つも並んでいません',
  fd_mtasts_policy_no_mx: 'mx: の項目がないポリシーは何にも当たらないので、それを守る送信者には配送先がありません。',

  flag_tlsrpt_missing: 'TLS-RPT レコードがありません',
  fd_tlsrpt_missing: 'TXT レコード一つで、送信者があなたのサーバーと TLS を合意できていないことを知る唯一の手立てです。それがないと、期限切れの証明書や壊れた STARTTLS はあなたの側からまったく見えません。',

  flag_tlsrpt_no_rua: 'TLS-RPT レコードに宛先がありません',
  fd_tlsrpt_no_rua: 'rua= がなければレポートの行き先がなく、レコードは何もしません。',

  flag_dane_missing: 'DANE レコードがありません',
  fd_dane_missing: 'TLSA レコードは、メールサーバーが提示すべき証明書を、公開認証局ではなく DNSSEC を頼りに固定します。二つの経路保護のうち強いほうであり — 署名済みのゾーンを必要とし、それが使われていない通常の理由でもあります。',

  flag_dane_partial: '一部のメールサーバーにしか DANE レコードがありません',
  fd_dane_partial: '送信者は優先度でサーバーを選ぶので、一部のホストだけ固定された組は、時間の一部しか守られていません。',

  flag_dane_without_dnssec: '署名のないゾーンにある TLSA レコード',
  fd_dane_without_dnssec: 'DANE は完全に DNSSEC の上に乗っています。署名がなければ、MX レコードを差し替えられる者は TLSA レコードも差し替えられます。固定は何も守らず、守っているように見えるだけです。',

  flag_dane_mismatch: 'TLSA レコードが提示された証明書と一致しません',
  fd_dane_mismatch: 'サーバーが、自分の DANE レコードが認めていない証明書を提示しています。DANE を検証する送信者はすべて配送を拒みます — メールが止まります。',

  flag_dane_pkix_usage: 'TLSA レコードが PKIX の用法を使っています',
  fd_dane_pkix_usage: '用法 0 と 1 は、証明書が公開認証局を通じても検証できることを求めます。RFC 7672 §3.1 はどちらも SMTP では禁じています。メールについてその確認を行う合意された方法が存在しないからです。',

  flag_dane_full_certificate: 'TLSA レコードが証明書全体を固定しています',
  fd_dane_full_certificate: '照合タイプ 0 はハッシュではなく証明書そのものを収めます。動きますが、レコードが大きくなり、更新のたびに差し替えが要ります。',

  flag_port_25_blocked_from_here: 'このサービスが動いている場所では外向きのポート 25 が塞がれています',
  fd_port_25_blocked_from_here: 'これは当方のネットワークの話であって、あなたのではありません。多くのホスティング事業者はポート 25 への外向き接続を既定で塞ぎます。そのため STARTTLS、実際の証明書との DANE 照合、リレーの検査は行えず、たまたま届いた範囲から算出する代わりに評価を保留しています。',

  flag_mx_not_reachable_on_25: 'ポート 25 でどのメールサーバーも応答しませんでした',
  fd_mx_not_reachable_on_25: 'MX レコードが挙げるホストは、メールを配送するポートで接続を受け付けません。このドメインには何も配送できません。',

  flag_no_starttls: 'メールサーバーが STARTTLS を提示しません',
  fd_no_starttls: 'このサーバーへ配送されるメールはすべて暗号化されずにインターネットを渡り、経路上のあらゆるものに読まれます。STARTTLS の提示にかかるのは証明書一枚と設定一行です。',

  flag_starttls_fails: 'STARTTLS を提示しているのに機能しません',
  fd_starttls_fails: 'サーバーは STARTTLS を告知し、ハンドシェイクは失敗します。慎重な送信者は平文へ戻ることを拒み、メールを保留するかもしれません — つまり、まったく提示しないよりも悪い状態です。',

  flag_starttls_legacy_protocol: 'メールサーバーが旧式の TLS で合意しています',
  fd_starttls_legacy_protocol: 'TLS 1.0 と 1.1 は RFC 8996 以降、非推奨です。送信者は順次サポートを外しており、外し終えたときメールは届かなくなります。',

  flag_mx_certificate_not_trusted: 'メールサーバーの証明書が検証できません',
  fd_mx_certificate_not_trusted: '通常の日和見的 TLS は証明書を検証しないので、今日のところ配送は妨げません。enforce モードの MTA-STS か DANE が関わった瞬間、完全に妨げます。',

  flag_banner_reveals_version: '挨拶がソフトウェアとその版を名乗っています',
  fd_banner_reveals_version: 'その版に既知の不具合があるホストを探している者への、ささやかな贈り物です。挨拶には何とでも書けます。',

  flag_open_relay: 'サーバーが見ず知らずの相手のメールを中継しています',
  fd_open_relay: '無関係な送信者から無関係な宛先へのメールを受け付けました。誰でもあなたの名前で迷惑メールを送れますし、まだでなければ数時間のうちにブロックリストに載ります。これは今日直すものです。（検査は RCPT TO で止めて RSET を送りました — メールは一通も送っていません。）',

  flag_no_size_extension: 'サーバーが SIZE を告知しません',
  fd_no_size_extension: 'SIZE がないと、送信者は大きなメールが受け入れられるかどうかを、全部送り終えるまで知ることができません。',

  flag_submission_without_starttls: '投稿ポートが STARTTLS を提示しません',
  fd_submission_without_starttls: 'ポート 587 はメールソフトが認証を行う場所です。STARTTLS がなければ、その資格情報は平文でネットワークを渡ります。',

  flag_rdns_missing: 'メールサーバーのアドレスに PTR レコードがありません',
  fd_rdns_missing: '逆引き DNS の欠落は、新しいサーバーからのメールが保留されたり迷惑メール扱いされたりする最もありふれた理由の一つであり — 受信側が最も説明しない理由の一つでもあります。',

  flag_rdns_not_confirmed: '逆引き DNS が戻って一致しません',
  fd_rdns_not_confirmed: 'PTR レコードは名前を返しますが、その名前はこのアドレスへ解決しません。受信側が往復を確かめるのは、それが異なる二者それぞれの仕事を要求するからです。',

  flag_rdns_none_confirmed: '確認済みの逆引き DNS を持つメールサーバーが一つもありません',
  fd_rdns_none_confirmed: '往復の確認を通るアドレスが一つもありません。これを重く見る受信側では、配送の遅れと迷惑メール扱いを見込んでください。',
};

OWN.hi = {
  title: 'मेल जाँच — किसी भी डोमेन के लिए SPF, DKIM, DMARC, MTA-STS और DANE',
  title_short: 'मेल जाँच',
  h1: 'मेल जाँच',
  subtitle: 'SPF हर include से होकर खोला जाता है और दस की सीमा के सामने गिना जाता है, DMARC का संरेखण और रिपोर्टिंग, और परिवहन की सुरक्षा असली कनेक्शन पर परखी जाती है',
  ph_host: 'example.com',
  hero_label: 'जाँचा जा रहा डोमेन',
  empty_hint: 'एक डोमेन नाम डालें। जाँच SPF अभिलेख को हर include से होकर खोलती है, बड़े प्लेटफ़ॉर्म जिन DKIM चयनकों का उपयोग करते हैं उन्हें आज़माती है, DMARC नीति पढ़ती है, MTA-STS नीति HTTPS से लाती है और मेल सर्वरों से केवल-पढ़ने वाले SMTP सत्र खोलती है। कोई संदेश कभी नहीं भेजा जाता।',

  stage_resolve: 'मेल सर्वर खोजे जा रहे हैं',
  stage_mx: 'MX समूह की जाँच',
  stage_spf: 'SPF खोला जा रहा है',
  stage_dkim: 'DKIM कुंजियाँ खोजी जा रही हैं',
  stage_dmarc: 'DMARC नीति पढ़ी जा रही है',
  stage_mtasts: 'MTA-STS नीति लाई जा रही है',
  stage_dane: 'DANE की जाँच',
  stage_starttls: 'मेल सर्वरों से बातचीत',
  stage_grade: 'श्रेणी निर्धारण',

  card_grade: 'श्रेणी का विवरण',
  card_mx: 'मेल सर्वर',
  card_spf: 'SPF',
  card_spf_tree: 'SPF का विस्तार',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'परिवहन की सुरक्षा',
  card_sessions: 'SMTP सत्र',
  card_rdns: 'उल्टा DNS',

  comp_authentication: 'प्रामाणिकता',
  comp_transport: 'परिवहन',
  comp_hygiene: 'स्वच्छता',

  k_mx_count: 'MX अभिलेख',
  k_null_mx: 'शून्य MX',
  k_ipv6_mx: 'IPv6 से पहुँच योग्य',
  k_spf_record: 'अभिलेख',
  k_spf_lookups: 'उपयोग किए गए DNS प्रश्न',
  k_spf_voids: 'खाली प्रश्न',
  k_spf_policy: 'बाकी सबके लिए डिफ़ॉल्ट',
  k_dkim_keys: 'मिली कुंजियाँ',
  k_dkim_tried: 'आज़माए गए चयनक',
  k_dkim_strongest: 'सबसे मज़बूत कुंजी',
  k_dmarc_policy: 'नीति',
  k_dmarc_subdomain: 'उपडोमेन की नीति',
  k_dmarc_percent: 'लागू होती है',
  k_dmarc_alignment: 'संरेखण (DKIM / SPF)',
  k_dmarc_rua: 'सारांश रिपोर्ट यहाँ',
  k_dmarc_ruf: 'विफलता रिपोर्ट यहाँ',
  k_dmarc_external: 'बाहरी रिपोर्टिंग अधिकृत',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'विधा',
  k_mtasts_id: 'नीति पहचानकर्ता',
  k_mtasts_maxage: 'संचित रहती है',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'शामिल सर्वर',
  k_starttls: 'STARTTLS',
  k_port25: 'बाहर जाने वाला पोर्ट 25',
  k_open_relay: 'खुला रिले',
  k_rdns_confirmed: 'आगे की ओर पुष्ट',
  k_queries: 'किए गए प्रश्न',

  th_priority: 'प्राथमिकता',
  th_host: 'होस्ट',
  th_addresses: 'पते',
  th_port: 'पोर्ट',
  th_tls: 'TLS',
  th_banner: 'अभिवादन',
  th_extensions: 'घोषित',
  th_selector: 'चयनक',
  th_key_type: 'कुंजी',
  th_bits: 'बिट',
  th_state: 'स्थिति',
  th_address: 'पता',
  th_ptr: 'PTR',
  th_confirmed: 'पुष्ट',
  th_term: 'पद',
  th_lookup: 'प्रश्न',

  pol_none: 'none — केवल निगरानी',
  pol_quarantine: 'quarantine — स्पैम में',
  pol_reject: 'reject — अस्वीकार',
  spfp_pass: 'सबको जाने दें (+all)',
  spfp_fail: 'अस्वीकार करें (-all)',
  spfp_softfail: 'नरम विफलता (~all)',
  spfp_neutral: 'तटस्थ (?all)',
  spfp_redirect: 'redirect से सौंपा गया',
  spfterm_no_target: 'कोई लक्ष्य नहीं',
  spfterm_loop: 'चक्र — पहले ही आ चुके',
  spfterm_lookup_failed: 'प्रश्न विफल',
  spfterm_no_spf_record: 'वहाँ SPF अभिलेख नहीं है',

  stsmode_enforce: 'enforce — लागू करें',
  stsmode_testing: 'testing — केवल रिपोर्ट',
  stsmode_none: 'none — बंद',
  rdns_confirmed: 'पुष्ट',
  rdns_unconfirmed: 'वापस हल नहीं होता',
  rdns_missing: 'PTR नहीं है',
  rdns_unknown: 'जाँचा नहीं गया',
  v_of_limit: '{limit} में से {used}',
  v_percent: '{n}%',
  v_days_short: '{n} दि',
  v_blocked_here: 'हमारे नेटवर्क से अवरुद्ध',
  v_no_selector_found: '{n} ज्ञात चयनकों में से एक भी नहीं',

  note_spf: 'RFC 7208 पूरी गणना में DNS प्रश्न करने वाले दस पदों की अनुमति देता है, और हर include के भीतर के हर include को भी गिना जाता है। दस के बाद प्राप्तकर्ता को permerror लौटाना ही पड़ता है — और permerror का अर्थ है कि SPF लागू ही नहीं होता, ठीक वैसे जैसे कोई अभिलेख हो ही न।',
  note_dmarc: 'p=none के साथ कुछ भी लागू नहीं होता: जो संदेश SPF और DKIM दोनों के संरेखण में विफल होता है वह पहले की तरह ही पहुँचा दिया जाता है। शुरू करने के लिए यह सही जगह है और ठहरने के लिए ग़लत।',
  note_transport: 'STARTTLS अवसरवादी है: जिस भेजने वाले से यह प्रस्ताव छीन लिया जाए वह बस खुले पाठ में आगे बढ़ जाता है। MTA-STS और DANE ही वह चीज़ हैं जो इस संभावना को गारंटी में बदलती हैं।',
  note_sessions: 'हर सत्र केवल पढ़ने के लिए है। रिले की जाँच RCPT TO पर रुकती है और RSET भेजती है; DATA आदेश कभी नहीं दिया जाता, इसलिए कोई संदेश भेजा ही नहीं जा सकता।',
  note_rdns: 'अकेला PTR अभिलेख कुछ भी सिद्ध नहीं करता — पतों के खंड का मालिक वहाँ कोई भी नाम लिख सकता है। प्राप्तकर्ता यह देखते हैं कि वह नाम उसी पते पर वापस हल होता है या नहीं।',

  err_smtp_timeout: 'मेल सर्वर ने समय पर उत्तर नहीं दिया।',
  err_smtp_network: 'मेल सर्वर तक पहुँचा नहीं जा सका।',
  err_smtp_refused: 'मेल सर्वर ने कनेक्शन अस्वीकार कर दिया।',
  err_tls_failed: 'मेल सर्वर के साथ TLS हाथ मिलाना विफल रहा।',

  inc_mx_lookup_failed: 'MX अभिलेख पढ़े नहीं जा सके',
  inc_spf_lookup_failed: 'SPF अभिलेख पढ़ा नहीं जा सका',
  inc_dmarc_lookup_failed: 'DMARC अभिलेख पढ़ा नहीं जा सका',
  inc_port_25_unreachable_from_this_network: 'जहाँ यह सेवा चलती है वहाँ बाहर जाने वाला पोर्ट 25 अवरुद्ध है, इसलिए STARTTLS, असली प्रमाणपत्र से DANE का मिलान और रिले की जाँच नहीं हो सकी',
  inc_not_every_mx_was_probed: 'केवल सबसे ऊँची प्राथमिकता वाले सर्वरों से जुड़ा गया',

  cap_open_relay: 'सर्वर अजनबियों की डाक आगे भेजता है',
  cap_spf_authorises_everyone: 'SPF पूरे इंटरनेट को अधिकृत करता है',
  cap_no_mail_servers: 'कोई मेल सर्वर नहीं',
  cap_mail_servers_unreachable: 'पोर्ट 25 पर किसी मेल सर्वर ने उत्तर नहीं दिया',
  cap_dane_mismatch: 'DANE प्रस्तुत प्रमाणपत्र से मेल नहीं खाता',
  cap_mtasts_policy_contradicts_dns: 'MTA-STS नीति में एक असली मेल सर्वर छूटा है',
  cap_spf_over_the_lookup_limit: 'SPF प्रश्नों की सीमा से बाहर है',
  cap_spf_permerror: 'SPF एक स्थायी त्रुटि है',
  cap_dmarc_permerror: 'DMARC एक स्थायी त्रुटि है',
  cap_mail_in_the_clear: 'डाक बिना कूटलेखन के स्वीकार की जाती है',
  cap_no_spf: 'कोई SPF अभिलेख नहीं',
  cap_no_dmarc: 'कोई DMARC अभिलेख नहीं',
  cap_starttls_broken: 'STARTTLS दिया जाता है और काम नहीं करता',
  cap_dmarc_not_enforcing: 'DMARC कुछ भी लागू नहीं करता',
  cap_no_reverse_dns: 'कोई पुष्ट उल्टा DNS नहीं',
  cap_spf_without_a_default: 'SPF का कोई डिफ़ॉल्ट नहीं',
  cap_weak_dkim_key: 'बहुत छोटी DKIM कुंजी',
  cap_dmarc_reports_go_nowhere: 'DMARC रिपोर्टें अधिकृत नहीं हैं',
  cap_mail_server_does_not_resolve: 'एक मेल सर्वर हल नहीं होता',
  cap_scan_incomplete: 'जाँच अधूरी रही, इसलिए कोई श्रेणी नहीं दी गई',

  flag_null_mx: 'डोमेन घोषित करता है कि वह डाक नहीं संभालता',
  fd_null_mx: 'प्राथमिकता 0 वाला अकेला MX जो जड़ की ओर इशारा करे, वह RFC 7505 का «यह डोमेन न डाक भेजता है न लेता है» है। यह जानबूझकर है और MX के बिल्कुल न होने से कहीं बेहतर — MX न हो तो भेजने वाले पते वाले अभिलेख पर लौट जाते हैं।',

  flag_no_mx: 'कोई MX अभिलेख नहीं',
  fd_no_mx: 'कुछ भी नहीं बताता कि इस डोमेन की डाक कहाँ जाए, और लौटने के लिए कोई पता भी नहीं है, इसलिए पहुँचाना बस असंभव है।',

  flag_no_mx_falls_back_to_a: 'MX न होने पर भेजने वाले A अभिलेख पर लौटते हैं',
  fd_no_mx_falls_back_to_a: 'RFC 5321 §5.1 बिना MX वाले भेजने वाले को पते वाला अभिलेख आज़माने को कहता है। इस डोमेन की डाक उसी को मिलेगी जो वेब सर्वर के पोर्ट 25 पर सुन रहा है — और यह शायद ही कभी अभिप्रेत होता है।',

  flag_duplicate_mx_host: 'वही होस्ट दो बार दर्ज है',
  fd_duplicate_mx_host: 'एक होस्ट एक से अधिक प्राथमिकताओं पर दिखता है। यह अतिरेक नहीं है; यह वही मशीन है जिसे दो बार आज़माया जाएगा।',

  flag_mx_does_not_resolve: 'किसी मेल सर्वर का नाम हल नहीं होता',
  fd_mx_does_not_resolve: 'MX ऐसे होस्ट का नाम लेता है जिसके पते वाले अभिलेख नहीं हैं। इस प्राथमिकता तक पहुँचा हर भेजने वाला प्रश्न की प्रतीक्षा करता है, कुछ नहीं पाता और आगे बढ़ जाता है — और जो डाक तुरंत पहुँचनी थी वह देर से पहुँचती है।',

  flag_mx_points_at_cname: 'एक MX अभिलेख उपनाम की ओर इशारा करता है',
  fd_mx_points_at_cname: 'RFC 2181 §10.3 माँगता है कि MX पते वाले होस्ट का नाम ले, CNAME का नहीं। कुछ भेजने वाले निभा लेते हैं, कुछ मना कर देते हैं, और कौन क्या करता है यह समय के साथ बदलता रहता है।',

  flag_single_mx: 'केवल एक मेल सर्वर',
  fd_single_mx: 'एक ही MX के साथ किसी भी रुकावट का मतलब है कि भेजने वाले कतार में डालकर दोबारा कोशिश करेंगे — अपनी-अपनी नीति के अनुसार घंटों या दिनों तक — और उस डाक का एक हिस्सा अंततः वापस लौट जाएगा।',

  flag_no_ipv6_mx: 'कोई मेल सर्वर IPv6 से पहुँच योग्य नहीं',
  fd_no_ipv6_mx: 'केवल-IPv6 नेटवर्क के भेजने वाले इस डोमेन तक अनुवादक के रास्ते पहुँचते हैं, अगर पहुँचते हैं तो।',

  flag_spf_missing: 'कोई SPF अभिलेख नहीं',
  fd_spf_missing: 'कुछ भी नहीं बताता कि कौन-से सर्वर इस डोमेन के नाम से डाक भेज सकते हैं, इसलिए मिलान करने को भी कुछ नहीं है। SPF एक TXT अभिलेख है और इस पूरे पन्ने की सबसे सस्ती चीज़।',

  flag_spf_multiple_records: 'एक से अधिक SPF अभिलेख',
  fd_spf_multiple_records: 'RFC 7208 §4.5 दो अभिलेखों को स्थायी त्रुटि बना देता है, और permerror का अर्थ है SPF का कोई परिणाम ही नहीं — दूसरा जोड़ने के इरादे के ठीक उलट। इन्हें एक में मिलाना चाहिए।',

  flag_spf_too_many_lookups: 'SPF को दस से अधिक DNS प्रश्न चाहिए',
  fd_spf_too_many_lookups: 'RFC 7208 §4.6.4 की सीमा पूरी गणना में प्रश्न करने वाले दस पद है, और हर include के भीतर के हर include को भी गिना जाता है। इसके आगे प्राप्तकर्ता को permerror लौटाना पड़ता है और SPF लागू होना बंद हो जाता है — अभिलेख न होता तो भी वही बात। एक और प्रदाता जोड़ते ही सीमा पार हो जाती है, और अभिलेख को देखकर यह बिल्कुल पता नहीं चलता।',

  flag_spf_lookups_near_limit: 'SPF दस प्रश्नों की सीमा के पास है',
  fd_spf_lookups_near_limit: 'गुंजाइश लगभग नहीं बची। अगली जोड़ी गई सेवा — या किसी और के include के भीतर का बदलाव, जिस पर आपका ज़ोर नहीं — इसे सीमा के पार ले जाएगी।',

  flag_spf_too_many_void_lookups: 'बहुत सारे SPF प्रश्न खाली लौटते हैं',
  fd_spf_too_many_void_lookups: 'RFC 7208 दो ऐसे प्रश्नों की छूट देता है जो कुछ नहीं देते; उससे आगे स्थायी त्रुटि है। आमतौर पर यह किसी अब अनुपयोगी सेवा का छूटा हुआ include होता है।',

  flag_spf_no_all: 'SPF का कोई डिफ़ॉल्ट नहीं',
  fd_spf_no_all: '«all» तंत्र और redirect दोनों के बिना, जिस भेजने वाले से कुछ मेल नहीं खाता उसे तटस्थ परिणाम मिलता है — जो कोई राय न रखने के बराबर है।',

  flag_spf_plus_all: 'SPF पूरे इंटरनेट को अधिकृत करता है',
  fd_spf_plus_all: '«+all» कहता है कि कहीं का भी कोई भी होस्ट इस डोमेन के नाम से भेज सकता है। यह लगभग हमेशा क्वालिफ़ायर की ग़लतफ़हमी है, और SPF के न होने से भी बुरा है, क्योंकि यह जालसाज़ के लिए स्पष्ट रूप से गारंटी देता है।',

  flag_spf_neutral_all: 'SPF ?all पर समाप्त होता है',
  fd_spf_neutral_all: '«?all» उन भेजने वालों के बारे में कुछ भी कहने से स्पष्ट इनकार करता है जिनसे कुछ मेल नहीं खाता। प्राप्तकर्ता इसे परिणाम की अनुपस्थिति मानते हैं।',

  flag_spf_softfail_all: 'SPF -all के बजाय ~all पर समाप्त होता है',
  fd_spf_softfail_all: 'नरम विफलता प्राप्तकर्ताओं से स्वीकार करने पर निशान लगाने को कहती है। जब तक आप पता लगा रहे हैं कि आपके नाम से कौन भेजता है, यह सही सेटिंग है; पता चल जाने पर यही कसने की चीज़ है।',

  flag_spf_uses_ptr: 'SPF ptr तंत्र का उपयोग करता है',
  fd_spf_uses_ptr: 'RFC 7208 §5.5 इसे सीधे-सीधे अप्रचलित घोषित करता है: यह धीमा है, भरोसेमंद नहीं है, और काम को उलटे ज़ोन चलाने वाले पर डाल देता है। कुछ प्राप्तकर्ता इसे पूरी तरह अनदेखा करते हैं।',

  flag_spf_unknown_mechanism: 'SPF में ऐसा पद है जिसे कोई नहीं समझता',
  fd_spf_unknown_mechanism: 'अपरिचित तंत्र RFC 7208 §4.6.1 के अनुसार स्थायी त्रुटि है और पूरे अभिलेख को रद्द कर देता है। आमतौर पर यह टाइपिंग की भूल होती है।',

  flag_spf_duplicate_redirect: 'एक से अधिक redirect संशोधक',
  fd_spf_duplicate_redirect: 'दूसरा redirect अभिलेख को स्थायी त्रुटि बना देता है।',

  flag_spf_redirect_after_all: 'ऐसा redirect जहाँ कभी नहीं पहुँचा जाएगा',
  fd_spf_redirect_after_all: 'अभिलेख में «all» तंत्र भी है और redirect भी। «all» हमेशा मेल खाता है, इसलिए गणना वहीं रुक जाती है और redirect मृत पाठ रह जाता है।',

  flag_spf_record_long: 'SPF अभिलेख लंबा है',
  fd_spf_record_long: 'लंबे अभिलेख भेजते समय कई हिस्सों में बँट जाते हैं। यह अपने आप में ठीक है — प्राप्तकर्ता उन्हें बिना कुछ डाले जोड़ लेते हैं — पर ठीक यहीं वे विश्लेषक अभिलेख को बिगाड़ना शुरू करते हैं जो उन्हें खाली स्थान से जोड़ते हैं।',

  flag_spf_include_loop: 'कोई include वहीं वापस इशारा करता है जहाँ पहले आ चुके',
  fd_spf_include_loop: 'विस्तार चक्र में पड़ जाता है। प्राप्तकर्ता प्रश्नों की सीमा पर रुककर स्थायी त्रुटि लौटा देता है।',

  flag_spf_include_without_record: 'कोई include ऐसे डोमेन की ओर है जिसमें SPF अभिलेख नहीं',
  fd_spf_include_without_record: 'RFC 7208 §5.2 इसे केवल बर्बाद हुआ प्रश्न नहीं, बल्कि स्थायी त्रुटि मानता है। आमतौर पर यह ऐसी सेवा है जो एक छोर पर हटा दी गई और दूसरे पर नहीं।',

  flag_dkim_no_known_selector: 'हमें ज्ञात किसी भी चयनक पर DKIM कुंजी नहीं मिली',
  fd_dkim_no_known_selector: 'चयनक वही चुनता है जो हस्ताक्षर करता है, और वे केवल हस्ताक्षरित संदेश के शीर्ष में दिखते हैं, इसलिए बाहर से उन्हें गिना नहीं जा सकता। यह इस बात का प्रमाण नहीं कि DKIM नहीं है — अगर आप अपना चयनक जानते हैं तो ?selector= से भेजें, जाँच निर्णायक हो जाएगी।',

  flag_dkim_key_revoked: 'एक DKIM कुंजी निरस्त कर दी गई है',
  fd_dkim_key_revoked: 'अभिलेख खाली p= के साथ प्रकाशित है, जो कुंजी को निरस्त करता है। किसी कुंजी को विदा करने का यही सही तरीका है — और महीनों से इसी हाल में पड़ा अभिलेख आमतौर पर ऐसी अदला-बदली है जिसे किसी ने पूरा नहीं किया।',

  flag_dkim_key_malformed: 'एक DKIM कुंजी पढ़ी नहीं जा सकती',
  fd_dkim_key_malformed: 'p= का मान वैध कुंजी सामग्री नहीं है। उससे बना हर हस्ताक्षर सत्यापन में विफल होगा।',

  flag_dkim_in_test_mode: 'एक DKIM अभिलेख परीक्षण विधा में है',
  fd_dkim_in_test_mode: 't=y प्राप्तकर्ताओं से कहता है कि विफल हस्ताक्षर को ऐसे लें मानो DKIM उपयोग में ही न हो। इसकी जगह केवल लागू करने की प्रक्रिया है, और कहीं नहीं।',

  flag_dkim_key_too_short: 'एक DKIM कुंजी 1024 बिट से छोटी है',
  fd_dkim_key_too_short: '1024 बिट से नीचे हस्ताक्षर की नकल बनाना ख़ास कठिन नहीं है, और कई प्राप्तकर्ता ऐसी कुंजियों को सीधे अनदेखा कर देते हैं।',

  flag_dkim_key_1024_bit: 'एक DKIM कुंजी 1024 बिट की है',
  fd_dkim_key_1024_bit: 'अब भी हर जगह स्वीकार्य है और मौजूदा सिफ़ारिशों से नीचे। सामान्य आकार 2048 है; बदलाव का अर्थ है एक नया चयनक और एक DNS अभिलेख।',

  flag_dmarc_missing: 'कोई DMARC अभिलेख नहीं',
  fd_dmarc_missing: 'DMARC के बिना SPF और DKIM के परिणाम केवल सलाह हैं: कुछ भी उन्हें उस पते से नहीं बाँधता जो पढ़ने वाला वास्तव में देखता है, और कुछ भी प्राप्तकर्ताओं को नहीं बताता कि विफलता पर क्या करें।',

  flag_dmarc_inherited: 'DMARC मूल डोमेन से विरासत में मिला है',
  fd_dmarc_inherited: 'इस नाम का अपना अभिलेख नहीं है, इसलिए संगठनात्मक डोमेन की नीति लागू होती है — उसका sp= यदि हो, अन्यथा उसका p=।',

  flag_dmarc_multiple_records: 'एक से अधिक DMARC अभिलेख',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: एक से अधिक अभिलेख होने पर नीति पूरी तरह छोड़ दी जाती है, मानो कोई प्रकाशित ही न की गई हो।',

  flag_dmarc_no_policy: 'DMARC अभिलेख में p= टैग नहीं है',
  fd_dmarc_no_policy: 'p= अनिवार्य है। उसके बिना अभिलेख अनदेखा कर दिया जाता है।',

  flag_dmarc_invalid_policy: 'DMARC नीति कोई पहचाना जाने वाला मान नहीं है',
  fd_dmarc_invalid_policy: 'p= none, quarantine या reject होना चाहिए। किसी और मान पर प्राप्तकर्ता अभिलेख छोड़ देते हैं।',

  flag_dmarc_policy_none: 'DMARC कुछ भी लागू नहीं करता',
  fd_dmarc_policy_none: 'p=none प्राप्तकर्ताओं से कहता है कि रिपोर्ट करें और कुछ न बदलें। जो संदेश SPF और DKIM दोनों के संरेखण में विफल होता है वह ठीक वैसे ही पहुँचाया जाता है जैसे DMARC के बिना। शुरू करने का यही सही तरीका है — और बहुत सारे डोमेन वर्षों से यहीं बैठे हैं, यह मानकर कि वे सुरक्षित हैं।',

  flag_dmarc_policy_quarantine: 'DMARC अस्वीकार करने के बजाय अलग रखता है',
  fd_dmarc_policy_quarantine: 'विफल डाक अस्वीकार होने के बजाय स्पैम फ़ोल्डर में जाती है। reject की ओर एक उचित क़दम, और वह जगह जहाँ जाली डाक अब भी लोगों तक पहुँचती है।',

  flag_dmarc_subdomain_policy_none: 'उपडोमेन नीति से बाहर हैं',
  fd_dmarc_subdomain_policy_none: 'sp=none हर उपडोमेन को — उन्हें भी जो कभी अस्तित्व में नहीं रहे — जालसाज़ी के लिए खुला छोड़ देता है, जबकि डोमेन स्वयं सुरक्षित रहता है।',

  flag_dmarc_partial_percentage: 'नीति डाक के केवल एक हिस्से पर लागू होती है',
  fd_dmarc_partial_percentage: '100 से कम pct= प्राप्तकर्ताओं से कहता है कि विफल संदेशों के उस अनुपात पर नीति लागू करें और बाक़ी के साथ नरमी बरतें। लागू करते समय उपयोगी है, और जब तक लगा है तब तक एक छेद।',

  flag_dmarc_no_reporting: 'सारांश रिपोर्टों के लिए कोई पता नहीं',
  fd_dmarc_no_reporting: 'rua= के बिना कोई रिपोर्ट नहीं आती, यानी यह जानने का कोई रास्ता नहीं कि आपके डोमेन के नाम से कौन भेज रहा है, या नीति कसने पर क्या टूटेगा।',

  flag_dmarc_external_reporting_unauthorised: 'बाहरी रिपोर्ट पते ने आपको अधिकृत नहीं किया',
  fd_dmarc_external_reporting_unauthorised: 'रिपोर्टें किसी और डोमेन को भेजी जा रही हैं, और वह डोमेन उन्हें लेने की सहमति वाला अभिलेख प्रकाशित नहीं करता (RFC 7489 §7.1)। नियम मानने वाले प्राप्तकर्ता कुछ नहीं भेजते। DMARC अभिलेख निर्दोष दिखता है और रिपोर्टें कभी नहीं आतीं — और इसे लगभग हमेशा «रिपोर्ट आने में समय लगता है» कहकर टाल दिया जाता है।',

  flag_mtasts_missing: 'कोई MTA-STS नीति नहीं',
  fd_mtasts_missing: 'STARTTLS अवसरवादी है: जिस भेजने वाले को यह प्रस्ताव दिखता ही नहीं वह खुले पाठ में भेज देता है, और दोनों सर्वरों के बीच खड़े किसी के लिए यह प्रस्ताव हटा देना आसान है। MTA-STS HTTPS पर प्रकाशित करता है कि यह डोमेन हमेशा TLS बोलता है, जिससे उस हमले के लिए वेब PKI तोड़नी पड़ती है।',

  flag_mtasts_multiple_records: 'एक से अधिक MTA-STS TXT अभिलेख',
  fd_mtasts_multiple_records: 'भेजने वाले नहीं बता सकते कि कौन-सा पहचानकर्ता मौजूदा है, इसलिए नीति बदलने पर ताज़ा न हो पाए।',

  flag_mtasts_no_id: 'MTA-STS अभिलेख में पहचानकर्ता नहीं है',
  fd_mtasts_no_id: 'पहचानकर्ता ही वह चीज़ है जिससे भेजने वाला जानता है कि उसके पास रखी नीति की प्रति पुरानी पड़ चुकी है। उसके बिना बदली हुई नीति max_age बीतने तक न उठाई जाए।',

  flag_mtasts_policy_host_missing: 'नीति का होस्ट हल नहीं होता',
  fd_mtasts_policy_host_missing: 'TXT अभिलेख एक नीति की घोषणा करता है, और mta-sts.<डोमेन> का कोई पता नहीं है, इसलिए कोई भी भेजने वाला उसे ला ही नहीं सकता।',

  flag_mtasts_policy_host_private: 'नीति का होस्ट निजी पता क्षेत्र में हल होता है',
  fd_mtasts_policy_host_private: 'नीति नहीं लाई गई: होस्ट ऐसे पते की ओर है जिससे यह सेवा नहीं जुड़ती।',

  flag_mtasts_policy_unreachable: 'MTA-STS नीति लाई नहीं जा सकी',
  fd_mtasts_policy_unreachable: 'TXT अभिलेख ऐसी नीति का वादा करता है जो वहाँ है ही नहीं, या जिसका प्रमाणपत्र सत्यापित नहीं होता। चूँकि पूरा तंत्र उसी HTTPS प्रमाणपत्र पर टिका है, यहाँ की विफलता का अर्थ है कि भेजने वाले अवसरवादी TLS पर लौट जाते हैं।',

  flag_mtasts_policy_wrong_content_type: 'नीति text/plain के रूप में नहीं दी जाती',
  fd_mtasts_policy_wrong_content_type: 'RFC 8461 text/plain माँगता है। सख़्त भेजने वाले इसे अस्वीकार कर देंगे।',

  flag_mtasts_policy_bad_version: 'नीति का संस्करण STSv1 नहीं है',
  fd_mtasts_policy_bad_version: 'भेजने वाले ऐसी नीति का उपयोग नहीं करेंगे जिसका संस्करण वे नहीं पहचानते।',

  flag_mtasts_policy_bad_mode: 'नीति की विधा कोई पहचानी जाने वाली नहीं है',
  fd_mtasts_policy_bad_mode: 'mode enforce, testing या none होना चाहिए।',

  flag_mtasts_mode_testing: 'MTA-STS परीक्षण विधा में है',
  fd_mtasts_mode_testing: 'विफलताओं की सूचना दी जाती है और डाक फिर भी पहुँचा दी जाती है, यानी नीति अभी कुछ भी नहीं बचाती। यह एक पड़ाव है, मंज़िल नहीं।',

  flag_mtasts_mode_none: 'MTA-STS अपनी ही नीति से बंद है',
  fd_mtasts_mode_none: 'mode=none नीति को वापस ले लेता है। यह इसलिए है कि कोई डोमेन MTA-STS को शालीनता से छोड़ सके; यूँ ही पड़ा रहने पर इसका मतलब बस यह है कि अभिलेख कुछ नहीं करता।',

  flag_mtasts_no_max_age: 'नीति में max_age नहीं है',
  fd_mtasts_no_max_age: 'max_age अनिवार्य है, और यही नीति को दबाए जाने के प्रति टिकाऊ बनाता है: जिस भेजने वाले ने उसे संचित कर लिया वह लागू करता रहेगा।',

  flag_mtasts_max_age_short: 'नीति एक दिन से कम समय संचित रहती है',
  fd_mtasts_max_age_short: 'छोटा max_age उस खिड़की को सँकरा कर देता है जिसमें संचित नीति किसी भेजने वाले की रक्षा करती है। नीति स्थिर हो जाने पर आमतौर पर कुछ हफ़्ते रखे जाते हैं।',

  flag_mtasts_mx_not_in_policy: 'नीति में एक असली मेल सर्वर छूटा है',
  fd_mtasts_mx_not_in_policy: 'MX समूह में ऐसा होस्ट है जिससे नीति का कोई mx: नमूना मेल नहीं खाता। इस नीति को लागू करने वाला हर भेजने वाला उस होस्ट पर पहुँचाने से इनकार कर देगा — यानी डाक ठीक उन्हीं भेजने वालों के लिए विफल होती है जो सावधानी बरत रहे हैं।',

  flag_mtasts_policy_lists_unknown_mx: 'नीति में ऐसे नमूने हैं जिनसे कोई मौजूदा MX मेल नहीं खाता',
  fd_mtasts_policy_lists_unknown_mx: 'हानिरहित, और आमतौर पर किसी स्थानांतरण की बची हुई चीज़। नीति वास्तविकता बताती रहे, इसके लिए साफ़ कर देना उचित है।',

  flag_mtasts_policy_no_mx: 'नीति में कोई मेल सर्वर सूचीबद्ध नहीं',
  fd_mtasts_policy_no_mx: 'बिना mx: प्रविष्टियों वाली नीति किसी से मेल नहीं खाती, इसलिए उसे लागू करने वाले भेजने वालों के पास पहुँचाने की कोई जगह नहीं बचती।',

  flag_tlsrpt_missing: 'कोई TLS-RPT अभिलेख नहीं',
  fd_tlsrpt_missing: 'एक TXT अभिलेख, और यह जानने का इकलौता रास्ता कि भेजने वाले आपके सर्वरों के साथ TLS तय नहीं कर पा रहे। उसके बिना समाप्त हो चुका प्रमाणपत्र या टूटा STARTTLS आपकी ओर से बिल्कुल दिखाई नहीं देता।',

  flag_tlsrpt_no_rua: 'TLS-RPT अभिलेख का कोई गंतव्य नहीं',
  fd_tlsrpt_no_rua: 'rua= के बिना रिपोर्टों के जाने की जगह नहीं है, इसलिए अभिलेख कुछ नहीं करता।',

  flag_dane_missing: 'कोई DANE अभिलेख नहीं',
  fd_dane_missing: 'TLSA अभिलेख यह तय करते हैं कि मेल सर्वर को कौन-सा प्रमाणपत्र दिखाना है, और इसके लिए सार्वजनिक प्राधिकरणों के बजाय DNSSEC पर टिकते हैं। दो परिवहन तंत्रों में यह अधिक मज़बूत है — और इसके लिए हस्ताक्षरित ज़ोन चाहिए, जो आमतौर पर इसके उपयोग में न होने का कारण भी है।',

  flag_dane_partial: 'केवल कुछ मेल सर्वरों के पास DANE अभिलेख हैं',
  fd_dane_partial: 'भेजने वाले सर्वर प्राथमिकता से चुनते हैं, इसलिए जिस समूह में केवल कुछ होस्ट तय हैं वह केवल कुछ ही समय सुरक्षित रहता है।',

  flag_dane_without_dnssec: 'अहस्ताक्षरित ज़ोन में TLSA अभिलेख',
  fd_dane_without_dnssec: 'DANE पूरी तरह DNSSEC पर टिका है। हस्ताक्षरों के बिना जो MX अभिलेख बदल सकता है वह TLSA भी बदल सकता है, इसलिए यह बंधन कुछ भी नहीं बचाता, बस बचाता हुआ दिखता है।',

  flag_dane_mismatch: 'TLSA अभिलेख प्रस्तुत प्रमाणपत्र से मेल नहीं खाता',
  fd_dane_mismatch: 'सर्वर ऐसा प्रमाणपत्र दिखा रहा है जिसकी अनुमति उसका अपना DANE अभिलेख नहीं देता। DANE जाँचने वाला हर भेजने वाला पहुँचाने से इनकार कर देगा — इससे डाक रुक जाती है।',

  flag_dane_pkix_usage: 'किसी TLSA अभिलेख में PKIX उपयोग है',
  fd_dane_pkix_usage: 'उपयोग 0 और 1 यह भी माँगते हैं कि प्रमाणपत्र सार्वजनिक प्राधिकरणों से भी सत्यापित हो। RFC 7672 §3.1 SMTP के लिए दोनों को मना करता है, क्योंकि डाक के लिए यह जाँच करने का कोई सर्वसम्मत तरीका है ही नहीं।',

  flag_dane_full_certificate: 'किसी TLSA अभिलेख ने पूरा प्रमाणपत्र बाँध रखा है',
  fd_dane_full_certificate: 'मिलान प्रकार 0 सारांश के बजाय पूरा प्रमाणपत्र रखता है। यह काम करता है, अभिलेख को बड़ा बनाता है और हर नवीनीकरण पर बदलने को बाध्य करता है।',

  flag_port_25_blocked_from_here: 'जहाँ यह सेवा चलती है वहाँ बाहर जाने वाला पोर्ट 25 अवरुद्ध है',
  fd_port_25_blocked_from_here: 'यह हमारे नेटवर्क की बात है, आपके की नहीं। अधिकांश होस्टिंग प्रदाता पोर्ट 25 पर बाहर जाने वाले कनेक्शन डिफ़ॉल्ट रूप से रोक देते हैं। इसीलिए STARTTLS, असली प्रमाणपत्र से DANE का मिलान और रिले की जाँच नहीं हो सकी, और श्रेणी जो कुछ संयोग से पहुँच में था उससे निकालने के बजाय रोक ली गई है।',

  flag_mx_not_reachable_on_25: 'पोर्ट 25 पर किसी मेल सर्वर ने उत्तर नहीं दिया',
  fd_mx_not_reachable_on_25: 'MX अभिलेख ऐसे होस्टों का नाम लेते हैं जो डाक पहुँचाने वाले पोर्ट पर कनेक्शन नहीं लेते। इस डोमेन पर कुछ भी नहीं पहुँचाया जा सकता।',

  flag_no_starttls: 'कोई मेल सर्वर STARTTLS नहीं देता',
  fd_no_starttls: 'इस सर्वर तक पहुँचाया गया हर संदेश बिना कूटलेखन के इंटरनेट पार करता है और रास्ते की हर चीज़ के लिए पढ़ने योग्य होता है। STARTTLS देने की क़ीमत एक प्रमाणपत्र और विन्यास की एक पंक्ति है।',

  flag_starttls_fails: 'STARTTLS दिया जाता है और काम नहीं करता',
  fd_starttls_fails: 'सर्वर STARTTLS की घोषणा करता है और हाथ मिलाना विफल हो जाता है। सावधान भेजने वाले खुले पाठ पर लौटने से मना कर सकते हैं और डाक टाल सकते हैं — यानी यह बिल्कुल न देने से भी बुरा है।',

  flag_starttls_legacy_protocol: 'मेल सर्वर पुराने TLS संस्करण पर तय करता है',
  fd_starttls_legacy_protocol: 'TLS 1.0 और 1.1 RFC 8996 के बाद से अप्रचलित हैं। भेजने वाले उनका समर्थन हटाते जा रहे हैं, और जब हटा देंगे तो डाक आनी बंद हो जाएगी।',

  flag_mx_certificate_not_trusted: 'मेल सर्वर का प्रमाणपत्र सत्यापित नहीं होता',
  fd_mx_certificate_not_trusted: 'साधारण अवसरवादी TLS प्रमाणपत्र जाँचता ही नहीं, इसलिए आज यह पहुँचाने में बाधा नहीं है। जैसे ही enforce विधा वाला MTA-STS या DANE आता है, यह पूरी तरह बाधा बन जाता है।',

  flag_banner_reveals_version: 'अभिवादन सॉफ़्टवेयर और उसका संस्करण बता देता है',
  fd_banner_reveals_version: 'यह उसके लिए छोटा-सा उपहार है जो उसी संस्करण की ज्ञात ख़ामी वाले होस्ट खोज रहा है। अभिवादन में कुछ भी लिखा जा सकता है।',

  flag_open_relay: 'सर्वर अजनबियों की डाक आगे भेजता है',
  fd_open_relay: 'उसने एक असंबद्ध भेजने वाले से असंबद्ध पाने वाले तक का संदेश स्वीकार कर लिया। कोई भी इसका उपयोग आपके नाम से स्पैम भेजने के लिए कर सकता है, और यदि पहले से नहीं है तो कुछ ही घंटों में अवरोध सूचियों में आ जाएगा। यह आज ही ठीक होता है। (जाँच RCPT TO पर रुकी और RSET भेजा — कोई संदेश नहीं भेजा गया।)',

  flag_no_size_extension: 'सर्वर SIZE की घोषणा नहीं करता',
  fd_no_size_extension: 'SIZE के बिना भेजने वाला यह नहीं जान सकता कि बड़ा संदेश स्वीकार होगा या नहीं, जब तक वह उसे पूरा भेज न दे।',

  flag_submission_without_starttls: 'भेजने वाला पोर्ट STARTTLS नहीं देता',
  fd_submission_without_starttls: 'पोर्ट 587 वहीं है जहाँ मेल क्लाइंट प्रमाणीकरण करते हैं। STARTTLS के बिना वे प्रमाण-पत्र नेटवर्क को खुले पाठ में पार करते हैं।',

  flag_rdns_missing: 'किसी मेल सर्वर के पते का PTR अभिलेख नहीं है',
  fd_rdns_missing: 'उल्टे DNS का न होना उन सबसे आम कारणों में से एक है जिनसे नए सर्वर की डाक टाली जाती है या स्पैम में डाल दी जाती है — और उन कारणों में से एक जिन्हें पाने वाला पक्ष सबसे कम समझाता है।',

  flag_rdns_not_confirmed: 'उल्टा DNS वापस हल नहीं होता',
  fd_rdns_not_confirmed: 'PTR अभिलेख एक नाम देता है, और वह नाम इस पते पर हल नहीं होता। प्राप्तकर्ता आने-जाने की जाँच इसीलिए करते हैं कि उसके लिए दो अलग-अलग पक्षों को अपना-अपना हिस्सा करना पड़ता है।',

  flag_rdns_none_confirmed: 'किसी मेल सर्वर के पास पुष्ट उल्टा DNS नहीं है',
  fd_rdns_none_confirmed: 'एक भी पता आने-जाने की जाँच पास नहीं करता। जो प्राप्तकर्ता इसे तौलते हैं उनके यहाँ देरी और स्पैम में जाने की अपेक्षा रखें।',
};

OWN.ar = {
  title: 'فحص البريد — SPF وDKIM وDMARC وMTA-STS وDANE لأي نطاق',
  title_short: 'فحص البريد',
  h1: 'فحص البريد',
  subtitle: 'يُفتح SPF عبر كل include ويُعدّ في مواجهة حد العشرة، ومحاذاة DMARC وتقاريره، وحماية النقل تُختبر على اتصال حقيقي',
  ph_host: 'example.com',
  hero_label: 'النطاق قيد الفحص',
  empty_hint: 'أدخل اسم نطاق. يفتح الفحص سجل SPF عبر كل include، ويجرّب معرّفات DKIM التي تستعملها المنصات الكبرى، ويقرأ سياسة DMARC، ويجلب سياسة MTA-STS عبر HTTPS، ويفتح جلسات SMTP للقراءة فقط مع خوادم البريد. ولا تُرسَل أي رسالة على الإطلاق.',

  stage_resolve: 'البحث عن خوادم البريد',
  stage_mx: 'فحص مجموعة MX',
  stage_spf: 'فتح SPF',
  stage_dkim: 'البحث عن مفاتيح DKIM',
  stage_dmarc: 'قراءة سياسة DMARC',
  stage_mtasts: 'جلب سياسة MTA-STS',
  stage_dane: 'فحص DANE',
  stage_starttls: 'الحديث مع خوادم البريد',
  stage_grade: 'إعطاء التقدير',

  card_grade: 'تفصيل التقدير',
  card_mx: 'خوادم البريد',
  card_spf: 'SPF',
  card_spf_tree: 'شجرة SPF',
  card_dkim: 'DKIM',
  card_dmarc: 'DMARC',
  card_transport: 'حماية النقل',
  card_sessions: 'جلسات SMTP',
  card_rdns: 'DNS العكسي',

  comp_authentication: 'التوثيق',
  comp_transport: 'النقل',
  comp_hygiene: 'النظافة',

  k_mx_count: 'سجلات MX',
  k_null_mx: 'MX فارغ',
  k_ipv6_mx: 'يمكن بلوغها عبر IPv6',
  k_spf_record: 'السجل',
  k_spf_lookups: 'استعلامات DNS المستهلكة',
  k_spf_voids: 'استعلامات فارغة',
  k_spf_policy: 'المعاملة الافتراضية لسائر المرسلين',
  k_dkim_keys: 'المفاتيح الموجودة',
  k_dkim_tried: 'المعرّفات المجرَّبة',
  k_dkim_strongest: 'أقوى مفتاح',
  k_dmarc_policy: 'السياسة',
  k_dmarc_subdomain: 'سياسة النطاقات الفرعية',
  k_dmarc_percent: 'تُطبَّق على',
  k_dmarc_alignment: 'المحاذاة (DKIM / SPF)',
  k_dmarc_rua: 'التقارير المجمّعة إلى',
  k_dmarc_ruf: 'تقارير الإخفاق إلى',
  k_dmarc_external: 'التقارير الخارجية مأذونة',
  k_mtasts: 'MTA-STS',
  k_mtasts_mode: 'الوضع',
  k_mtasts_id: 'معرّف السياسة',
  k_mtasts_maxage: 'تُحفظ لمدة',
  k_tlsrpt: 'TLS-RPT',
  k_dane: 'DANE (TLSA)',
  k_dane_covered: 'الخوادم المشمولة',
  k_starttls: 'STARTTLS',
  k_port25: 'المنفذ 25 الصادر',
  k_open_relay: 'ترحيل مفتوح',
  k_rdns_confirmed: 'مؤكَّد بالاتجاهين',
  k_queries: 'الاستعلامات المرسلة',

  th_priority: 'الأولوية',
  th_host: 'المضيف',
  th_addresses: 'العناوين',
  th_port: 'المنفذ',
  th_tls: 'TLS',
  th_banner: 'التحية',
  th_extensions: 'المعلَن',
  th_selector: 'المعرّف',
  th_key_type: 'المفتاح',
  th_bits: 'بت',
  th_state: 'الحالة',
  th_address: 'العنوان',
  th_ptr: 'PTR',
  th_confirmed: 'مؤكَّد',
  th_term: 'الحد',
  th_lookup: 'الاستعلام',

  pol_none: 'none — مراقبة فقط',
  pol_quarantine: 'quarantine — إلى المزعج',
  pol_reject: 'reject — رفض',
  spfp_pass: 'السماح للجميع (‎+all)',
  spfp_fail: 'الرفض (‎-all)',
  spfp_softfail: 'إخفاق ليّن (‎~all)',
  spfp_neutral: 'محايد (‎?all)',
  spfp_redirect: 'مفوَّض عبر redirect',
  spfterm_no_target: 'بلا هدف',
  spfterm_loop: 'دورة — مررنا بها من قبل',
  spfterm_lookup_failed: 'أخفق الاستعلام',
  spfterm_no_spf_record: 'لا يوجد سجل SPF هناك',

  stsmode_enforce: 'enforce — التطبيق',
  stsmode_testing: 'testing — تقارير فقط',
  stsmode_none: 'none — معطّلة',
  rdns_confirmed: 'مؤكَّد',
  rdns_unconfirmed: 'لا يعود إلى العنوان نفسه',
  rdns_missing: 'لا يوجد PTR',
  rdns_unknown: 'لم يُفحص',
  v_of_limit: '{used} من {limit}',
  v_percent: '{n}٪',
  v_days_short: '{n} ي',
  v_blocked_here: 'محجوب من شبكتنا',
  v_no_selector_found: 'ولا واحد من المعرّفات المعروفة الـ{n}',

  note_spf: 'يسمح RFC 7208 بعشرة حدود تستدعي استعلام DNS في التقييم كله، ويُحسب كل include داخل كل include. وبعد العاشر يجب على المستقبِل أن يعيد permerror — وpermerror يعني أن SPF لا ينطبق إطلاقًا، تمامًا كما لو لم يكن هناك سجل.',
  note_dmarc: 'مع p=none لا يُطبَّق شيء: الرسالة التي تخفق في محاذاة SPF وDKIM معًا تُسلَّم كما كانت. هو المكان الصحيح للبدء والخطأ للبقاء.',
  note_transport: 'STARTTLS انتهازي: المرسِل الذي يُنتزع منه العرض يمضي ببساطة بنص مكشوف. وMTA-STS وDANE هما ما يحوّل تلك الإمكانية إلى ضمانة.',
  note_sessions: 'كل الجلسات للقراءة فقط. يتوقف اختبار الترحيل عند RCPT TO ويرسل RSET؛ ولا يُصدَر أمر DATA أبدًا، فلا يمكن إرسال أي رسالة.',
  note_rdns: 'سجل PTR وحده لا يثبت شيئًا — فمالك كتلة العناوين يستطيع أن يضع فيها أي اسم. ما يتحقّق منه المستقبِلون هو أن ذلك الاسم يعود ليترجَم إلى العنوان نفسه.',

  err_smtp_timeout: 'لم يجب خادم البريد في الوقت المتاح.',
  err_smtp_network: 'تعذّر بلوغ خادم البريد.',
  err_smtp_refused: 'رفض خادم البريد الاتصال.',
  err_tls_failed: 'أخفقت مصافحة TLS مع خادم البريد.',

  inc_mx_lookup_failed: 'تعذّرت قراءة سجلات MX',
  inc_spf_lookup_failed: 'تعذّرت قراءة سجل SPF',
  inc_dmarc_lookup_failed: 'تعذّرت قراءة سجل DMARC',
  inc_port_25_unreachable_from_this_network: 'المنفذ 25 الصادر محجوب حيث تعمل هذه الخدمة، فتعذّر إجراء STARTTLS ومطابقة DANE مع الشهادة الحقيقية واختبار الترحيل',
  inc_not_every_mx_was_probed: 'لم يُتصل إلا بالخوادم ذات الأولوية الأعلى',

  cap_open_relay: 'الخادم يرحّل بريد الغرباء',
  cap_spf_authorises_everyone: 'SPF يأذن للإنترنت كلها',
  cap_no_mail_servers: 'لا خوادم بريد',
  cap_mail_servers_unreachable: 'لم يجب أي خادم بريد على المنفذ 25',
  cap_dane_mismatch: 'DANE لا يطابق الشهادة المقدَّمة',
  cap_mtasts_policy_contradicts_dns: 'سياسة MTA-STS تُغفل خادم بريد حقيقيًا',
  cap_spf_over_the_lookup_limit: 'SPF تجاوز حد الاستعلامات',
  cap_spf_permerror: 'SPF خطأ دائم',
  cap_dmarc_permerror: 'DMARC خطأ دائم',
  cap_mail_in_the_clear: 'البريد يُقبل دون تعمية',
  cap_no_spf: 'لا سجل SPF',
  cap_no_dmarc: 'لا سجل DMARC',
  cap_starttls_broken: 'STARTTLS معروض ولا يعمل',
  cap_dmarc_not_enforcing: 'DMARC لا يطبّق شيئًا',
  cap_no_reverse_dns: 'لا DNS عكسي مؤكَّد',
  cap_spf_without_a_default: 'SPF بلا معاملة افتراضية',
  cap_weak_dkim_key: 'مفتاح DKIM أقصر مما ينبغي',
  cap_dmarc_reports_go_nowhere: 'تقارير DMARC غير مأذونة',
  cap_mail_server_does_not_resolve: 'خادم بريد لا يُترجَم إلى عنوان',
  cap_scan_incomplete: 'كان الفحص ناقصًا، فلم يُمنح تقدير',

  flag_null_mx: 'النطاق يعلن أنه لا يتعامل مع البريد',
  fd_null_mx: 'سجل MX واحد بأولوية 0 يشير إلى الجذر هو ما يعنيه RFC 7505 بـ«هذا النطاق لا يرسل بريدًا ولا يستقبله». قرار مقصود، وأفضل بكثير من غياب MX تمامًا — فبغيابه يرتد المرسِلون إلى سجل العنوان.',

  flag_no_mx: 'لا سجلات MX',
  fd_no_mx: 'لا شيء يبيّن إلى أين يذهب بريد هذا النطاق، ولا عنوان بديل يُرتدّ إليه، فالتسليم ببساطة غير ممكن.',

  flag_no_mx_falls_back_to_a: 'لا سجلات MX، فيرتدّ المرسِلون إلى سجل A',
  fd_no_mx_falls_back_to_a: 'يوجّه RFC 5321 §5.1 المرسِل الذي لا يجد MX إلى تجربة سجل العنوان. سيُسلَّم بريد هذا النطاق إلى ما يستمع على المنفذ 25 عند خادم الويب — وهو نادرًا ما يكون المقصود.',

  flag_duplicate_mx_host: 'المضيف نفسه مذكور مرتين',
  fd_duplicate_mx_host: 'يظهر مضيف واحد بأكثر من أولوية. هذا ليس تكرارًا احتياطيًا، بل الآلة نفسها تُجرَّب مرتين.',

  flag_mx_does_not_resolve: 'اسم أحد خوادم البريد لا يُترجَم إلى عنوان',
  fd_mx_does_not_resolve: 'يشير MX إلى مضيف بلا سجلات عناوين. كل مرسِل يبلغ هذه الأولوية ينتظر الاستعلام، ولا يحصل على شيء، ثم يمضي — فيتأخّر بريد كان ينبغي أن يصل فورًا.',

  flag_mx_points_at_cname: 'سجل MX يشير إلى كنية',
  fd_mx_points_at_cname: 'يوجب RFC 2181 §10.3 أن يسمّي MX مضيفًا له سجلات عناوين، لا CNAME. بعض المرسِلين يتدبّرون الأمر وبعضهم يرفض، وتوزيع هؤلاء يتغيّر مع الوقت.',

  flag_single_mx: 'خادم بريد واحد فقط',
  fd_single_mx: 'مع MX واحد، أي انقطاع يعني أن المرسِلين يصفّون البريد ويعيدون المحاولة — ساعات أو أيامًا بحسب سياسة كلٍّ منهم — وجزء من ذلك البريد سيرتدّ في النهاية.',

  flag_no_ipv6_mx: 'لا خادم بريد يمكن بلوغه عبر IPv6',
  fd_no_ipv6_mx: 'المرسِلون في الشبكات التي لا تدعم إلا IPv6 يصلون إلى هذا النطاق عبر مترجم، إن وصلوا.',

  flag_spf_missing: 'لا سجل SPF',
  fd_spf_missing: 'لا شيء يبيّن أي الخوادم يجوز لها إرسال البريد باسم هذا النطاق، فلا شيء يُقارَن به. وSPF سجل TXT واحد وأرخص ما في هذه الصفحة كلها.',

  flag_spf_multiple_records: 'أكثر من سجل SPF',
  fd_spf_multiple_records: 'يجعل RFC 7208 §4.5 وجود سجلين خطأً دائمًا، وpermerror يعني ألا نتيجة لـSPF أصلًا — عكس ما أُريد تمامًا عند إضافة الثاني. ينبغي دمجهما في سجل واحد.',

  flag_spf_too_many_lookups: 'يحتاج SPF إلى أكثر من عشرة استعلامات DNS',
  fd_spf_too_many_lookups: 'الحد في RFC 7208 §4.6.4 عشرة حدود تستدعي استعلامًا في التقييم كله، ويُحسب كل include داخل كل include. وبعده يجب على المستقبِل أن يعيد permerror فيتوقّف انطباق SPF — وكأن السجل غير موجود. ويسهل تجاوزه بإضافة مزوّد واحد آخر، ولا يظهر ذلك من السجل نفسه إطلاقًا.',

  flag_spf_lookups_near_limit: 'SPF قريب من حد الاستعلامات العشرة',
  fd_spf_lookups_near_limit: 'لم يبقَ هامش يُذكر. الخدمة التالية التي تُضاف — أو تغيير داخل include يخصّ غيرك ولا سلطان لك عليه — ستدفعه إلى ما بعد الحد.',

  flag_spf_too_many_void_lookups: 'كثير من استعلامات SPF تعود فارغة',
  fd_spf_too_many_void_lookups: 'يسمح RFC 7208 باستعلامين لا يترجمان إلى شيء؛ وما بعدهما خطأ دائم. وغالبًا ما يكون include متروكًا لخدمة لم تعد تُستعمل.',

  flag_spf_no_all: 'SPF بلا معاملة افتراضية',
  fd_spf_no_all: 'بغير آلية «all» وبغير redirect، يحصل المرسِل الذي لا ينطبق عليه شيء على نتيجة محايدة — وهو ما يساوي ألا يكون لك رأي أصلًا.',

  flag_spf_plus_all: 'SPF يأذن للإنترنت كلها',
  fd_spf_plus_all: '«‎+all» يقول إن أي مضيف في أي مكان يجوز له الإرسال باسم هذا النطاق. وهو في الغالب سوء فهم للمُحدِّد، وأسوأ من غياب SPF لأنه يزكّي المزوِّر صراحةً.',

  flag_spf_neutral_all: 'SPF ينتهي بـ‎?all',
  fd_spf_neutral_all: '«‎?all» يرفض صراحةً أن يقول شيئًا عن المرسِلين الذين لا ينطبق عليهم شيء. ويعامله المستقبِلون على أنه غياب نتيجة.',

  flag_spf_softfail_all: 'SPF ينتهي بـ‎~all بدل ‎-all',
  fd_spf_softfail_all: 'الإخفاق الليّن يطلب من المستقبِلين القبول مع وضع علامة. وهو الإعداد الصحيح ما دمت تستكشف من يرسل باسمك، وهو ما يُشدّ حين تعرف.',

  flag_spf_uses_ptr: 'SPF يستعمل آلية ptr',
  fd_spf_uses_ptr: 'يهجرها RFC 7208 §5.5 صراحةً: بطيئة وغير موثوقة وتحمّل العبء لمن يدير المنطقة العكسية. وبعض المستقبِلين يتجاهلونها تمامًا.',

  flag_spf_unknown_mechanism: 'في SPF حدٌّ لا يفهمه شيء',
  fd_spf_unknown_mechanism: 'الآلية غير المعروفة خطأ دائم بحسب RFC 7208 §4.6.1، وتُسقط السجل كله. وهي في العادة خطأ مطبعي.',

  flag_spf_duplicate_redirect: 'أكثر من مُعدِّل redirect',
  fd_spf_duplicate_redirect: 'وجود redirect ثانٍ يجعل السجل خطأً دائمًا.',

  flag_spf_redirect_after_all: 'redirect لن يُبلَغ أبدًا',
  fd_spf_redirect_after_all: 'في السجل آلية «all» وredirect معًا. و«all» تنطبق دائمًا، فيتوقّف التقييم عندها ويبقى redirect نصًّا ميتًا.',

  flag_spf_record_long: 'سجل SPF طويل',
  fd_spf_record_long: 'تُقسَّم السجلات الطويلة إلى عدة سلاسل على السلك. وهذا في ذاته سليم — يصلها المستقبِلون دون فاصل — لكنه بالضبط الموضع الذي تبدأ عنده المحلّلات التي تصلها بمسافة في إفساد السجل.',

  flag_spf_include_loop: 'include يعود إلى موضع مررنا به من قبل',
  fd_spf_include_loop: 'يدور الفتح في حلقة. يتوقّف المستقبِل عند حد الاستعلامات ويعيد خطأً دائمًا.',

  flag_spf_include_without_record: 'include يشير إلى نطاق بلا سجل SPF',
  fd_spf_include_without_record: 'يجعله RFC 7208 §5.2 خطأً دائمًا لا مجرد استعلام مهدور. وهو عادةً خدمة أُزيلت من طرف ولم تُزَل من الآخر.',

  flag_dkim_no_known_selector: 'لا مفتاح DKIM عند أي معرّف نعرفه',
  fd_dkim_no_known_selector: 'المعرّفات يختارها من يوقّع، ولا تظهر إلا في ترويسة رسالة موقَّعة، فلا يمكن حصرها من الخارج. وهذا ليس دليلًا على غياب DKIM — إن كنت تعرف معرّفك فمرّره عبر ‎?selector=‎ ليصير الفحص قاطعًا.',

  flag_dkim_key_revoked: 'أُبطل أحد مفاتيح DKIM',
  fd_dkim_key_revoked: 'نُشر السجل بـp= فارغة، وهو ما يُبطل المفتاح. تلك هي الطريقة الصحيحة لإحالة مفتاح إلى التقاعد — وسجل بقي هكذا شهورًا يعني عادةً تبديل مفاتيح لم يُتمّه أحد.',

  flag_dkim_key_malformed: 'أحد مفاتيح DKIM لا يمكن تحليله',
  fd_dkim_key_malformed: 'قيمة p= ليست مادة مفتاح صالحة. وكل توقيع يُصنع بها سيُخفق في التحقّق.',

  flag_dkim_in_test_mode: 'أحد سجلات DKIM في وضع الاختبار',
  fd_dkim_in_test_mode: 't=y يخبر المستقبِلين أن يعاملوا التوقيع المخفق كأن DKIM غير مستعمل. موضعه أثناء الإطلاق ولا موضع له غير ذلك.',

  flag_dkim_key_too_short: 'أحد مفاتيح DKIM أقصر من 1024 بت',
  fd_dkim_key_too_short: 'دون 1024 بت لا يكون تزوير التوقيع صعبًا فعليًا، وكثير من المستقبِلين يتجاهلون هذه المفاتيح ابتداءً.',

  flag_dkim_key_1024_bit: 'أحد مفاتيح DKIM بطول 1024 بت',
  fd_dkim_key_1024_bit: 'ما زال مقبولًا في كل مكان، وهو دون التوصيات الحالية. الحجم المعتاد 2048؛ والتبديل معرّف جديد وسجل DNS.',

  flag_dmarc_missing: 'لا سجل DMARC',
  fd_dmarc_missing: 'بغير DMARC تبقى نتائج SPF وDKIM استرشادية: لا شيء يربطها بالعنوان الذي يراه القارئ فعلًا، ولا شيء يخبر المستقبِلين بما يفعلونه عند الإخفاق.',

  flag_dmarc_inherited: 'DMARC موروث من النطاق الأصل',
  fd_dmarc_inherited: 'لا سجل خاصًّا بهذا الاسم، فتنطبق سياسة النطاق التنظيمي — قيمة sp= لديه إن وُجدت، وإلا فقيمة p=.',

  flag_dmarc_multiple_records: 'أكثر من سجل DMARC',
  fd_dmarc_multiple_records: 'RFC 7489 §6.6.3: بوجود أكثر من سجل تُطرح السياسة بالكامل، كأن شيئًا لم يُنشر.',

  flag_dmarc_no_policy: 'سجل DMARC بلا وسم p=',
  fd_dmarc_no_policy: 'p= إلزامية. وبغيرها يُتجاهل السجل.',

  flag_dmarc_invalid_policy: 'سياسة DMARC ليست قيمة معروفة',
  fd_dmarc_invalid_policy: 'يجب أن تكون p= إحدى none أو quarantine أو reject. وبأي قيمة أخرى يطرح المستقبِلون السجل.',

  flag_dmarc_policy_none: 'DMARC لا يطبّق شيئًا',
  fd_dmarc_policy_none: 'p=none يطلب من المستقبِلين أن يبلّغوا وألا يغيّروا شيئًا. والرسالة التي تخفق في محاذاة SPF وDKIM معًا تُسلَّم تمامًا كما لو لم يكن هناك DMARC. وهي الطريقة الصحيحة للبدء — وكثير جدًا من النطاقات جالسة هنا منذ سنوات وهي تحسب نفسها محميّة.',

  flag_dmarc_policy_quarantine: 'DMARC يعزل بدل أن يرفض',
  fd_dmarc_policy_quarantine: 'البريد المخفق يذهب إلى مجلد المزعج بدل أن يُرفض. خطوة معقولة في الطريق إلى reject، وموضع ما زال البريد المزوَّر يبلغ الناس فيه.',

  flag_dmarc_subdomain_policy_none: 'النطاقات الفرعية خارج السياسة',
  fd_dmarc_subdomain_policy_none: 'sp=none يترك كل نطاق فرعي — بما فيها ما لم يوجد قط — مفتوحًا للانتحال، بينما النطاق نفسه محميّ.',

  flag_dmarc_partial_percentage: 'السياسة تنطبق على جزء من البريد فقط',
  fd_dmarc_partial_percentage: 'قيمة pct= دون 100 تطلب من المستقبِلين تطبيق السياسة على تلك النسبة من الرسائل المخفقة ومعاملة الباقي بلين. مفيدة أثناء الإطلاق، وثغرة ما دامت موضوعة.',

  flag_dmarc_no_reporting: 'لا عنوان للتقارير المجمّعة',
  fd_dmarc_no_reporting: 'بغير rua= لا تصلك تقارير، أي لا سبيل لمعرفة من يرسل باسم نطاقك ولا ما الذي سينكسر إن شدّدت السياسة.',

  flag_dmarc_external_reporting_unauthorised: 'عنوان التقارير الخارجي لم يأذن لك',
  fd_dmarc_external_reporting_unauthorised: 'التقارير موجَّهة إلى نطاق آخر، وذلك النطاق لا ينشر السجل الذي يوافق به على استقبالها (RFC 7489 §7.1). والمستقبِلون الملتزمون لا يرسلون شيئًا. يبدو سجل DMARC مثاليًا ولا تصل التقارير أبدًا — وهو ما يُعزى دائمًا تقريبًا إلى أن «التقارير تتأخّر».',

  flag_mtasts_missing: 'لا سياسة MTA-STS',
  fd_mtasts_missing: 'STARTTLS انتهازي: المرسِل الذي لا يرى العرض يرسل بنص مكشوف، وإزالة ذلك العرض سهلة على أي أحد بين الخادمين. وMTA-STS ينشر عبر HTTPS أن هذا النطاق يتكلّم TLS دائمًا، فيصير الهجوم مطالبًا بكسر البنية العامة لمفاتيح الويب بدلًا من ذلك.',

  flag_mtasts_multiple_records: 'أكثر من سجل TXT لـMTA-STS',
  fd_mtasts_multiple_records: 'لا يستطيع المرسِلون تمييز المعرّف الحالي، فقد لا تُحدَّث السياسة عند تغيّرها.',

  flag_mtasts_no_id: 'سجل MTA-STS بلا معرّف',
  fd_mtasts_no_id: 'المعرّف هو ما يعرف به المرسِل أن نسخته من السياسة قديمة. وبغيره قد لا تُلتقط السياسة المعدَّلة حتى تنتهي مدة max_age.',

  flag_mtasts_policy_host_missing: 'مضيف السياسة لا يُترجَم إلى عنوان',
  fd_mtasts_policy_host_missing: 'يعلن سجل TXT عن سياسة، وليس لـmta-sts.<النطاق> عنوان، فلا يستطيع أي مرسِل جلبها.',

  flag_mtasts_policy_host_private: 'مضيف السياسة يُترجَم إلى فضاء عناوين خاص',
  fd_mtasts_policy_host_private: 'لم تُجلب السياسة: المضيف يشير إلى عنوان لا تتصل به هذه الخدمة.',

  flag_mtasts_policy_unreachable: 'تعذّر جلب سياسة MTA-STS',
  fd_mtasts_policy_unreachable: 'يعد سجل TXT بسياسة ليست موجودة، أو شهادتها لا تجتاز التحقّق. ولأن الآلية كلها قائمة على شهادة HTTPS تلك، فإخفاقًا هنا يعني ارتداد المرسِلين إلى TLS الانتهازي.',

  flag_mtasts_policy_wrong_content_type: 'السياسة لا تُقدَّم بنوع text/plain',
  fd_mtasts_policy_wrong_content_type: 'يشترط RFC 8461 نوع text/plain. والمرسِلون المتشدّدون سيرفضونها.',

  flag_mtasts_policy_bad_version: 'إصدار السياسة ليس STSv1',
  fd_mtasts_policy_bad_version: 'لن يستعمل المرسِلون سياسةً لا يعرفون إصدارها.',

  flag_mtasts_policy_bad_mode: 'وضع السياسة ليس قيمة معروفة',
  fd_mtasts_policy_bad_mode: 'يجب أن يكون mode إحدى enforce أو testing أو none.',

  flag_mtasts_mode_testing: 'MTA-STS في وضع الاختبار',
  fd_mtasts_mode_testing: 'يُبلَّغ عن الإخفاقات ويُسلَّم البريد على أي حال، فالسياسة لا تحمي شيئًا بعد. محطة في الطريق لا وجهة.',

  flag_mtasts_mode_none: 'MTA-STS معطّل بسياسته هو',
  fd_mtasts_mode_none: 'mode=none يسحب السياسة. وُجد ليتمكّن نطاق من ترك MTA-STS بترتيب؛ وتركه على حاله يعني ببساطة أن السجل لا يفعل شيئًا.',

  flag_mtasts_no_max_age: 'السياسة بلا max_age',
  fd_mtasts_no_max_age: 'max_age إلزامية، وهي ما يجعل السياسة عصيّة على الكتم: المرسِل الذي خزّنها سيظل يطبّقها.',

  flag_mtasts_max_age_short: 'السياسة تُحفظ أقل من يوم',
  fd_mtasts_max_age_short: 'قيمة max_age القصيرة تضيّق النافذة التي تحمي فيها السياسةُ المخزَّنة مرسِلًا. وبضعة أسابيع هي الخيار المعتاد بعد استقرار السياسة.',

  flag_mtasts_mx_not_in_policy: 'ينقص السياسةَ خادمُ بريد حقيقي',
  fd_mtasts_mx_not_in_policy: 'في مجموعة MX مضيف لا ينطبق عليه أي نمط mx: في السياسة. وكل مرسِل يطبّق هذه السياسة سيرفض التسليم إلى ذلك المضيف — أي أن البريد يخفق تحديدًا عند المرسِلين الحريصين.',

  flag_mtasts_policy_lists_unknown_mx: 'السياسة تذكر أنماطًا لا تطابق أي MX حالي',
  fd_mtasts_policy_lists_unknown_mx: 'غير ضار، وهو عادةً بقية من عملية نقل. ويستحق التنظيف كي تظل السياسة واصفةً للواقع.',

  flag_mtasts_policy_no_mx: 'السياسة لا تذكر أي خادم بريد',
  fd_mtasts_policy_no_mx: 'سياسة بلا مدخلات mx: لا تطابق شيئًا، فلا موضع لدى المرسِلين الذين يطبّقونها ليسلّموا إليه.',

  flag_tlsrpt_missing: 'لا سجل TLS-RPT',
  fd_tlsrpt_missing: 'سجل TXT واحد، وهو السبيل الوحيد لتعرف أن المرسِلين يخفقون في التفاهم على TLS مع خوادمك. وبغيره تكون شهادة منتهية أو STARTTLS معطوب غير مرئيين من جهتك.',

  flag_tlsrpt_no_rua: 'سجل TLS-RPT بلا وجهة',
  fd_tlsrpt_no_rua: 'بغير rua= لا مكان تذهب إليه التقارير، فلا يفعل السجل شيئًا.',

  flag_dane_missing: 'لا سجلات DANE',
  fd_dane_missing: 'تثبّت سجلات TLSA الشهادةَ التي يجب أن يقدّمها خادم البريد، مستندةً إلى DNSSEC لا إلى سلطات التصديق العامة. وهي الأقوى من آليتَي النقل — وتحتاج منطقةً موقّعة، وذلك عادةً سبب عدم استعمالها.',

  flag_dane_partial: 'بعض خوادم البريد فقط لديها سجلات DANE',
  fd_dane_partial: 'يختار المرسِلون الخادم بالأولوية، فالمجموعة التي لم يُثبَّت فيها إلا بعض المضيفين محميّة بعض الوقت فقط.',

  flag_dane_without_dnssec: 'سجل TLSA في منطقة غير موقّعة',
  fd_dane_without_dnssec: 'يقوم DANE كليًا على DNSSEC. فبغير تواقيع، من يستطيع استبدال سجل MX يستطيع استبدال TLSA أيضًا، فلا يحمي التثبيت شيئًا وإن بدا كذلك.',

  flag_dane_mismatch: 'سجل TLSA لا يطابق الشهادة المقدَّمة',
  fd_dane_mismatch: 'يقدّم الخادم شهادةً لا يأذن بها سجل DANE الخاص به. وكل مرسِل يتحقّق من DANE سيرفض التسليم — وهذا يوقف البريد.',

  flag_dane_pkix_usage: 'سجل TLSA يستعمل أحد استعمالَي PKIX',
  fd_dane_pkix_usage: 'يشترط الاستعمالان 0 و1 أن تجتاز الشهادة التحقّق عبر السلطات العامة أيضًا. ويمنعهما RFC 7672 §3.1 لـSMTP، إذ لا طريقة متّفقًا عليها لإجراء ذلك التحقّق للبريد.',

  flag_dane_full_certificate: 'سجل TLSA يثبّت الشهادة كاملةً',
  fd_dane_full_certificate: 'نوع المطابقة 0 يخزّن الشهادة كاملةً بدل بصمة. يعمل، ويضخّم السجل، ويُلزم باستبداله عند كل تجديد.',

  flag_port_25_blocked_from_here: 'المنفذ 25 الصادر محجوب حيث تعمل هذه الخدمة',
  fd_port_25_blocked_from_here: 'هذا يتعلق بشبكتنا لا بشبكتكم. تحجب معظم شركات الاستضافة الاتصالات الصادرة إلى المنفذ 25 افتراضيًا. لذلك تعذّر إجراء STARTTLS ومطابقة DANE مع شهادة حقيقية واختبار الترحيل، وحُجب التقدير بدل حسابه مما تصادف أنه كان في المتناول.',

  flag_mx_not_reachable_on_25: 'لم يجب أي خادم بريد على المنفذ 25',
  fd_mx_not_reachable_on_25: 'تسمّي سجلات MX مضيفين لا يقبلون الاتصال على المنفذ الذي يُسلَّم عبره البريد. فلا يمكن تسليم شيء إلى هذا النطاق.',

  flag_no_starttls: 'أحد خوادم البريد لا يعرض STARTTLS',
  fd_no_starttls: 'كل رسالة تُسلَّم إلى هذا الخادم تعبر الإنترنت بلا تعمية، مقروءةً لكل ما على الطريق. وعرض STARTTLS يكلّف شهادةً وسطرًا في الإعداد.',

  flag_starttls_fails: 'STARTTLS معروض ولا يعمل',
  fd_starttls_fails: 'يعلن الخادم STARTTLS ثم تخفق المصافحة. وقد يرفض المرسِلون الحريصون الارتداد إلى النص المكشوف ويؤجّلون البريد — فهذا أسوأ من ألا يُعرض أصلًا.',

  flag_starttls_legacy_protocol: 'خادم البريد يتفاهم على إصدار TLS مهجور',
  fd_starttls_legacy_protocol: 'هُجر TLS 1.0 و1.1 منذ RFC 8996. والمرسِلون يسحبون دعمهما تدريجيًا، وحين يفعلون يتوقّف وصول البريد.',

  flag_mx_certificate_not_trusted: 'شهادة خادم البريد لا تجتاز التحقّق',
  fd_mx_certificate_not_trusted: 'TLS الانتهازي العادي لا يتحقّق من الشهادات، فهذا لا يمنع التسليم اليوم. ويمنعه تمامًا لحظة دخول MTA-STS في وضع enforce أو DANE.',

  flag_banner_reveals_version: 'التحية تذكر البرنامج وإصداره',
  fd_banner_reveals_version: 'هديّة صغيرة لمن يبحث عن مضيفين فيهم عيب معروف في ذلك الإصدار بالضبط. ويمكن أن يُكتب في التحية أي شيء.',

  flag_open_relay: 'الخادم يرحّل بريد الغرباء',
  fd_open_relay: 'قبِل رسالةً من مرسِل لا صلة له إلى مستقبِل لا صلة له. يستطيع أي أحد استعماله لإرسال بريد مزعج باسمك، وسيدخل قوائم الحجب خلال ساعات إن لم يكن قد دخلها. هذا يُصلَح اليوم. (توقّف الاختبار عند RCPT TO وأرسل RSET — ولم تُرسَل أي رسالة.)',

  flag_no_size_extension: 'الخادم لا يعلن SIZE',
  fd_no_size_extension: 'بغير SIZE لا يستطيع المرسِل أن يعرف إن كانت رسالة كبيرة ستُقبل قبل أن ينقلها كاملة.',

  flag_submission_without_starttls: 'منفذ الإرسال لا يعرض STARTTLS',
  fd_submission_without_starttls: 'المنفذ 587 هو حيث تستوثق برامج البريد. وبغير STARTTLS تعبر تلك البيانات الشبكةَ بنص مكشوف.',

  flag_rdns_missing: 'أحد عناوين خوادم البريد بلا سجل PTR',
  fd_rdns_missing: 'غياب DNS العكسي من أشيع أسباب تأجيل بريد خادم جديد أو إيداعه في المزعج — ومن أقلّها شرحًا من الطرف المستقبِل.',

  flag_rdns_not_confirmed: 'DNS العكسي لا يعود إلى العنوان نفسه',
  fd_rdns_not_confirmed: 'يعطي سجل PTR اسمًا، وذلك الاسم لا يُترجَم إلى هذا العنوان. ويتحقّق المستقبِلون من الرحلة ذهابًا وإيابًا تحديدًا لأنها تقتضي أن يكون طرفان مختلفان قد أدّيا نصيبهما.',

  flag_rdns_none_confirmed: 'لا خادم بريد لديه DNS عكسي مؤكَّد',
  fd_rdns_none_confirmed: 'ولا عنوان واحد يجتاز التحقّق ذهابًا وإيابًا. توقّع تأخّرًا في التسليم وإيداعًا في المزعج لدى المستقبِلين الذين يزنون ذلك.',
};

window.I18N = window.mergeI18N(OWN);
