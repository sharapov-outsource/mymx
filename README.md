# mymx

**[mymx.sharapov.biz](https://mymx.sharapov.biz)** — SPF, DKIM, DMARC, MTA-STS,
DANE and STARTTLS for any domain.

No ads, no registration, no accounts. Nothing you look up is stored. MIT licensed,
twelve languages, one `docker run` to host your own.

```bash
curl mymx.sharapov.biz/example.com
```

---

## The check that this exists for

**SPF is expanded through every include and counted against the limit of ten.**

RFC 7208 §4.6.4 allows a record ten DNS-querying terms — `include`, `a`, `mx`,
`ptr`, `exists` and the `redirect` modifier — counted across the *whole*
evaluation, following every include into every include. Past ten, a receiver
must return `permerror`, and a permerror means SPF does not apply at all: the
mail is judged exactly as if there were no record.

This is easy to exceed and invisible from the record itself. One `include:` can
be four lookups inside. Add a CRM, a newsletter tool, a helpdesk and a payment
provider and a domain is over the limit without anybody having written anything
obviously wrong — and nothing breaks until the day a receiver starts enforcing.
Worse, the number can go up without you touching anything, because it depends on
what is inside somebody else's include.

So the expansion is shown as a tree with the running count, and the term that
pushed it over is named.

A macro target such as `exists:%{i}._spf.example.com` costs its lookup and is
left there: it expands per connection using the sending address, so it cannot be
resolved from outside, and querying the literal name would push healthy records
over the void-lookup limit.

## The rest

**DMARC**, including the part nobody checks. If `rua` points at an address
outside your domain — which it does whenever a third-party service handles
reports — that other domain must publish `<your-domain>._report._dmarc.<their-domain>`
to agree to receive them (RFC 7489 §7.1). Without it, conforming receivers send
nothing. The record looks perfect, the dashboard stays empty, and it is nearly
always put down to "reports take a while to arrive".

Also: `p=none` named for what it is — reporting with nothing enforced — plus
`sp`, `pct`, alignment, and the organisational-domain policy a subdomain
inherits.

**DKIM.** Selectors are chosen by whoever signs and appear only in the header of
a signed message, so they cannot be enumerated from outside. This tries the ones
the large platforms use and says plainly that a miss is not proof of absence.
Pass `?selector=` when you know yours and the answer becomes conclusive. Key
sizes are read from the DER in the record rather than guessed, and revoked keys
(empty `p=`) and test mode (`t=y`) are called out.

**MTA-STS**, fetched over HTTPS and compared with the real MX set. A host that
is in the DNS and missing from the policy has its mail refused by every sender
enforcing the policy — so the careful senders are the ones that fail.

**DANE.** TLSA records checked against the certificate actually presented,
selector and matching type computed properly. A TLSA record in an unsigned zone
is reported as the false comfort it is.

**STARTTLS** on 25, 465 and 587, with what each server announces, plus reverse
DNS with forward confirmation.

**An open-relay probe that cannot send mail.** It stops at `RCPT TO` — the point
at which the server has already decided whether it would accept mail from a
stranger for a stranger — then sends `RSET` and `QUIT`. **No `DATA` command is
ever issued.**

## About port 25

Most hosting providers block outbound connections to port 25 by default, to keep
their address space off blocklists. When that is the case wherever this is
running, the report says so — `port-25-blocked-from-here`, named as ours rather
than yours — the affected checks are marked as not made, and **the grade is
withheld**.

Reporting "no STARTTLS" because *we* could not connect would be the same mistake
as scoring a server that was rate-limiting the scanner. That one has been made
before, at a bank's expense.

## The grade

Authentication 45%, transport 35%, hygiene 20%. Two rules are absolute: an open
relay is an F whatever else is right, because it is an active hazard to
everybody rather than a weakness in your own defences — and it is reported even
from an incomplete check. And when something could not be measured, there is no
letter at all, only a list of what could not be established.

## API

```bash
curl mymx.sharapov.biz/example.com                    # full report
curl mymx.sharapov.biz/api/example.com?output=yaml    # YAML
curl mymx.sharapov.biz/api/stream/example.com         # server-sent events
curl "mymx.sharapov.biz/api/example.com?selector=k1"  # a DKIM selector we would not guess
curl mymx.sharapov.biz/example.com?lang=ru            # labels in another language
```

Watch the SPF budget from a script:

```bash
curl -s mymx.sharapov.biz/api/example.com | jq '.spf.budget'
```

## Running your own

```bash
docker run -d --name mymx -p 127.0.0.1:3027:3027 ghcr.io/sharapov-outsource/mymx:latest
```

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `3027` | listen port |
| `TRUST_PROXY` | `true` | read the client address from proxy headers. Turn **off** when facing the internet directly |
| `SMTP_PORT_25` | — | `open` or `blocked` to skip the outbound probe and state the answer |
| `SMTP_CHECK_465` / `SMTP_CHECK_587` | `true` | set `false` to skip a submission port |
| `SMTP_MAX_HOSTS` | `3` | how many MX hosts to connect to |
| `SMTP_EHLO_NAME` | `mymx.sharapov.biz` | the name used in `EHLO` |
| `DNS_RESOLVER` | `1.1.1.1` | resolver for ordinary lookups |
| `SCAN_TIMEOUT_MS` | `60000` | ceiling on a whole check |
| `METRIKA_ID` | — | analytics counter; omitted, no analytics and a tighter policy |
| `HSTS` | — | set to `true` behind TLS |

The container is read-only, unprivileged and writes nothing.

## Development

```bash
npm install
npm start
npm test                              # syntax, translations, unit tests, smoke
npm run scan -- example.com           # the checker without the web server
```

The shared packages are git dependencies, so `npm install` needs `git`:

```json
"@sharapov/service-kit": "github:sharapov-outsource/service-kit#v1.0.0",
"@sharapov/dns-wire":    "github:sharapov-outsource/dns-wire#v1.0.0"
```

## Built on

**[dns-wire](https://github.com/sharapov-outsource/dns-wire)** — the DNS codec.
Node's own module joins the character-strings of a TXT record without saying
where, which is exactly where SPF and DKIM parsing goes wrong.
**[service-kit](https://github.com/sharapov-outsource/service-kit)** — the HTTP
shell, translations and design system.

## The rest of the family

[myip](https://myip.sharapov.biz) ·
[myssl](https://myssl.sharapov.biz) ·
[mydns](https://mydns.sharapov.biz) ·
mymx ·
[myheaders](https://myheaders.sharapov.biz)

## Licence

MIT. See [LICENSE](LICENSE).
