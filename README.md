# mymx

**Русская версия — [ниже](#русская-версия).**

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
"@sharapov/service-kit": "git+https://github.com/sharapov-outsource/service-kit.git#v1.4.1",
"@sharapov/dns-wire":    "git+https://github.com/sharapov-outsource/dns-wire.git#v1.0.0"
```

The URL is spelled out in full because the `github:` shorthand resolves to
`git+ssh://`, and the build has no SSH key. `npm install` writes that form into
`package-lock.json` anyway, so after changing a version rewrite it back:

```bash
sed -i '' 's|git+ssh://git@github.com/|git+https://github.com/|g' package-lock.json
GIT_SSH_COMMAND=/usr/bin/false npm ci   # fails here if any ssh URL is left
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

---

## Русская версия

**[mymx.sharapov.biz](https://mymx.sharapov.biz)** — SPF, DKIM, DMARC, MTA-STS,
DANE и STARTTLS для любого домена.

Без рекламы, без регистрации, без учётных записей. Ничего из того, что вы
проверяете, не сохраняется. Лицензия MIT, двенадцать языков, свой экземпляр
поднимается одним `docker run`.

```bash
curl mymx.sharapov.biz/example.com
```

### Проверка, ради которой всё это существует

**SPF раскрывается через все include и считается против лимита в десять.**

RFC 7208 §4.6.4 разрешает записи десять терминов, обращающихся к DNS, —
`include`, `a`, `mx`, `ptr`, `exists` и модификатор `redirect`, — и считаются
они по *всей* проверке, с заходом в каждый include внутри каждого include.
Свыше десяти получатель обязан вернуть `permerror`, а permerror означает, что
SPF не применяется вообще: письмо оценивается ровно так, как если бы записи не
было.

Превысить лимит легко, и по самой записи этого не видно. Один `include:` может
означать четыре обращения внутри. Добавьте CRM, рассыльщик, службу поддержки и
платёжного провайдера — и домен за лимитом, хотя никто не написал ничего явно
неправильного. И ничего не ломается до того дня, когда какой-нибудь получатель
начнёт это соблюдать. Хуже того, число может вырасти само, без ваших правок, —
оно зависит от того, что лежит внутри чужого include.

Поэтому раскрытие показано деревом с нарастающим счётчиком, и термин, который
вывел за лимит, назван по имени.

Цель с макросом вроде `exists:%{i}._spf.example.com` стоит своего обращения и
оставляется как есть: она разворачивается на каждом соединении по адресу
отправителя, поэтому снаружи не разрешается, а запрос буквального имени вывел
бы здоровые записи за лимит пустых обращений.

### Остальное

**DMARC**, включая ту часть, которую не проверяет никто. Если `rua` указывает на
адрес за пределами вашего домена — а так и есть всегда, когда отчётами занимается
сторонний сервис, — этот другой домен обязан опубликовать
`<ваш-домен>._report._dmarc.<их-домен>`, чтобы согласиться их принимать
(RFC 7489 §7.1). Без этого соблюдающие стандарт получатели не отправляют ничего.
Запись выглядит безупречно, панель остаётся пустой, и почти всегда это списывают
на «отчёты приходят не сразу».

Ещё: `p=none` названо тем, что это есть, — отчётность без всякого применения, —
плюс `sp`, `pct`, выравнивание и политика организационного домена, которую
наследует поддомен.

**DKIM.** Селекторы выбирает тот, кто подписывает, и появляются они только в
заголовке подписанного письма, поэтому перечислить их снаружи нельзя. Здесь
перебираются те, которыми пользуются крупные платформы, и прямо говорится, что
промах — не доказательство отсутствия. Передайте `?selector=`, когда знаете свой,
и ответ станет окончательным. Размеры ключей читаются из DER в самой записи, а не
угадываются; отозванные ключи (пустой `p=`) и тестовый режим (`t=y`) отмечаются
отдельно.

**MTA-STS** забирается по HTTPS и сравнивается с настоящим набором MX. У узла,
который есть в DNS и которого нет в политике, почту отвергнет каждый отправитель,
соблюдающий эту политику, — то есть отваливаются как раз аккуратные отправители.

**DANE.** Записи TLSA сверяются с сертификатом, который сервер действительно
предъявил; селектор и тип сопоставления считаются как положено. Запись TLSA в
неподписанной зоне подаётся как то ложное успокоение, которым она и является.

**STARTTLS** на 25, 465 и 587, с тем, что объявляет каждый сервер, плюс обратный
DNS с прямым подтверждением.

**Проба открытого релея, которая не может отправить письмо.** Она
останавливается на `RCPT TO` — в точке, где сервер уже решил, принял бы он почту
от постороннего для постороннего или нет, — после чего шлёт `RSET` и `QUIT`.
**Команда `DATA` не выдаётся никогда.**

### Про порт 25

Большинство хостинг-провайдеров по умолчанию блокируют исходящие соединения на
порт 25, чтобы их адресное пространство не попадало в списки блокировок. Когда
это так там, где всё это запущено, отчёт об этом и говорит —
`port-25-blocked-from-here`, названо как наша проблема, а не ваша, — затронутые
проверки помечаются как несделанные, а **оценка не выставляется**.

Написать «нет STARTTLS» потому, что *мы* не смогли соединиться, было бы той же
ошибкой, что и выставить оценку серверу, который ограничивал скорость сканеру.
Эту ошибку уже совершали, за счёт банка.

### Оценка

Аутентификация 45%, транспорт 35%, гигиена 20%. Два правила безусловны: открытый
релей — это F, что бы ни было правильно в остальном, потому что это активная
опасность для всех, а не слабость вашей собственной обороны, — и сообщается он
даже по неполной проверке. И когда что-то измерить не удалось, буквы нет вообще,
есть только список того, что установить не получилось.

### API

```bash
curl mymx.sharapov.biz/example.com                    # полный отчёт
curl mymx.sharapov.biz/api/example.com?output=yaml    # YAML
curl mymx.sharapov.biz/api/stream/example.com         # server-sent events
curl "mymx.sharapov.biz/api/example.com?selector=k1"  # селектор DKIM, который мы бы не угадали
curl mymx.sharapov.biz/example.com?lang=en            # подписи на другом языке
```

Следить за бюджетом SPF из скрипта:

```bash
curl -s mymx.sharapov.biz/api/example.com | jq '.spf.budget'
```

### Запуск своего экземпляра

```bash
docker run -d --name mymx -p 127.0.0.1:3027:3027 ghcr.io/sharapov-outsource/mymx:latest
```

| Переменная | По умолчанию | Что делает |
|---|---|---|
| `PORT` | `3027` | порт прослушивания |
| `TRUST_PROXY` | `true` | брать адрес клиента из заголовков прокси. **Выключить**, когда сервис смотрит в интернет напрямую |
| `SMTP_PORT_25` | — | `open` или `blocked`, чтобы пропустить исходящую пробу и объявить ответ |
| `SMTP_CHECK_465` / `SMTP_CHECK_587` | `true` | поставить `false`, чтобы пропустить порт отправки |
| `SMTP_MAX_HOSTS` | `3` | к скольким узлам MX подключаться |
| `SMTP_EHLO_NAME` | `mymx.sharapov.biz` | имя, которым представляться в `EHLO` |
| `DNS_RESOLVER` | `1.1.1.1` | резолвер для обычных запросов |
| `SCAN_TIMEOUT_MS` | `60000` | потолок на всю проверку |
| `METRIKA_ID` | — | счётчик аналитики; без него аналитики нет, а политика строже |
| `HSTS` | — | поставить `true` за TLS |

Контейнер только для чтения, без привилегий, ничего не пишет.

### Разработка

```bash
npm install
npm start
npm test                              # синтаксис, переводы, юнит-тесты, smoke
npm run scan -- example.com           # проверялка без веб-сервера
```

Общие пакеты подключены как git-зависимости, поэтому `npm install` требует `git`:

```json
"@sharapov/service-kit": "git+https://github.com/sharapov-outsource/service-kit.git#v1.4.1",
"@sharapov/dns-wire":    "git+https://github.com/sharapov-outsource/dns-wire.git#v1.0.0"
```

Адрес выписан полностью, потому что сокращение `github:` разворачивается в
`git+ssh://`, а у сборки нет ключа SSH. `npm install` всё равно записывает эту
форму в `package-lock.json`, так что после смены версии её надо переписать
обратно:

```bash
sed -i '' 's|git+ssh://git@github.com/|git+https://github.com/|g' package-lock.json
GIT_SSH_COMMAND=/usr/bin/false npm ci   # здесь и упадёт, если ssh-адрес остался
```

### На чём построено

**[dns-wire](https://github.com/sharapov-outsource/dns-wire)** — кодек DNS.
Родной модуль Node склеивает символьные строки записи TXT, не говоря, где был
шов, — а именно на этом ломается разбор SPF и DKIM.
**[service-kit](https://github.com/sharapov-outsource/service-kit)** — оболочка
HTTP, переводы и оформление.

### Остальная семья

[myip](https://myip.sharapov.biz) ·
[myssl](https://myssl.sharapov.biz) ·
[mydns](https://mydns.sharapov.biz) ·
mymx ·
[myheaders](https://myheaders.sharapov.biz)

### Лицензия

MIT. См. [LICENSE](LICENSE).
