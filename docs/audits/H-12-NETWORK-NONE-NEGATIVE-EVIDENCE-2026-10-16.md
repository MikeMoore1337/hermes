# H-12 — реальные OS-отказы IPv4/IPv6 в immutable offline Docker

Дата: **16 октября 2026**. Issue: #64, зависимость #33.

## Исполненное изолированное испытание

Добавлен воспроизводимый `scripts/verify_h12_egress_isolation.py`.
Без `--execute` программа не запускает Docker и возвращает
`NOT_EXECUTED`. При явном `--execute` работает **только** с
локально кешированным immutable `nousresearch/hermes-agent` v0.22.2
на linux/amd64, с проверкой digest до запуска. Никакой pull,
сборки или установки в production.

Ограничения Docker:

- `--network none` — изолированный контур без внешних сетевых интерфейсов;
- `--pull=never --read-only --cap-drop ALL`;
- `--security-opt no-new-privileges --user 65534:65534`;
- `--cpus 0.5 --memory 256m --memory-swap 256m --pids-limit 25`;
- tmpfs только `/tmp`, объём 16 MiB, `noexec,nosuid,nodev`;
- нет mounts, Docker socket, host network, credentials,
  tokens, Wordstat, CMS, YFC или каких-либо исполняемых vendor tools.

Внутри именно Linux-контейнера выполняются девять проверок:

| Проверка | Результат |
|---|---|
| UID и GID 65534 | PASS |
| Effective capabilities = 0 | PASS |
| Только интерфейс loopback (`lo`) | PASS |
| Нет default IPv4 route | PASS |
| Нет **пригодного** default IPv6 route; `::/0` возможен только с флагом `RTF_REJECT=0x200` | PASS |
| TCP к cloud metadata `169.254.169.254:443` запрещён | PASS |
| TCP к private `10.0.0.1:443` запрещён | PASS |
| TCP к TEST-NET `192.0.2.1:443` запрещён | PASS |
| TCP к документационному IPv6 `2001:db8::1:443` запрещён | PASS |

**Уточнение критериев 16.10.2026:** первоначальный тест маршрутов
IPv6 проверял формат длины префикса неверно и пропускал присутствующую
в Linux служебную запись `::/0` с `RTF_REJECT`. Повторный аудит
реального `/proc/net/ipv6_route` на том же контейнере обнаружил эту
запись. Проверка исправлена: теперь читает таблицу строго (отказ при
ошибке/невалидной схеме), интерпретирует 2-символьную длину префикса
`00` и подтверждает **именно запрет** `RTF_REJECT=0x200`. Любой
пригодный `::/0` вызывает FAIL. `/proc/net/route` также обязан
содержать читаемый корректный заголовок. В результате новый запуск
дал 9/9 PASS с действительным доказательством reject-маршрута,
а не из-за ошибочной проверки длины поля.

Проверки TCP используют `socket.connect_ex` с коротким
тайм-аутом и принимают **только** системные отказы маршрута/
интерфейса/адреса. Успешное TCP, `ECONNREFUSED`, неопределённый
результат или сетевой timeout не дают PASS. В контейнере нет
внешнего маршрута, поэтому попытки не могли выйти на удалённые
сети. **HTTP/HTTPS к указанным адресам не выполнялся.**

Запуск в отдельном Docker Desktop на Windows:
`py -3.14 -m scripts.verify_h12_egress_isolation --execute`.
Результат `OFFLINE_NETWORK_NONE_OS_DENIALS_PASS`,
`checks_passed=9`, `checks_total=9`, `failed_checks=[]`.
Отдельные unit tests проверяют отрицательные результаты,
неверную схему и duplicate JSON fields, отсутствие любого
выполнения по умолчанию.

## Что этот PASS **не доказывает**

- **Не** подтверждает действующие iptables/nft rules на VPS.
  Проверки делались на отдельном Docker-хосте, а не
  через resident service. Нет production network modification.
- `--network none` допускает только полностью отключённую сеть.
  Он **не** реализует выборочный доступ к нескольким
  внешним сайтам и не подтверждает egress allowlist.
- Не проведены live E2E TLS/сертификатов, DNS rebinding/redirect,
  IPv6 leak через разрешённые каналы, `robots` и блокировки
  приватных сетей при наличии исходящего маршрута.
- Оригинальная v0.22.2 подпись/provenance, CVE/SBOM
  и resident native-tools policy не закрываются этой проверкой.
- Нет права запускать Wordstat, делать платные запросы,
  получать контент из сети, публиковать в CMS либо писать в YFC.

Следующий security gate: **изолированная default-deny egress
сеть в непроизводственном окружении**, OS allowlist с доказанным
отказом private/metadata IPv4+IPv6, без DNS/proxy leaks;
изолированный проверенный TLS E2E, затем отдельный owner GO
на production/провайдеров/публикации.

Итог: `NETWORK_NONE_OS_NEGATIVE_PASS`,
`SELECTIVE_EGRESS_ALLOWLIST_NO_DATA`,
`PRODUCTION_EGRESS_NO_GO`, `RESIDENT_NO_GO`,
`WORDSTAT_NO_GO`, `PUBLICATION_NO_GO`.
