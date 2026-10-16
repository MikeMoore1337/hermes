# H-12 / H-01: read-only проверка сетевых ограничений VPS

Дата: **16.10.2026**. Основание: #64 Statejnik, #33 H-01.
Режим: `NO-GO` для запуска сетевого Hermes Agent / Statejnik.
Аудит **только читает** существующую конфигурацию; никакие
сетевые правила, unit-файлы, службы, токены и backend не менялись.

## Наблюдаемые факты на VPS

Машина: production Hermes VPS; состояние снимка 16.10.2026.
Выполнено чтение через `systemctl show hermes-agent-sandbox.service`:

| Поле | Наблюдаемое значение |
|---|---|
| `ActiveState` | `inactive` |
| `LoadState` | `loaded` |
| `PrivateNetwork` | `no` |
| `NetworkNamespacePath` | пусто |
| `IPAddressDeny` / `IPAddressAllow` | пусто |
| `ProtectSystem` | `strict` |
| `NoNewPrivileges` | `yes` |
| `RestrictAddressFamilies` | `~` (требуется уточнить точный effective набор) |

На хосте есть `nft`, `iptables`, `ip6tables`, `unshare`,
`nsenter`, `systemd-run`, `docker`; `bubblewrap/bwrap`
и `podman` отсутствуют. `docker info` сообщает AppArmor,
seccomp builtin и cgroup namespace. Это **наличие инструментов**,
не доказательство разрешённых конкретных rootless namespaces,
не доказательство firewall egress, DNS pin, блокирования cloud
metadata и не итог CVE/SBOM проверки.

Пять существующих Hermes timers оставались `active`.
`hermes-agent-sandbox.service` остаётся `inactive`,
`hermes-cloudflare-proxy.service` остаётся `inactive`.
В рамках данного аудита не выполнялись `iptables/nft add`,
`systemctl set-property`, рестарты или внешние сетевые пробы.

## Строгое разграничение

Наличие `network_boundary`, `supervised_fetch` с внешним
20-секундным kill-budget, HTTPS exact-host DNS/TLS-pin и
15-секундного POSIX SIGALRM **не** формирует полноценный
per-workload egress security boundary. Сейчас для
`hermes-agent-sandbox.service` по `systemctl show` нет
выделенной системной сетевой изоляции или IP denylist.
Это **не утверждение**, что на VPS отсутствует глобальный
firewall: его правила и сетевые include отдельно не проходили
полноценный security review.

Нельзя считать поддержку systemd `PrivateNetwork=yes`
самодостаточной для будущих публичных HTTPS-вызовов: она
блокирует всю сеть, а для выборочного доступа потребуется
управляемый network namespace/сегментация с отдельным
выходным прокси или OS-filter allowlist. DNS hostname allowlist
в одном Python-модуле не заменяет блокировку IP на уровне ОС.

## Acceptance gate перед реальной сетью

1. Отдельная непроизводственная network namespace/изоляция
   без привилегий и без доступа к host, cloud metadata,
   loopback host и приватным подсетям по IPv4 и IPv6.
2. Версионированная firewall-policy с default-deny outbound
   и **только** явно утверждёнными адресами/портами;
   исключение маршрутов через прокси и DNS/IPv6 leak.
3. Доказательство негативных тестов на namespace, redirect,
   DNS rebinding, отказ провайдера, слабое/неверное TLS,
   прерывание зависшего DNS/HTTP child внешним watchdog.
4. Независимый обзор правил, журналирование тестов без
   секретов, rollback без удаления действующих служб Hermes;
   owner security/production approval на включение.
5. Даже после OS-GO: Wordstat IAM/billing hard stop,
   robots/право на контент, CMS/YFC publication approval —
   отдельные обязательные gates.

**Итог:** `H12_OS_EGRESS_ENFORCEMENT_NOT_VERIFIED`,
`H01_RESIDENT_AGENT_NO_GO`, `STATEJNIK_LIVE_NETWORK_NO_GO`.
Это blocker, а не просьба установить firewall немедленно.
