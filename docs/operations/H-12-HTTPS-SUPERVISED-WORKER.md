# H-12 / #64 — внешний watchdog HTTPS worker, без включения сети

Дата: **16.10.2026**. Статус **OFFLINE_EVIDENCE / NETWORK_RUNTIME_NO_GO**.

Проблема: предыдущий `SIGALRM`-таймер прерывает Python-фазу
медленного HTTP-чтения, но системное DNS-разрешение или другой
блокирующий C-вызов может задержать обработку Python сигнала. Этот
риск нельзя объявлять закрытым одним `setitimer`.

## Исправление в отдельном изолированном кандидате

Новый **не зарегистрированный** в runtime модуль
`statejnik_integration.supervised_fetch` создаёт *только*
отдельный дочерний Python-процесс с `-I -B`, запускающий
`statejnik_integration/_fetch_worker.py`.

- По умолчанию `network_authorized=False` — **DENY ещё до создания
  дочернего процесса**. Нет планировщика, фонового опроса, UI-команды,
  Wordstat, ключей, paid fallback, CMS, публикаций и YFC writes.
- Кандидат отклоняет любой URL с userinfo, query, fragment,
  небезопасным портом/доменом, non-HTTPS, слишком длинной или
  Unicode-командной строкой. Только явно разрешённый публичный
  хост, HTTPS 443, длина URL до 512 ASCII символов.
  URL **передаётся в argv**: поэтому нельзя передавать туда секреты,
  пользовательские запросы, токены, приватные ссылки или ID.
- Parent использует общий `scripts.bounded_subprocess.run_bounded`
  с `timeout=20` секунд, `stdout_limit=8192` байт,
  `stderr_limit=2048`, `env` только PATH и
  PYTHONDONTWRITEBYTECODE. Shell=false. Если worker превысил
  wall-budget, родитель посылает kill всей группе дочерних процессов
  и завершает сбор stdout/stderr. Рабочее тело HTML не передаётся
  обратно: возвращаются только заголовки title/H1, SHA256 и явные
  `source_authenticity_verified=false`/публикационные запреты.
- Worker ещё раз проверяет URL/allowlist и вызывает только
  `html_review.candidate_fetch_one` →
  `network_boundary.fetch_public_html` с pinned DNS/TLS и
  дополнительным 15-секундным POSIX SIGALRM guard.
- Parent повторно валидирует JSON, типы, длины, SHA256, URL,
  запреты на публикацию/Wordstat и синтаксис заголовков.
  Любая ошибка child, недопустимый вывод или timeout даёт
  фиксированный обезличенный отказ без URL/HTML/stderr.
- Оригинальные 62 файла подаренного Statejnik не меняются.

**Это кандидат, не разрешённый live network:** его никто не
вызывает в Hermes runner, Control Center, существующих timers,
YFC и Second Brain. Никакой внешний HTTP/DNS не производится
в acceptance tests.

## Evidence и оставшиеся gate

В тестах parent проверен с синтетическим worker JSON и
запрещёнными host/query/URL; реальный standalone worker
с `http://127.0.0.1` отклоняется без DNS.
Отдельный дочерний Python-процесс с `sleep(8)` убит
тем же `run_bounded` после ~0.18 секунды; проверено,
что родитель не дожидается зависшего child.
Это подтверждает **внешний процессный kill-budget**, но
не является проверкой реального сетевого соединения.

Для GO по-прежнему необходимы: независимый firewall/namespace,
невозможность прямого обхода egress allowlist, DNS rebind/redirect
live E2E в безопасном стенде, проверка `robots`, TLS,
провайдерских прав и Wordstat billing, явный owner network GO
и отдельное owner approval на публикации.

Решение: `SUPERVISED_CANDIDATE_OFFLINE_TESTED`,
`OS_EGRESS_NOT_VERIFIED`, `WORDSTAT_BILLING_NO_GO`,
`PUBLICATION_NO_GO`, `RESIDENT_HERMES_NO_GO`.
