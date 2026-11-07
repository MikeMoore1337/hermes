# H809 - автоматический Engineering Control в существующем QA Watcher

## Граница

Ранее проверенный Hermes QA watcher выполнялся ~17 секунд при TimeoutStartSec=22s. Полный дополнительный публичный GitHub/npm обход без ограничения мог бы нарушить CI-наблюдение.

Новый режим команды `python3 -m qa_advisor.watch_once --execute --engineering-auto` выполняет существующие CI, GitHub Observe и Project Observe **первыми**. Только затем запускает публичные Engineering Control проверки. Переиспользуются **те же сервис и 15-минутный таймер**. Новая служба, scheduler, агент, paid API, GitHub/OS права или токен не создаются.

## Четыре проверяемых источника

- ReleaseGuard: текущий main Hermes, exact SHA и фактические GitHub CI.
- MergeControl: ограниченная выборка открытых PR, head/base SHA и потенциальные пересечения файлов. Не доказательство реального Git-conflict.
- OpenSource Radar: фиксированный публичный upstream NousResearch/hermes-agent, source SHA, LICENSE/NOTICE, root metadata и публичные advisory signals, без скачивания исходного кода и установки.
- DepPilot: утверждённый публичный lockfile `control_center/frontend/package-lock.json` из уже установленного выпуска Control Center (`/opt/hermes-control-center/current/control_center/frontend/package-lock.json`); пакет react. Node.js 22 - целевая версия CI toolchain, а не проверенная версия установленного Node на VPS. Совместимость не предполагается без доказательств.

Недоступные сведения обозначаются NOT_AVAILABLE/INCONCLUSIVE. Ошибки источника, включая ограничения GitHub и неизвестные данные, **не** превращаются в GO.

## Безопасность и производительность

- В Linux main thread для дополнительного сбора установлен строгий 38-секундный SIGALRM, включая сохранение очищенного отчёта. Существующий alarm не перехватывается.
- Дополнительный **публичный** сбор допускается не чаще одного раза за 45 минут. Перед первым сетевым запросом создаётся фиксированный `engineering-auto-attempt` (0600, root-only) **в уже существующем** `/var/lib/hermes-qa-watch` (0700). Неблокирующая файловая блокировка не допускает параллельных циклов. Любая попытка, в том числе закончившаяся ошибкой/таймаутом, расходует текущий бюджет; повторный запуск возвращает `SKIPPED_COOLDOWN` без GitHub/npm запросов. Неверная метка, права или недоступная блокировка приводят к безопасному отказу без сети. Это один небольшой служебный маркер, не отдельная БД или планировщик.
- На один разрешённый 45-минутный цикл допускается не более **26 публичных GitHub GET** через единый клиент, а MergeControl читает максимум **3 открытых PR**. Остальные помечаются неполными (`pr_window_incomplete`), не считается, что конфликтов нет. Ограничение защищает общую бесплатную квоту GitHub; ошибки 403/429 дают частичный/неизвестный результат без повторных запросов.
- Существующий QA unit получает TimeoutStartSec=75s; MemoryMax=96M, CPUQuota=10%, filesystem restrictions, NoNewPrivileges и 15m cadence неизменны. Никаких отдельного таймера или расширения прав.
- При сбое автоматического сбора оригинальный QA-сигнал и обе GitHub Observe выдачи сохраняются. В журналах только фиксированные статусы. Пропущенный цикл или недоступный источник может сделать отчёт `STALE`; это корректная защитная реакция, а не доказательство отсутствия рисков.
- Результаты записываются через проверенный engineering_feed.save: 0700 root-only directory, 0600 atomically stored JSON. Не сохраняются сырые описания PR, секреты и URL.
- Command Center использует существующий snapshot collector и owner-only Operator Inbox с фиксированными статусами; подпись coverage теперь нейтральна к ручному/автоматическому запуску. Никаких новых визуальных компонентов, кнопок исполнения или полных прав.

## Активация и rollback

**Merge и GitHub CI не активируют production.** После отдельного owner approval на точный актуальный cumulative main SHA выполнить штатный production deploy с verified QA/UI CI, receipt и rollback. Существующий установленный systemd QA unit нужно **отдельно** заменить в проверенном maintenance window (обычная доставка архива НЕ обновляет /etc/systemd/system автоматически):

1. Сверить точный digest нового QA unit, diff с текущим и `systemd-analyze verify`; сохранить root-only backup старого unit.
2. Убедиться, что QA job не выполняется. Атомарно заменить только QA unit, `daemon-reload`. Интервал действующего timer не менять.
3. Наблюдать минимум два реальных 15m цикла с исходным CI/Observe и дополнительным Engineering Control; проверить результат, `SKIPPED_COOLDOWN` между доступными обновлениями, права feed и маркера `engineering-auto-attempt`. Для подтверждения реального повторного сбора потребуется наблюдение не менее 45 минут.
4. При ошибках вернуть старый verified unit из backup, сделать reload, сохранить все прежние данные и маркер попытки (не удалять его ради обхода квоты), не отключать YFC, Ops Watch, Research Scout и ограниченный H-01.
5. Owner-auth browser UAT #747 остаётся отдельной задачей. Вся визуальная переработка требует отдельного одобрения.

До такой установки и физической приёмки статус: CODE_READY / RUNTIME_AUTO_NOT_VERIFIED.

## Тесты

`python3 -m unittest tests.test_engineering_auto tests.test_engineering_once tests.test_engineering_feed -v`, затем полноценные GitHub Actions checks на точном PR HEAD. Моки не заменяют production-таймер.

Связанные задачи: #809, ранее завершённый MVP #771, независимая owner UAT #747.
