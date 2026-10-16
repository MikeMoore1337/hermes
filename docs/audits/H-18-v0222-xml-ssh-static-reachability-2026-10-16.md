# H-18 #199 — XML и SSH: точечная проверка поверхности v0.22.2

**2026-10-16. Verdict: P0_REVIEW_REQUIRED.** Проверка точного upstream Git commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`. Только чтение локального чистого checkout, AST-разбор четырёх публичных файлов, без запуска SSH, парсера с недоверенными документами, процессов Hermes, Docker, сетевых запросов и VPS-изменений.

## Фактически проверено

Использован `scripts/audit_v0222_xml_ssh_surfaces.py --execute --source-tree <pinned-clean-checkout>`. Он проверяет Git HEAD и clean tracked tree через существующий H-18 helper, читает только четыре строго перечисленных файла, фиксирует SHA256 и структурные вызовы, не печатает исходники.

| Файл | Факты исходника |
| --- | --- |
| `plugins/platforms/wecom/wecom_crypto.py` | импорт `xml.etree.ElementTree`, явных сторонних XML imports нет |
| `tools/read_extract.py` | импорт `xml.etree.ElementTree`, вызовы `ET.fromstring` на строках **465, 527**, а также `subprocess.run` на 258 для `pdftotext` |
| `tools/environments/ssh.py` | реализация SSH backend с процессными вызовами на **213, 216, 258, 300**; фактический `ssh`/архивные операции определяются конфигурацией |
| `hermes_cli/setup_terminal.py` | SSH setup осуществляет `subprocess.run` на **246** |

В этих двух XML-файлах *синтаксически* показан stdlib `xml.etree`, но это **не исключает** присутствие/использование `libxml2` остальными модулями, зависимостями, native binaries или динамическими plugins; нельзя объявить CVE-2026-6653 `NOT_APPLICABLE`. Наличие SSH backend не означает его доступность разрешённому Agent, но явно исключает утверждение «SSH-кода нет». Для CVE-2026-60002 нужен реальный OS/egress/tool deny, никакого безопасного waiver на основании только source.

Здесь **нет** настоящего выполнения SSH, исходящих соединений, подстановки секретов, загрузки XML и exploit. `10/10` синтетических unit tests проверяют no-GO, синтаксис/import, контроль обязательных путей, изменение байтов, большие файлы, fail-closed ошибки, отсутствие утечек и невозможность неявного запуска.

## Ограничения и дальнейшие gate

- Скрипт не проверяет shell/SSH или libxml2 runtime reachability, native tool ACL, seccomp/AppArmor, egress-policy и dynamic import/call.
- Static AST доказательство принадлежит только фиксированному v0.22.2 source. Локальный PyJWT 2.15.1 derivative из PR #216 не выводит Linux/SSH/libxml2 из риска.
- Дальше нужны OS-level негативные тесты deny-by-default без нарушения рабочих таймеров, cgroup/nft/egress эксперименты в sandbox, source-to-image signer, pinned SBOM на новом build и vendor remediation, затем ограниченный burn-in.
- `#199 OPEN`, `#33 resident_agent_allowed=false`. Код размещён только в repo. Production/VPS не менялся.
