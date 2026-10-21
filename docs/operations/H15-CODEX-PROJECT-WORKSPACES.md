# H15: Codex + доступ к проектам через собственный BRC

## Состояние и границы

Цель #297/#372: ChatGPT и Codex используют `https://mcp.mikemoore.top/mcp` без платного облачного посредника Desktop Commander. Это устраняет **квоту посредника**, но не лимиты моделей, вычислительных ресурсов и GitHub.

Устройства: Windows `h15-win-05be75515428`, Hermes VPS `h15-hermes-ab005bc0e0ea`, YFC VPS `h15-yfc-c6ee0d53e858`. При нескольких устройствах **всегда** указывать `deviceId`. Фактическую доступность смотреть через `list_devices`, а не утверждать по этому документу.

Windows BRC работает под Linux Docker без прав администратора, его `/workspace` — смонтированный каталог `C:\Users\Mike\Hermes-H15-Test`. Оба VPS видят только свои отдельные `/workspace`. Не расширять монтирования в production, не добавлять Docker socket, ключи, частное хранилище Second Brain, базы данных YFC или каталоги Hermes H-01.

## Codex (локальный Windows)

`deploy/h15/codex-hermes-mcp.ps1`:
1. `-Mode Check`: проверка установленного Codex CLI и текущей конфигурации без изменений.
2. `-Mode Install`: резервная копия `~/.codex/config.toml` с проверкой SHA-256; затем официальный `codex mcp add hermes --url https://mcp.mikemoore.top/mcp`. Если запись `hermes` уже есть — без перезаписи.
3. `-Mode Login`: официальный интерактивный `codex mcp login hermes` с OAuth через браузер. Не копировать токены в чат.
4. `-Mode Status`: проверить конфигурацию через `codex mcp list`. Перезапустить Codex Desktop/IDE, чтобы обновились MCP-действия.

**Codex E2E ещё не подтверждён, пока Codex лично не вызвал** `list_devices`, `read_file`, `write_file`, `start_process` с конкретным `deviceId`. Регистрация сервера сама по себе недостаточна. Не включать API-ключи и не менять настройки других MCP.

## Подготовка рабочих копий Git

`deploy/h15/windows-project-workspaces.ps1` создаёт **новые чистые копии публичного кода** в уже согласованной папке Windows, не затрагивая оригинальные рабочие каталоги и их незакоммиченные изменения:

| Ключ | В Windows | В BRC |
| --- | --- | --- |
| Hermes | `Hermes-H15-Test\projects\hermes` | `/workspace/projects/hermes` |
| YFC | `Hermes-H15-Test\projects\your-fitness-coach` | `/workspace/projects/your-fitness-coach` |
| SecondBrain (только публичный код) | `Hermes-H15-Test\projects\second-brain` | `/workspace/projects/second-brain` |
| Toolkit (только справочник навыков) | `Hermes-H15-Test\projects\ai-development-toolkit` | `/workspace/projects/ai-development-toolkit` |

- `-Mode Check` — без изменений.
- `-Mode Prepare -Project Hermes` — отдельно склонировать Hermes.
- `-Mode Prepare -Project YFC` / `SecondBrain` / `Toolkit` — отдельные копии.
- `-Mode Prepare -Project All` — все четыре, YFC большой; потребуется место и время.
- `-Mode Status` — сверка origin и ветки каждого существующего клона.

Используется `git clone --depth 1 --single-branch --filter=blob:none`, без автоматического `pull`, `reset`, удаления или перезаписи существующих каталогов. Папки с несоответствующим origin/веткой отклоняются. Частично созданную папку сохранять до разбора ошибки. Репозитории **не становятся точной копией локальных несохранённых правок** пользователя. Частное хранилище Second Brain не копируется.

В новых рабочих копиях перед задачей читать соответствующий `AGENTS.md`; использовать нужные роли/навыки AI Development Toolkit только как источники инструкций. Отчёты других проектов никогда не сохранять в Toolkit. Изменения выполнять в отдельной ветке и через PR/CI, а не непосредственно в защищённой `main`/`master`.

Для тяжёлых задач Codex на Windows может работать в своём локальном репозитории **непосредственно**, а BRC использовать для удалённых ресурсов. Для подключения **исходных локальных каталогов**, производственных VPS-каталогов или приватных файлов понадобится отдельное точное разрешение на путь и проверка изоляции — автоматического расширения прав не предусмотрено.

## Проверки / отзыв

1. На Windows `-Mode Check` для обоих сценариев.
2. Codex OAuth с собственной авторизацией; без платных API.
3. `-Mode Prepare -Project Hermes`, проверить файл `/workspace/projects/hermes/AGENTS.md` на Windows через ChatGPT и затем через Codex.
4. Отдельный `deviceId` при каждом обращении; после трёх устройств обязательно негативные пробы межустройственной маршрутизации.
5. `codex mcp remove hermes` — только по решению владельца, после проверки имени подключения; при восстановлении TOML сверить свежие изменения. Windows-агент можно отдельно остановить прежним проверенным `windows-agent.ps1 -Mode Stop`, но это отзывает устройство и не является безусловным штатным шагом установки.
6. Тесты исходников и синтаксиса PowerShell CI **не заменяют** живую проверку Codex и фактическую доступность рабочих копий.

До подтверждения Codex E2E и восстановления агентов после перезагрузки #297/#372 остаются открытыми. Пакет относится к source-only изменениям; merge/deploy кода не меняет действующие службы.
