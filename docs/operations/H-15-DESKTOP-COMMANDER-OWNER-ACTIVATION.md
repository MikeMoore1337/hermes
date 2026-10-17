# H-15 Desktop Commander: активация на VPS (#275)

Подготовлено 18.10.2026. Владелец разрешил отдельный OAuth Remote MCP и изолированный локальный тест tools/list. Это не разрешение включать инструменты в ограниченный агент H-01 (#33).

## Обязательный интерактивный SSH-шаг

На момент проверки все три устройства Online, но удалённые команды заблокированы из-за облачной квоты 0%. ChatGPT OAuth не используется Hermes и не переносится в него. Привилегированный CD SSH поддерживает только deploy и не даёт произвольного shell. Нужен один вход владельца по SSH на vps1777112993.

Подставить фактический SHA последнего успешно доставленного release из GitHub Actions и перейти в его директорию:

    cd /opt/hermes-agent-owner/releases/main-<ACTUAL_SHA>
    sudo bash deploy/h15-desktop-commander-setup.sh status
    sudo bash deploy/h15-desktop-commander-setup.sh prepare
    sudo bash deploy/h15-desktop-commander-setup.sh local

prepare создаёт изолированного пользователя hermes-desktop, устанавливает Node-пакеты @wonderwhy-er/desktop-commander@0.2.52 и mcp-remote@0.13.5 в его собственный каталог без запуска npm от root. Устанавливает unit templates, но не включает службу. Нужны Node.js >= 22.12.0 и npm. Установщик проверяет фактическую версию под `hermes-desktop`, а npm запускается с `--engine-strict`, чтобы несовместимые зависимости не устанавливались с предупреждениями. Если системный Node.js старше, отдельно обновить ветку 22.x из официального репозитория NodeSource, предварительно просмотрев `apt-get -s install nodejs`. Системные пакеты, H-01, Caddy, Second Brain, YFC и Codex не изменяет.

local вызывает только initialize и tools/list. При старте используется upstream-флаг --no-onboarding, чтобы не запускать welcome/browser onboarding. Максимальный бюджет локального probe — 60 секунд. На неуспехе печатается только стадия (initialize/tools_list) и безопасный класс ошибки из stderr без раскрытия исходного текста логов. Список инструментов НЕ означает право их фактического выполнения агентом. Ожидается LOCAL_MCP_TOOLS_LIST=PASS.

Если LOCAL_MCP_PROBE=FAILED с причиной local_initialize_timeout или local_tools_list_timeout, не переходить к auth/enable. Сохранить короткую диагностическую строку для Issue #275; секреты и приватный stderr не публиковать.

## Авторизация

    sudo bash deploy/h15-desktop-commander-setup.sh auth

Команда запускает интерактивный OAuth-клиент под hermes-desktop и выводит ссылку входа. Открыть её на собственном ПК. Если localhost callback недоступен, открыть с Windows ПК отдельный SSH-туннель с реальным портом, напечатанным OAuth (часто 3334):

    ssh -N -L 3334:127.0.0.1:3334 <SSH_USER>@<HERMES_VPS_HOST>

Сначала открыть туннель, затем завершить OAuth. Не публиковать код, state, callback URL и содержимое .mcp-auth в чат, GitHub или CI. При HTTP 403/500 на стороне провайдера остановиться и сообщить только обезличенный код ошибки.

## Реальная проверка и таймер

После успешного OAuth:

    sudo bash deploy/h15-desktop-commander-setup.sh verify
    sudo bash deploy/h15-desktop-commander-setup.sh enable
    sudo bash deploy/h15-desktop-commander-setup.sh status

verify делает ТОЛЬКО реальный who_am_i/list_devices и записывает очищенный статус/SQLite-историю; выводит status, процент, число устройств и точек истории. Статус exhausted допустим для read-only мониторинга и запрещает cloud execution. enable требует свежий настоящий снимок, включает только telemetry timer на 15 минут, без команд на устройствах. При unavailable/stale/unknown включение невозможно.

Проверить виджет «Устройства» на https://hermes.mikemoore.top/ после первого опроса.

## Откат

    sudo systemctl disable --now hermes-desktop-commander.timer
    sudo systemctl stop hermes-desktop-commander.service
    sudo bash deploy/h15-desktop-commander-setup.sh status

Не удалять OAuth токены или устройства без отдельного желания владельца. Контур H-01 остаётся без новых MCP/shell полномочий.
