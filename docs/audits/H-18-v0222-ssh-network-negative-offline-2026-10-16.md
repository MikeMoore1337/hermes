# H-18 / #199 — реальный локальный network-none и scoped SSH negative

**Дата:** 2026-10-16. **Вердикт:** `NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS`, **только локальный sandbox**. `resident_agent_allowed=false`. К production, YFC и Second Brain отношения не имеет.

## Проверенный объект

- Локально доступный заранее созданный PyJWT 2.15.1 derivative Hermes v0.22.2, **точный image ID** `sha256:90e878c4af899364fb56be9e7c4f5e96ca06c4741b6c94cc79260f07f919ebe9` (linux/amd64). Исходный base: официальный exact `nousresearch/hermes-agent@sha256:a11574b7...`. Candidate содержит native tool policy guard и PyJWT 2.15.1 после реального локального offline build по [#216](https://github.com/MikeMoore1337/hermes/pull/216). Никаких новых Docker build, registry pull, provider account/secret или publication.
- На отдельном Windows 11 Docker Desktop **действительно** выполнен opt-in inspector `scripts.probe_h18_ssh_network_denial --execute`. До запуска `docker image inspect` проверяет точный local SHA256 ID и linux/amd64; несовпадение = INCONCLUSIVE. `docker run --rm --pull=never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534`; CPU 0.5, 768 MiB, 32 PIDs, /tmp отдельный tmpfs. Не монтировались volume, Docker socket, ключи, домашняя папка, виртуальные проекты, секреты.
- Внутри исполнялся только Python `/opt/hermes/.venv/bin/python -B -c` с жёстко закреплённым синтетическим inspector. **Настоящий SSH binary, shell, Hermes Agent loop и LLM не запускались**.

## Реальные отрицательные проверки

1. В namespace `--network none` Python `socket.connect_ex(("192.0.2.1", 22))` (RFC 5737 TEST-NET-1, без DNS и реального сервера) вернул **Linux ENETUNREACH = 101**. Следовательно, в этом *конкретном Docker network namespace* нет TCP маршрута к тестовому адресу. Это **не** доказывает production nftables, все протоколы или будущие контейнерные конфигурации.
2. Перед двумя синтетическими вызовами `model_tools.handle_function_call` `terminal {"command":"ssh SYNTHETIC_NO_EXEC"}` и `process {"action":"list"}` final executor `_execute_tool`, registry `dispatch` и OS `subprocess.Popen` **подменены `unittest.mock`**, каждый spy бросает исключение, если его пытаются вызвать. Запись: `native_executor_reached=false`, `registry_dispatch_reached=false`, `process_spawn_attempted=false`, `model_or_real_ssh_executed=false`. Это реальное выполнение маршрутизации `model_tools` локального derivative, но **не исполнение настоящей запрещённой команды**.
3. Итог inspector валидируется строгим JSON contract с лимитом 4096 байт и duplicate-key rejection. Только согласованные результаты, Linux errno и явное подтверждение mocking позволяют выдавать **bounded PASS**. Не поддержанные/неполные результаты, реальные executor calls, отсутствие network denial дают `DENIAL_BOUNDARY_NOT_PROVEN` или `INCONCLUSIVE`, всегда exit 2 и resident NO-GO.
4. **Сначала была обнаружена ошибка reviewer на Windows:** сравнивались host-errno вместо Linux target errno, поэтому первый реальный результат ENETUNREACH 101 ошибочно получил `DENIAL_BOUNDARY_NOT_PROVEN`. Код reviewer исправлен, ожидаемые Linux errno зафиксированы явно (101/113/100/13/1), и реальный inspector запущен повторно. Повторный результат **`NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS`**, network denied `true`. Никакой ложный GO не выдавался.

Локальные тесты `tests/test_h18_ssh_network_denial.py`: **12/12 PASS**, включая отрицательные случаи успешного TCP connect, ложного denied proof, достижения каждого mock boundary, неотмеченного mocking, wrong immutable image ID, неправильных JSON/дубликатов, отсутствия неявного запуска и redaction failure.

## Запуск (только из разрешённого отдельного Windows Docker хоста)

```bash
python3 -m unittest tests.test_h18_ssh_network_denial -v
python3 -m scripts.probe_h18_ssh_network_denial
# NOT_EXECUTED, exit 0; Docker вообще не вызывается.
python3 -m scripts.probe_h18_ssh_network_denial --execute
# NETWORK_NONE_AND_SCOPED_NATIVE_DENIAL_BOUNDED_PASS, exit 2 (NO-GO).
```

CLI **не принимает image override, host, arbitrary URL, command, credentials, network mode или target path**. Docker image должен уже присутствовать локально. Даже при bounded PASS остаются `production_os_policy_verified=false`, `all_native_tools_verified=false`, `mcp_tool_enforcement_verified=false`, `resident_agent_allowed=false`.

## Следующие препятствия

- Нужно независимо аттестовать воспроизводимую сборку, компоненты Python 3.14.7 и remaining 3 CRITICAL, реальную production OS-level isolation, policy enforcement по всем tool backends, MCP/network, provider billing hard-stop, peak burn-in/recovery и отдельный owner GO.
- Скрипт намеренно не доказывает невозможность вызова SSH из низкоуровневого `SSHEnvironment` **минуя** native dispatcher (этот backend реально существует). Ограничение доступа к такому коду требует независимого OS enforcement и проверки реального маршрута будущего agent deployment.
- Документ и verifier являются **repo-only evidence**. На VPS ничего не установлено и не запущено. #199 OPEN, #33 resident NO-GO.
