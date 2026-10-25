# Hermes Commander #454 — изолированные рабочие ветки для параллельных задач

## Назначение

Использовать уже подключённый Hermes MCP и существующие публичные
sandbox-клоны, не создавая ещё одно подключение, агент, OAuth или UI.
Каждая задача получает собственный Git worktree. ChatGPT и Codex могут
редактировать разные каталоги и коммитить разные ветки без конфликта
одной рабочей копии. Это **не доступ к оригинальным Windows-папкам**
или production VPS checkout.

В рабочем Windows sandbox доступны Git 2.39, Python 3.11 и Node 24.
Репозитории: `hermes`, `your-fitness-coach`, `second-brain`
(только публичный код), `ai-development-toolkit`.
VPS sandbox пока не имеют Git/Python и **не подходят для этого скрипта**.

## Маршрутизация задачи агентом (пользователь не вводит команды)

1. Вызвать `list_workspaces` и `resolve_workspace(project="YFC")`
   через установленный Hermes MCP. Использовать только актуальный ID
   `H15 Windows permanent sandbox` и root
   `/workspace/projects/your-fitness-coach`.
2. Для ещё не начатой задачи вызвать `start_process` **на этом sandbox**
   с ограниченной командой:

   ```sh
   python3 -B /workspace/commander-tools/task_worktree.py \
      --project yfc --task 1206 --slug postgresql --prepare --sync
   ```

   ID и короткий slug выбираются по утверждённой GitHub Issue;
   никаких произвольных shell-фрагментов из названия задачи.
   `--sync` только для нового worktree: Git fetch из строго
   проверенного `https://github.com/MikeMoore1337/<repo>.git`
   и только `refs/heads/main` либо `master`.
3. Разобрать JSON-ответ: `status=created|reused`,
   `root`, `branch`, `head`, `basis`, `scope=sandbox`.
   Использовать возвращённый каталог для дальнейших файловых
   операций и запуска тестов, **не исходный main/master**.
4. При `status=refused` прекратить изменения, не подбирать
   произвольный путь и не делать `reset --hard`, `clean` или
   принудительное удаление ветки.
5. После изменений проверить локальный diff/status, выполнить
   подходящие тесты и доставить PR через штатный GitHub Flow.
   Не обещать, что Git remote push настроен: если credentials
   отсутствуют, использовать разрешённый GitHub connector.
   Не трогать чужие worktree, приватный vault и хостовые корни.

Скрипт сначала проверяет каталог, Git origin, default branch и HEAD.
Новый worktree из локального checkout **может быть устаревшим**;
для актуальной задачи нужен `--sync`. Это меняет только локальную
Git object database / remote refs; **основная рабочая ветка и tracked
файлы исходного клона остаются неизменными**. При повторном запросе
существующий worktree возвращается без Git fetch, сброса файлов
или изменения незавершённой работы. Никакой автоматической уборки.

## Один раз установить на уже разрешённый sandbox

Исходник `scripts/h454_task_worktree.py` необходимо установить
как `/workspace/commander-tools/task_worktree.py` через существующий
Hermes BRC процесс, только после сверки GitHub blob SHA с утверждённым
релизным SHA. Путь находится в существующем разрешённом
`/workspace` bind; не требует новых Docker mounts и host shell.

Git clone нельзя обновлять бездумным `reset`: при необходимости
`--sync` загружает разрешённый remote branch, оставляя default
checkout как есть. Для каждого репозитория независимая задача
получает `/workspace/task-worktrees/<repo>/issue<ID>-<slug>`.

## Доказательства и ограничения

- 2026-10-25: реальный Windows sandbox сделал disposable Git worktree
  `work/454-parallel`, обе ветки сохранены, затем только тестовые
  каталоги удалены — PASS.
- Реальный `/workspace/projects/hermes` выдал рабочий
  `work/issue454-commander-parity` из локального HEAD, затем
  повтор `--prepare` вернул `reused` без изменений — PASS.
- `git ls-remote` и bounded `git fetch --depth=1` с
  `pack.threads=1` получили настоящий origin/main SHA без изменения
  основного checkout — PASS.
- Без отдельного runtime image обе VPS sandbox пока Node-only:
  установленность Git/Python там не утверждается.
- Изменение relay, onboarding нового устройства, reboot Windows,
  доступ к native Windows и привилегиям VPS **не входит** в эту поставку.

Тесты: `python3 -B -m unittest -v tests.test_h454_task_worktree`.
Никаких платных API, Codex CLI, Claude CLI, модели или новых secrets.
