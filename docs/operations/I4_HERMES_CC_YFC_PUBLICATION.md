# I4 — публикация статей YFC из Hermes Control Center

**Decision:** владелец выбрал Hermes Control Center для просмотра и ручной публикации статей YFC (25.10.2026). Задачи: [Hermes #601](https://github.com/MikeMoore1337/hermes/issues/601), [Hermes #599](https://github.com/MikeMoore1337/hermes/issues/599), [YFC #1226](https://github.com/MikeMoore1337/your-fitness-coach/issues/1226).

## Границы прав

- Hermes Research Scout автономно собирает сведения, проверяет источники, может готовить черновик и передавать **только draft** в существующий HMAC YFC intake.
- Hermes Control Center использует **GitHub OAuth owner authentication**. Это **не** равно YFC Root Telegram identity.
- YFC `require_root_admin` принимает решение о реальном `draft → published`. Никакие Hermes HMAC, GitHub-owner cookie, агент, модель, workflow или systemd timer не становятся публикационными полномочиями.
- Точный запрос на стороне YFC (PR #1233): `POST /api/v1/admin/articles/drafts/publish` требует YFC Root bearer, **article_id + content_hash + content_version**, `confirm_exact_revision=true` и `acknowledge_unverified_evidence=true`. Сменился контент — 409, не публикация. Успех оставляет `scientific_verification=not_attested`, сохраняет pending матрицу и audit владельца.

## Реализация первой части

`control_center.yfc_editorial` содержит **изолированный stateless transport**:
- `list_drafts(root_token, limit, offset)` — ограниченный GET списка.
- `get_draft(root_token, article_id)` — точная матрица источников и предупреждения.
- `publish_existing_draft(root_token, article_id, content_hash, content_version, owner_confirmed=True)` — только явный запрос с двумя признаками согласия; без owner_confirmed нет сети.
- Все обращения pinned на `https://app.your-fitness-coach.ru`; никаких произвольных адресов, redirect, persistent bearer store, env credentials, logging секретов, фоновых операций или платных API. Ошибки от YFC становятся fixed error codes, тело ошибки сервера не выводится.

**ВНИМАНИЕ:** транспортный модуль существует **без HTTP routes, without CC UI action, without a live operator feature**. Нельзя считать этот PR разрешением публикации через интерфейс. Ему нужны отдельные защиты Hermes OAuth + Origin/CSRF, пользовательский ввод transient YFC token, визуально принятый экран и независимый e2e.

## Визуальная приёмка

Макет с графитовой/синей палитрой и тремя состояниями (очередь → черновик/источники → явное подтверждение) подготовлен вне production как HTML. Нельзя изменять текущую CC navigation/JS/CSS до отдельного visual APPROVE владельца. Состояние MVP без более сложного pair-flow: владелец вводит краткоживущий Root токен в защищённой Hermes сессии **в памяти только на конкретную операцию**, с сетевым POST через Hermes server и немедленным уничтожением после запроса. Токен никогда не хранить в localStorage/sessionStorage, БД, cookie, логах, URL или файловом vault.

В перспективе можно заменить ручной ввод на отдельную consent-based cross-app PKCE/delegated authorization, но только с двусторонней явной привязкой GitHub-owner и Root Telegram identity, без service-level publish secret и без автоматизации публикаций. Это НЕ реализовано данным PR.

### Условия открытия Hermes POST

1. Owner approves visual states; Review never automatically publishes.
2. Only GitHub OAuth mode and authenticated owner session; reject proxy/preview.
3. Strict Origin/CSRF and Content-Type/size/rate bound; never token in URL/log.
4. Pinned YFC egress without redirect/SSRF, no retry of unsafe POST, exact revision checks.
5. HTTP tests for 401/403, CSRF, missing token, wrong Root, version conflicts, rate limits, idempotent user replay, and audit receipt.
6. Production deployment to CC with exact SHA and manual owner E2E proof; YFC public URL only after real authenticated owner click.

**NO-GO:** любые плановые публикации, скрытая кнопка publish в автоматическом процессе, поддельный reviewer, внешние платные LLM, работу через Hermes BRC в данном чате.
