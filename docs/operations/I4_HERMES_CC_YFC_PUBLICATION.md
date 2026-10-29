# I4 — статьи YFC в Hermes Control Center: эксплуатация и границы публикации

**Дата актуализации:** 29.10.2026. **Принцип владельца:** автоматизировать Research Scout → научно-осторожный **draft** → YFC Root review; само опубликование только отдельным явным действием владельца. Связанные задачи: [Hermes #599](https://github.com/MikeMoore1337/hermes/issues/599), [#601](https://github.com/MikeMoore1337/hermes/issues/601), [YFC #1226](https://github.com/MikeMoore1337/your-fitness-coach/issues/1226).

## Реальное состояние и доказательства

- Исходная статья о лёгких/тяжёлых весах сохранена в Hermes как операторский кандидат, два оригинальных текста защищены SHA-256; **пять тезисов всё ещё `pending`**. Отсутствие независимой научной аттестации и абсолютного publisher notice clearance не скрывается.
- Owner VPS подготовил защищённый `i4-reviewed-content.json`, `PENDING_EDITORIAL_REVIEW`, затем локальный `READY_NOT_SUBMITTED`; packet SHA256: `d56a63617f50738d9bb60961bf4ab4163176c1f6f2ccaafdc55a0a92c6d3c93e`.
- Реальный YFC backend принял один HMAC draft-only intake с существующим HMAC из собственной среды, **не** переносив shared secret на Hermes и не открывая root-to-root SSH. Ответ: `ACCEPTED_DRAFT_ONLY`, статья `510276353c157f60ab5cb87ce9b2e336`, version `1`, `publisher_invoked=false`, `public_url=null`.
- Оператор выполнил отрицательный запрос к публичному YFC API по slug `legkie-i-tyazhelye-vesa-gipertrofiya-sila`: `HTTP 404`.
- Владелец 29.10.2026 показал реальный production Hermes Control Center: очередь из одного черновика, связанная Root YFC сессия, заголовок, шесть разделов, тексты исследований, источники и пять тезисов. **Это visual/read-only E2E, не подтверждение публикации.** Полную побайтовую сверку 15 абзацев и реальный Root publish audit отдельно не проводили.
- Уточнение: исходное поле матрицы YFC — **`source_ids: string[]`**, а не `source_id`. PR #656 исправляет рендеринг всех источников и запрещает публикационные действия при повреждённой/неполной матрице. Release status PR проверяется отдельно; не считать код доставленным до CI и production SHA.

## Текущая архитектура безопасности

1. Hermes Research Scout может готовить и HMAC-отправлять **только** статью со статусом `draft` в существующий `POST /api/v1/hermes/articles/intake`. У Research Scout нет Root Telegram identity и публикационных полномочий. Подготовка по source metadata не является scientific signoff.
2. Hermes Control Center требует собственную GitHub OAuth owner-сессию. UI `control_center/frontend/src/YfcArticles.jsx` открывает отдельное окно `https://app.your-fitness-coach.ru/admin/hermes-bridge` через `control_center/frontend/src/yfc-browser-bridge.js`. Consent исходит из действующей **независимой Root-сессии YFC**. Root bearer не отправляется в браузер Hermes и не хранится в его БД/cookies/localStorage.
3. Read-only действия списка и полного текста возвращают `article_id`, `content_hash`, `content_version`, все `body_sections`, `claims`, `sources`, `claim_source_matrix`, `review_blockers` и provenance. Публикационная кнопка должна быть недоступна при неполном тексте, чужом ID/хеше/версии или нарушенной матрице ссылок. Передача данных браузеру допускает только безопасный текст/HTTPS URL.
4. Публикация не начинается при выборе статьи. Владелец отдельно открывает confirmation modal с точной версией и SHA-256, ставит чекбокс о прочтении и неопределённости доказательств, затем подтверждает публикацию ещё **в YFC Root окне**. Сервис YFC строго проверяет `article_id`, `expected_content_hash`, `expected_content_version`, `confirm_exact_revision=true`, `acknowledge_unverified_evidence=true`; изменение редакции должно дать 409, а не неявную публикацию. Только YFC Root выполняет переход в `published` и пишет actor audit.
5. Нельзя использовать Hermes OAuth, HMAC, worker, CI, BRC, systemd timer или модель для имитации владельца, бесконтрольного POST в Root endpoint либо обхода Root consent. Никаких платных API. Secrets не выводятся в логи, chat, артефакты или репозитории.

## Приёмка и остаток

| Gate | Состояние |
|---|---|
| Подготовленный текст + точный source packet hash | PASS, подтверждённый owner VPS |
| HMAC `draft` intake + real article ID/version | PASS |
| Публичный API возвращает 404 до Root публикации | PASS |
| Root read-only link + production Control Center очередь / полный текст | PASS (owner screenshot, не byte-for-byte) |
| Матрица `source_ids` без undefined / foreign source fail-closed | **PASS**, PR #656 merged и production CD PASS, подтверждено в [#601](https://github.com/MikeMoore1337/hermes/issues/601) |
| Синтетические negative / owner double-confirm E2E | **PASS**, CI и UI E2E зафиксированы в [#601](https://github.com/MikeMoore1337/hermes/issues/601); реальную публикацию не доказывают |
| Настоящая ручная Root публикация exact revision + audit receipt | **NOT_TESTED**, ожидает отдельного желания владельца публиковать |

**Правило завершения (решение владельца от 29.10.2026):** #599 и #601 **CLOSED / COMPLETED** по документированной приёмке owner-reviewed draft-only pipeline и Root UI. Добровольная публикация конкретной статьи **не является** обязательным тестом для закрытия #601; действительная Root-квитанция появляется только при последующем собственном решении владельца. #317: отдельная научная экспертиза прекращена владельцем из-за недоступности независимого рецензента, **CLOSED / NOT_PLANNED**, а не `SCIENTIFIC_VERIFIED`. Все поля `pending/unclear` остаются таковыми, Root принимает отдельное редакционное решение по каждому материалу. Автоматического выпуска, моделируемых Root-квитанций и обхода прав нет.

**NO-GO:** повторная отправка после неопределённого исхода; подмена экспертной подписи; публикация по HMAC; распространение секретов между VPS; автоматический таймер выпуска.
