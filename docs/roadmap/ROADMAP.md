# Дорожная карта Hermes

**Сверено 14.10.2026:** на VPS активны новостной Hermes, локальный Ops Watch и служба сетевой защиты; постоянный Hermes Agent и облачный прокси отключены. Защищённый CLI выполнил реальные ограниченные запросы к Cloudflare Free и инструменту todo_list. Сквозная автономная эксплуатация ещё не подтверждена.

**H-02:** локальный Ops Watch хранит инциденты в SQLite и формирует безопасные тексты. [PR #48](https://github.com/MikeMoore1337/hermes/pull/48) добавил резервирование и подтверждение событий, [PR #51](https://github.com/MikeMoore1337/hermes/pull/51) подготовил явно включаемую отправку владельцу, [PR #58](https://github.com/MikeMoore1337/hermes/pull/58) усилил проверку получателя. Реальная отправка **не включена** и не доказана.

**H-03:** модули NCBI ESummary, ESearch и ручной проверки имеются в main (PR #50, #56, #57). Без контактного адреса HERMES_NCBI_CONTACT_EMAIL реальных запросов нет. Попытка скопировать новые ESearch/Review на VPS отклонена внешним контрольным механизмом, поэтому подтверждения установки нет. **Не путать код в main с установленной службой.**

**H-04:** offline-анализ CI реализован. [PR #39](https://github.com/MikeMoore1337/hermes/pull/39) на чтение публичных GitHub Actions остаётся открытым из-за ограничения на объединение. Вторым PR или альтернативным маршрутом запрет не обходить.

**Границы:** Next H-01 [#33](https://github.com/MikeMoore1337/hermes/issues/33) - происхождение исходников образа, безопасность и проверка перезагрузки/нагрузки; H-02 [#3](https://github.com/MikeMoore1337/hermes/issues/3) - согласованный Telegram-адресат и сквозная доставка; H-03 [#4](https://github.com/MikeMoore1337/hermes/issues/4) - контакт разработчика NCBI, реальный ESearch/ESummary, ограничения общего IP, ручная проверка научных выводов. H-05 Second Brain остаётся заблокированным до проверки v4 и отдельного GO.

**Итоговые технические доказательства:** [сверка фактов и блокировок](../status/HERMES-CURRENT-2026-10-14.md). Программу новостей YFC и режим платных API не изменять.

| Код | Приоритет | Этап | Зависимость/условие |
|---|---|---|---|
| [H-00 #1](https://github.com/MikeMoore1337/hermes/issues/1) | P0 | Read-only аудит runtime, хостов и ownership | Стартовая |
| [H-01 #2](https://github.com/MikeMoore1337/hermes/issues/2) | P1 | Самостоятельный Hermes Agent (минимальный профиль/изоляция) | H-00 + owner GO на runtime/provider |
| [H-02 #3](https://github.com/MikeMoore1337/hermes/issues/3) | P1 | Ops Watch: мониторинг инфраструктуры и алерты | H-01 |
| [H-03 #4](https://github.com/MikeMoore1337/hermes/issues/4) | P1 | Research Scout: проверяемое исследование | H-01 + стандарт выбора интеграций |
| [H-04 #5](https://github.com/MikeMoore1337/hermes/issues/5) | P2 | QA Advisor: GitHub/CI аналитика в read-only | H-01, H-02 и scoped auth |
| [H-05 #6](https://github.com/MikeMoore1337/hermes/issues/6) | P2 | Second Brain bridge: поиск знаний через read-only API | завершение Second Brain #386 + owner GO + H-01 |
| H-06 | P2 | YFC Growth Operator | **существующий YFC #322**, зависит от #320; не дублировать |
| [H-07 #8](https://github.com/MikeMoore1337/hermes/issues/8) | P3 | Видео, Coach OS, Hermes Desktop usability | Только после обоснования, оценки лицензий/стоимости и owner GO |
| [M-01 #7](https://github.com/MikeMoore1337/hermes/issues/7) | P2 | Перенос news worker/discovery в hermes (если оправдано) | H-00 + новый контракт ownership + shadow + отдельный cutover GO |

## Существующие блокировки

- [Second Brain #386](https://github.com/MikeMoore1337/second-brain/issues/386): v4 burn-in. Запрещена скрытая write-интеграция, новые поставщики, широкие права и прямой доступ к vault.
- [YFC #320](https://github.com/MikeMoore1337/your-fitness-coach/issues/320) -> [YFC #322](https://github.com/MikeMoore1337/your-fitness-coach/issues/322): SEO evidence gate. Нет оснований запускать H-06 здесь.
- YFC dedicated Hermes production services нельзя менять для H-01 без подтверждённых ресурсов и отдельного owner approval.
- Выбор режима платных API и ключей не делается без конкретного разрешения.

## Волны

0. H-00 + реестр прав/контрактов + bootstrap CI без runtime.
1. H-01 после формального решения по H-00, затем H-02 и H-03.
2. H-04, а H-05 - только после Second Brain gate.
3. H-06 через YFC backlog, H-07 и M-01 по отдельной доказанной необходимости.

## Definition of Done

Конкретные acceptance cases, тесты, негативные проверки прав, источник истины, ссылки на Issue/PR/CI; отдельная запись «не развернуто» до подтверждённого runtime. Никаких автоматических переходов между волнами.
