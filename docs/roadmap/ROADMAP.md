# Дорожная карта Hermes

**Статус:** H-00 завершён (PR #9); H-01 имеет [проект безопасного runtime](../architecture/H-01-runtime-plan.md), но запуск заблокирован до отдельного решения владельца. Создание репозитория не активирует этапы и не заменяет owner-approval. Один GitHub Issue на независимую задачу; ссылки на реальные Issues ниже.

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
