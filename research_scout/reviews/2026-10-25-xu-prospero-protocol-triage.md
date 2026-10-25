# #317 / I3 — Xu NMA: выборочная сверка PROSPERO и методов (25.10.2026)

**Статус:** `SOURCE_TRIAGE_ONLY / OFFICIAL_RECORD_FULL_HISTORY_NOT_RETRIEVED / P1–P5=HOLD`. Это аналитическая подготовка для независимого эксперта, не квалифицированная рецензия, AMSTAR 2 assessment, авторизация публикации или изменение Research Scout. Экспертные подписи: **0/5**.

## Исходные источники и фактическая глубина

1. **Первичная статья:** Xu et al., *Frontiers in Nutrition* 2026, DOI [10.3389/fnut.2026.1857527](https://doi.org/10.3389/fnut.2026.1857527), [полный HTML издателя](https://www.frontiersin.org/journals/nutrition/articles/10.3389/fnut.2026.1857527/full), § Abstract / Methods, просмотр 25.10.2026. В § Methods авторы называют регистрацию перспективной, указывают поиск до **января 2026**, четыре первичных исхода (DOMS, strength, CK, CRP) на **48 часах**, вторичные 24/72 часа, кроссовер с washout **≥2 недели**, 30 РКИ / 595 человек, общую низкую определённость результата.
2. **Официальный каталог PROSPERO:** [CRD420261340555](https://www.crd.york.ac.uk/PROSPERO/view/CRD420261340555), отдельные текстовые поля официального домена получены только **из поискового индекса** 25.10.2026. Прямая загрузка интерактивной записи вернула JS-оболочку; **полную запись, исходную версию, изменения и приложения непосредственно не прочитали**. В индексированных полях указаны первая отправка и регистрация **15.03.2026**, старт обзора **15.02.2026**, окончание **12.04.2026**, «full protocol has not been written», типы только randomized studies, опубликованные англоязычные исследования, а также ряд полей с маркером `1 change` (intervention/comparator/context). Степень полноты/актуальности этих индексных полей **не установлена**.
3. **Основной plant-food обзор:** Nguyen et al., DOI [10.3390/nu18183049](https://doi.org/10.3390/nu18183049), 36 неоднородных вмешательств. Не считать два обзора независимыми выборками: `TRIAL_OVERLAP=NOT_QUANTIFIED`. Подробнее — [P1–P5 packet](2026-10-25-plant-recovery-independent-review-packet.md) §§8–9.

## Новые вопросы к рецензенту (не установленное нарушение)

| Наблюдение по источнику | Разрешённый вывод | Что проверить по официальному origin |
| --- | --- | --- |
| PROSPERO index: review start 15.02.2026; registration 15.03.2026 | Регистрация **позже заявленной даты начала обзора**. Это требует хронологической проверки, но само по себе не доказывает post-hoc изменение исходов или некорректный метаанализ | Подтвердить текущий и **первый** официальный timestamp, какую работу начали до регистрации, даты финализации search/screening и outcome locking |
| Article: search from inception **to January 2026**; PROSPERO registered March 2026 | **Search cutoff** ≠ обязательно **дата выполнения поиска**. Нельзя по двум датам утверждать, что сам поиск проходил до регистрации | Search logs / Appendix 1 / protocol history с точными execution dates |
| PROSPERO indexed record: «full protocol has not been written»; article: prospectively registered | Регистрационная карточка не равна внешнему детальному protocol/SAP. Несовпадение формулировок требует проверки глубины prespecification | Первая версия полей primary/secondary outcome, comparator, subgroup, crossover criteria, CINeMA, PRISMA-NMA |
| Official index: несколько полей имеют `1 change` | **Изменения существовали**, но индикатор без просмотра revision diff ничего не говорит об их направлении или значимости | Original/current PROSPERO diff, dates, reasons, влияние на inclusion/selection и первичные результаты |
| Article: crossover washout >=2 weeks | Это опубликованный критерий включения, не независимый audit всех 30 originals | Протоколы/таблицы всех включённых crossover: eligibility и нарушения, effect estimates и sensitivity |
| Article: 48h DOMS signal, но сила/CK/CRP без ясной пользы; certainty generally low | Возможный сигнал субъективного исхода, **не** доказанная функциональная польза, дозировка или продуктовая рекомендация | Отдельно оценить RoB2, NMA transitivity/inconsistency, CINeMA, outcome-specific effect и 95% CI, overlap с Nguyen |

## Воспроизводимая следующая приёмка

- Получить документированную копию первой и текущей версии `CRD420261340555` прямо от PROSPERO (с датой, полями, change history); при невозможности сохранить `OFFICIAL_VERSION_NOT_OBSERVED`.
- Сопоставить оригинальные пункты PICO, 48h endpoint, допустимые кроссоверы, search/extraction dates и причины каждого изменения с издательским Methods/Appendix 1; не выводить ложный `PROSPECTIVE_VERIFIED` из наличия номера регистрации.
- Проверить trial IDs и пересечение с 36 originals Nguyen; независимую RoB 2 и полноценный AMSTAR 2 поручить специалисту. Никаких `PASS` по поисковому индексу.
- Оценить точный образовательный claim только после экспертного заключения и отдельного YFC editorial/owner gate.

**Выход:** `P1/P2/P3/P4/P5=HOLD`, `EXPERT_SIGNOFF=0/5`, `YFC_REQUEST_PAYLOAD=null`, `PUBLICATION_ALLOWED=false`. Не были вызваны external APIs с персональными данными, редакционный POST, платные модели или BRC.
