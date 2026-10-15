# H-03 - проверка исправлений и отзыва научной статьи

[Issue #4](https://github.com/MikeMoore1337/hermes/issues/4). Europe PMC предоставляет [официальный метод `GET /article/{source}/{id}`](https://europepmc.org/RestfulWebService) для получения библиографической записи с `resultType=core`. Для частного исследования **не требуются** регистрация NCBI, API-ключ, банковская карта или платный доступ.

## Проверяемый протокол

```bash
python3 -m research_scout.article_integrity --source MED --id 42771055
# NOT_EXECUTED - безопасный режим без сети

python3 -m research_scout.article_integrity --execute --source MED --id 42771055
# HOLD + CORRECTION_NOTICE для известного примера
```

Команда допускает только `source=MED|PMC` и валидный PMID/PMCID; удалённый адрес **никогда не конструируется из пользовательского домена**. Отправляется один `GET` на `www.ebi.ac.uk:443` через публичный проверенный IP и TLS по имени сервера. Ответ ограничен 48 KiB, таймаут 8 секунд; без redirect, retry, proxy, переходов на статьи издателей, полнотекстовых скачиваний и доступа к закрытым данным. Не изменяет таймер Research Scout и новостной конвейер.

Пример 15.10.2026:

- Europe PMC `/article/MED/42771055?format=json&resultType=core` действительно вернул `hitCount=1`, DOI `10.1007/s00520-026-11251-3` и `commentCorrectionList.commentCorrection` с `type=Erratum in`. Указан корректирующий PMID `42825937`. Официальное опубликованное исправление: [PubMed](https://pubmed.ncbi.nlm.nih.gov/42825937/) и [Springer](https://link.springer.com/article/10.1007/s00520-026-11294-6).
- Проверка `PMC13639859` по `/article/PMC/PMC13639859` вернула `hitCount=1`, `pmcid=PMC13639859`, но без DOI и PMID в данной записи. Это **не доказательство отсутствия DOI**, поскольку [PubMed 42840492](https://pubmed.ncbi.nlm.nih.gov/42840492/) приводит DOI `10.3389/fcimb.2026.1918695`. Пока связь двух систем записи не подтверждена в самом процессе, результат `HOLD`.
- Поле с типом `Erratum in` помечается `CORRECTION_NOTICE`. Ретракции - `RETRACTION_OR_WITHDRAWAL_NOTICE`, выражение обеспокоенности - `EXPRESSION_OF_CONCERN`, незнакомые типы - `OTHER_OR_UNKNOWN_NOTICE`. Любой обнаруженный сигнал означает **HOLD** до проверки первоисточника.
- Если поле `commentCorrectionList` отсутствует, результат `NOT_REPORTED_IN_THIS_METADATA`, а не `no corrections`. Даже при DOI и отсутствии обнаруженного уведомления `MANUAL_REVIEW` не является допуском к публикации или подтверждением научной истинности.

Результат содержит **только фиксированные категории и проверенные идентификаторы**, без заголовка, полного текста, ссылок на произвольные сайты, списка авторов, личных данных, фрагментов статьи или исходного JSON ответа. Обязательные флаги `scientific_claims_verified=false`, `automatic_publication=false`, `authoritative_notice_clearance=false`. Ошибка сети, 429, 404, несовпадение DOI/PMID/PMCID или некорректный JSON дают отказ `UNKNOWN` и никогда не выводят заключение о безопасности.

Это **ручная дополнительная проверка**, не изменяющая ежедневную нагрузку существующей службы. Перед интеграцией в автоматический отчёт отдельно согласовать лимит запросов и проверить, как хранить сведения об исправлениях без ложного статуса «проверено».
