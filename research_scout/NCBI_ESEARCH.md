# H-03: NCBI ESearch - идентификаторы кандидатов

Частичная реализация Issue #4, без автоматических запусков.
Вызов вручную: python3 -m research_scout.ncbi_esearch --topic resistance-training

Предусмотрены только три фиксированные темы: resistance-training, muscle-hypertrophy, exercise-recovery.
Один запрос HTTPS к eutils.ncbi.nlm.nih.gov с TLS, фиксированным адресом после проверки DNS, без перенаправлений и повторов.
Выборка не более 5 PMID за последние 30 дней с datetype=edat. Это дата добавления/обновления записи Entrez, не подтверждённая дата публикации.
Вывод UNVERIFIED_PMID_CANDIDATES / NO_DATA / UNKNOWN не является научной рекомендацией.

Перед запросом проверяется непустой реальный HERMES_NCBI_CONTACT_EMAIL. Контактный адрес не печатается и не коммитится.
На VPS на момент разработки контакт не настроен. Нет разрешения запускать фиктивный адрес.
Ключ NCBI, модель AI, платный API, публикация, очередь и запись в YFC/Second Brain не используются.

Согласно NCBI, без API-ключа не более 3 E-utilities запросов/сек на IP, tool и email идентифицируют разработчика.
Здесь реализован один ручной запрос. Прежде чем включать расписание, нужен отдельный лимит для всего VPS, а не только процесса.
Документация: https://www.ncbi.nlm.nih.gov/books/NBK25499/ и https://www.ncbi.nlm.nih.gov/books/NBK25497/.
