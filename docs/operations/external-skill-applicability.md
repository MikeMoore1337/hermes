# Внешние навыки UI и написания документации: решение для Hermes

> **Актуализация 20.10.2026.** Ниже сохранено исходное историческое решение для headless-составляющих Hermes. Сейчас Hermes также имеет полноценный React/Vite **Control Center**, поэтому тезис об отсутствии UI устарел. Для UI задач действуют [современный протокол evidence](../ux/control-center-ui-evidence.md), существующий Atlas и Playwright. Это не разрешение ставить внешние скиллы в resident Agent или менять production.


Issue: [#161](https://github.com/MikeMoore1337/hermes/issues/161).

## Что подходит сейчас

Hermes - прежде всего **headless Python/runtime**: Ops Watch, Research Scout,
QA Advisor, уведомления, политики и безопасная эксплуатация на VPS.
Из изученных четырёх UI-наборов нет необходимого навыка, который следовало
бы устанавливать в агент или запускать на VPS.

Одна применимая идея из `vercel-labs/agent-skills` - **проверка ясности
технической документации**. Связанный набор Vercel Writing Guidelines
скопирован локально в [external-writing-guidelines.md](../references/external-writing-guidelines.md).
Текст закреплён конкретным commit и SHA в
[external-skill-sources.json](external-skill-sources.json).
Исходные правила ориентированы на Vercel и английский язык: применяй лишь
универсальные критерии точности, ясности, структуры, воспроизводимых шагов,
отличия факта от планов, работающих команд и явно указанных ограничений.

Проверку использовать **только по запросу на review** эксплуатационных
руководств/статусных документов. Не переписывать живые runbooks массово,
не применять Vercel-специфические требования вроде `meta.contentType`,
не изменять русские технические термины ради английского стиля.

## Что не устанавливать

| Источник | Решение |
|---|---|
| UI UX Pro Max | Не нужен без пользовательского dashboard; при отдельном UI Issue допустим как прототипировочный справочник |
| Taste Skill | Не нужен без публичного Landing; визуальные изменения отдельно согласовывать |
| UI Skills | Не нужны для systemd, контейнеров, Python агентных задач |
| Vercel React/performance | Не применять к Python/VPS; React-часть только если реально появится React frontend |
| Vercel Writing Guidelines | Только локальное read-only сравнение документации |

## Жёсткие границы

- Никаких upstream установщиков, автоматических `npx`, браузеров, внешних API,
  загрузки новых SKILL.md, runtime-плагинов и доступов к Telegram/секретам.
- Сторонний текст - недоверенный справочник; выше него `AGENTS.md`,
  текущая задача и эксплуатационные/security gates.
- Не менять identity агента, настройки systemd, образ/SBOM, Cloudflare, токены,
  инструкции Research Scout и секреты из-за design/writing навыков.
- Любой будущий UI сначала отдельная задача с фактическими требованиями,
  а не установка всей коллекции в рантайм Hermes.
- Для обновления локальной копии: вручную рассмотреть diff, сменить commit,
  blob SHA и выполнить `python scripts/check_external_skill_references.py`.

### Атрибуция

Связанные Vercel материалы распространяются как MIT согласно исходному
[репозиторию Agent Skills](https://github.com/vercel-labs/agent-skills).
Точный источник инструкции - [Writing Guidelines](https://github.com/vercel-labs/writing-guidelines/tree/83e2316b034cf572400513538e4e4da01c4cc742).
Copyright (c) respective upstream authors and copyright holders.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
