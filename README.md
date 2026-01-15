# Scr-LFI-Protect
Обратный прокси для защиты веб-приложений от атак типа LFI
(Loval File Inclusion) с предотвращением утечек файлов в реальном времени.

## Возможности
- Сканирование URL, форм, JSON запроса на наличие паттернов Path Traversal (`../`, `..\`)
- Анализ имён файлов в `multipart/form-data` (защита от Remote File Inclusion)
- Обнарудение утечек файлов в ответах веб-сервера
- Алгоритм Ахо-Корасик для высокопроизводительного обнаружения утечек
- Удобная конфигурация в YAML-файле и интерфейсе админ-панели
- Админ-панель (в разработке)

## Инструкция по развёртыванию
Скачайте репозиторий:
```
git clone https://github.com/scratcher-402/lfi-protect.git
```
Зайдите в папку репозитория:
```
cd lfi-protect
```
Выполните сборку:
```
go build . -o lfi-protect
```
Создайте конфигурационный файл (см. [Настройка](#Настройка))

**Важно.** Измените пароль, если используете админ-панель. Сгенерировать хеш Bcrypt можно [здесь](https://bcrypt-generator.com/).

Запустите `./lfi-protect` (на Mac, Linux) или `lfi-protect.exe` (на Windows)

## Настройка
### Пример конфигурации
Создайте файл `config.yaml`:
```yaml
proxy:
    listen: ":1545"
    server: "http://localhost:1544"
    max-req-body-size: 16000000
    check-url: true
    check-query: true
    check-filenames: true
    check-json: true
    check-file-leaks: true
    check-all-fields: true
    check-fields: [] # use when check-all-fields is false
files:
    paths:
        - .
    exclude:
        - example/files
        - example/templates
        - example/static
    min-depth: 10
    detect-depth: 32
logs:
    logs-path: logs
admin:
    enabled: true
    listen: ":6767"
    username: "admin"
    password: "$2a$12$tTKc1fh6WU6Q25e0reF8Nufdyoq/iqrjsCD4Cqj1KN/cl52A6AEt2" # "admin"
```
### Опции конфигурации
#### Прокси-сервер
- `proxy.listen` - Адрес, который будет прослушивать прокси.
- `proxy.server` - Адрес целевого веб-приложения для защиты.
- `proxy.max-req-body-size` - Максимальный размер тела запроса (в байтах)
- `proxy.check-url` - Проверять URL запросов (true/false)
- `proxy.check-query` - Проверять Query-параметры и текстовые поля форм запросов (true/false)
- `proxy.check-filenames` - Провеоять имена файлов в формах запросов (true/false)
- `proxy.check-json` - Проверять JSON запросов (true/false)
- `proxy.check-file-leaks` - Проверять тело ответа сервера на наличие утечек (true/false)
- `proxy.check-all-fields` - Проверять все поля в Query, формах, JSON (true/false). Если false, используется список полей из `proxy.check-fields`.
#### Обнаружение утечек
- `files.paths` - Список конфиденциальных файлов и директорий для защиты.
- `files.exclude` - Чёрный список файлов и директорий. Можно использовать паттерны с `*`.
- `files.detect-depth` - Максимальная глубина детектирования.
- `files.min-depth` - Минимальная глубина.
#### Логирование
- `logs.logs-path` - Директория для хранения логов.
#### Админ-панель
- `admin.enabled` - Включена ли админ-панель. (true/false)
- `admin.listen` - Адрес админ-панели.
- `admin.username` - Имя пользователя для входа.
- `admin.password` - пароль для входа, хеширован в bcrypt.
