# 🚀 PHP DoH Proxy Resolver

Лёгкий, быстрый и гибкий **DNS-over-HTTPS (DoH) прокси-резолвер на PHP**.

Работает на обычном **shared-хостинге** без Docker и без root-доступа.

---

# 📌 Возможности

- 🔁 **Domain Routing** — разные upstream DNS для разных доменов  
- 🧠 **DNS Override** — жёсткая подмена IP  
- 🛡 **AdGuard / Adblock фильтрация** — блокировка рекламы и трекеров  
- ⚡ **Параллельные DNS запросы** через `curl_multi`  
- 🗂 **DNS кеширование** через APCu  
- 🌐 **Поддержка GET и POST** (RFC 8484)  
- 🚀 **Failover между upstream DNS  
- 📦 **Поддержка blocklists (AdGuard / hosts)**

---

# 🌍 Используемые upstream (по умолчанию)

```
https://dns.quad9.net/dns-query
https://dns10.quad9.net/dns-query
https://dns.adguard-dns.com/dns-query
```

Вы можете добавить **любые DoH серверы**.

---

# ⚙ Архитектура

```
Client
   ↓
PHP DoH Proxy
   ↓
Adblock Filter
   ↓
DNS Override
   ↓
Domain Routing
   ↓
Cache
   ↓
Multi-Upstream (parallel)
   ↓
Fastest valid response
```

---

# 🧩 Конфигурация

---

## 🔹 Общий пул upstream

```php
$default_upstreams = [
    "https://dns.quad9.net/dns-query",
    "https://dns10.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query"
];
```

---

## 🔹 Domain Routing

Маршрутизация конкретных доменов через определённые DNS:

```php
$domain_upstreams = [
    "google.com" => [
        "https://8.8.4.4/dns-query"
    ],
    "cloudflare.com" => [
        "https://1.0.0.1/dns-query"
    ],
];
```

Поддерживаются:

- точные совпадения
- поддомены (`api.google.com`)
- зоны (`.google.com`)

---

## 🔹 DNS Override

Жёсткая подмена IP без обращения к upstream:

```php
$dns_overrides = [
    "example.com" => "1.2.3.4"
];
```

---

# 🛡 Фильтрация доменов (AdGuard / Adblock)

Резолвер поддерживает **DNS-блокировку рекламы и трекеров** через фильтры.

Поддерживаются форматы:

- `||domain^`
- `0.0.0.0 domain`
- `127.0.0.1 domain`
- обычные домены

Если домен найден в фильтре — DNS вернёт:

```
0.0.0.0
```

---

## 🔹 Подключение фильтров

```php
$filter_lists = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt"
];
```

Можно подключить **любое количество списков**.
списки можно посметреть тут https://github.com/ppfeufer/adguard-filter-list
или создать свои )) 

Скрипт автоматически:

1. скачивает списки
2. объединяет домены
3. сохраняет кеш

---

## 🔹 Кэш фильтров

Чтобы не скачивать списки при каждом DNS-запросе используется кеш.

```php
$filter_cache_ttl = 3600;
```

После истечения времени фильтры автоматически обновляются.

Кеш хранится в файле:

```
filters.cache
```

---

# 🔹 DNS кеширование

```php
$cache_ttl = 600;
```

```
600 секунд = 10 минут
```

Если **APCu включён**, ответы DNS автоматически кешируются.

---

# 🌐 Использование

## POST (RFC 8484)

```
POST /dns-query.php
Content-Type: application/dns-message
```

Тело запроса — бинарный DNS-пакет.

---

## GET

```
GET /dns-query.php?dns=BASE64URL
```

Поддерживается **Base64URL-кодировка**.

---

# 📦 Установка

1. Загрузить PHP файл на хостинг
2. Убедиться, что включены:

```
curl
apcu (необязательно)
```

3. Готово ✅

Никаких дополнительных зависимостей.

---

# 🛡 Подходит для

- собственного DoH сервера
- обхода DNS-блокировок
- кастомной маршрутизации DNS
- блокировки рекламы
- интеграции с DNS / Proxy клиентами
- использования в прокси-инфраструктуре

---

# 📊 Порядок обработки DNS

```
1. Adblock Filter
2. DNS Override
3. Domain Routing
4. Cache
5. Upstream DNS
```

Это позволяет:

- блокировать домены **до обращения к upstream**
- экономить DNS запросы
- ускорять работу резолвера

---

# ⚡ Производительность

Даже при использовании **100 000+ доменов фильтрации**:

- поиск выполняется мгновенно
- кеш снижает нагрузку
- upstream DNS опрашиваются параллельно

---

# 🚀 Преимущества

- работает без Docker
- подходит для shared-hosting
- не требует root-доступа
- минимальная конфигурация
- легко масштабируется
- отказоустойчивый

---

# 📜 Лицензия

MIT License — свободное использование и модификация.
