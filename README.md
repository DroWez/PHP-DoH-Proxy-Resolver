# 🚀 PHP DoH Proxy Resolver

Лёгкий, быстрый и гибкий **DNS-over-HTTPS (DoH) прокси-резолвер на PHP**  
Работает на обычном shared-хостинге без Docker и без root-доступа.

---

## 📌 Возможности

- 🔁 Domain Routing (разные upstream для разных доменов)
- 🧠 DNS Override (жёсткая подмена IP)
- ⚡ Параллельные запросы через `curl_multi`
- 🗂 Кэширование через APCu
- 🌐 Поддержка GET и POST (RFC 8484)
- 🚀 Failover между upstream-серверами

---

## 🌍 Используемые upstream (по умолчанию)

- :contentReference[oaicite:0]{index=0}  
- :contentReference[oaicite:1]{index=1}  

Вы можете добавить любые DoH-серверы в конфигурацию.

---

## ⚙ Архитектура

```
Client
   ↓
PHP DoH Proxy
   ↓
Routing / Override / Cache
   ↓
Multi-Upstream (parallel)
   ↓
Fastest valid response
```

---

## 🧩 Конфигурация

### 🔹 Общий пул upstream

```php
$default_upstreams = [
    "https://dns.quad9.net/dns-query",
    "https://dns10.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query"
];
```

---

### 🔹 Domain Routing

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

### 🔹 DNS Override

Жёсткая подмена IP без обращения к upstream:

```php
$dns_overrides = [
    "example.com" => "1.2.3.4"
];
```

---

### 🔹 Кэширование

```php
$cache_ttl = 600; // секунды
```

Если APCu включён — ответы кэшируются автоматически.

---

## 🌐 Использование

### POST (RFC 8484)

```
POST /dns-query.php
Content-Type: application/dns-message
```

Тело запроса — бинарный DNS-пакет.

---

### GET

```
GET /dns-query.php?dns=BASE64URL
```

Поддерживается Base64URL-кодировка.

---

## 📦 Установка

1. Загрузить PHP-файл на хостинг
2. Убедиться, что включены:
   - `curl`
   - `apcu` (необязательно)
3. Готово ✅

Никаких дополнительных зависимостей.

---

## 🛡 Подходит для

- собственного DoH сервера
- обхода блокировок
- кастомной маршрутизации DNS
- интеграции с DNS/Proxy клиентами
- использования в связке с прокси-инфраструктурой

---

## 🚀 Преимущества

- Работает без Docker
- Подходит для shared-хостинга
- Не требует root-доступа
- Минимальная конфигурация
- Лёгкая масштабируемость
- Производственный уровень отказоустойчивости

---

## 📜 Лицензия

MIT — свободное использование и модификация.
