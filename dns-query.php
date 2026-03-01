<?php

/*
=====================================
ОБЩИЙ ПУЛ UPSTREAM
=====================================
*/
$default_upstreams = [
    "https://dns.quad9.net/dns-query",
    "https://dns10.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query"
];

/*
=====================================
DOMAIN ROUTING (через какой upstream)
ключ — домен или зона
значение — массив upstream
=====================================
*/
$domain_upstreams = [
    "google.com" => [
        "https://8.8.4.4/dns-query"
    ],
    "cloudflare.com" => [
        "https://1.0.0.1/dns-query"
    ],
    "example.org" => [
        "https://unfiltered.adguard-dns.com/dns-query"
    ],
];

/*
=====================================
DNS OVERRIDE (жёсткая перезапись IP)
=====================================
*/
$dns_overrides = [
    "example.com" => "1.2.3.4"
];

$cache_ttl = 600;
$batch_size = 3;

/* ============================= */

function now_ms() {
    return (int) round(microtime(true) * 1000);
}

function error_json($code, $message) {
    http_response_code($code);
    header("Content-Type: application/json");
    echo json_encode([
        "error" => [
            "timestamp" => now_ms(),
            "code" => $code,
            "message" => $message,
        ],
    ]);
    exit();
}

/*
=====================================
ПАРСИНГ ДОМЕНА ИЗ DNS ЗАПРОСА
=====================================
*/
function parse_dns_query_domain($data) {
    if (strlen($data) < 12) return null;

    $offset = 12;
    $labels = [];

    while ($offset < strlen($data)) {
        $l = ord($data[$offset]);
        if ($l === 0) break;
        $offset++;
        $labels[] = substr($data, $offset, $l);
        $offset += $l;
    }

    return strtolower(implode(".", $labels));
}

/*
=====================================
ПОИСК UPSTREAM ДЛЯ ДОМЕНА
работает и для поддоменов
=====================================
*/
function match_domain_upstreams($domain, $domain_upstreams) {
    foreach ($domain_upstreams as $zone => $ups) {
        if ($domain === $zone || str_ends_with($domain, "." . $zone)) {
            return $ups;
        }
    }
    return null;
}

/*
=====================================
СБОРКА DNS ОТВЕТА (A)
=====================================
*/
function build_dns_response($query, $ip) {
    $id = substr($query, 0, 2);

    $header =
        $id .
        "\x81\x80" . // flags
        "\x00\x01" . // qdcount
        "\x00\x01" . // ancount
        "\x00\x00" .
        "\x00\x00";

    $question = substr($query, 12);

    $answer =
        "\xc0\x0c" .
        "\x00\x01" .
        "\x00\x01" .
        pack("N", 60) .
        "\x00\x04" .
        inet_pton($ip);

    return $header . $question . $answer;
}

/*
=====================================
ПОЛУЧЕНИЕ ТЕЛА ЗАПРОСА
=====================================
*/
$method = $_SERVER["REQUEST_METHOD"] ?? "POST";

if ($method === "GET") {
    if (empty($_GET['dns'])) {
        error_json(400, "GET must include dns param");
    }
    $body = base64_decode(strtr($_GET['dns'], '-_', '+/'));
} else {
    $body = file_get_contents("php://input");
}

if (!$body) {
    error_json(400, "Empty DNS query");
}

/*
=====================================
ПАРСИМ ДОМЕН
=====================================
*/
$domain = parse_dns_query_domain($body);

/*
=====================================
1. OVERRIDE
=====================================
*/
if ($domain && isset($dns_overrides[$domain])) {
    header("Content-Type: application/dns-message");
    echo build_dns_response($body, $dns_overrides[$domain]);
    exit();
}

/*
=====================================
2. DOMAIN ROUTING
=====================================
*/
$upstreams = match_domain_upstreams($domain, $domain_upstreams);

if (!$upstreams) {
    $upstreams = $default_upstreams;
}

/*
=====================================
КЕШ
=====================================
*/
$cache_key = "doh_" . md5($domain . ":" . $body);

if (function_exists("apcu_fetch")) {
    $cached = apcu_fetch($cache_key);
    if ($cached !== false) {
        header("Content-Type: application/dns-message");
        echo $cached;
        exit();
    }
}

/*
=====================================
MULTI CURL
=====================================
*/
shuffle($upstreams);

$mh = curl_multi_init();
$chs = [];

foreach ($upstreams as $up) {
    $ch = curl_init($up);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            "Content-Type: application/dns-message",
            "Accept: application/dns-message",
        ],
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_TIMEOUT => 4,
    ]);
    curl_multi_add_handle($mh, $ch);
    $chs[] = $ch;
}

$running = null;
do {
    curl_multi_exec($mh, $running);
    curl_multi_select($mh);

    while ($info = curl_multi_info_read($mh)) {
        $ch = $info['handle'];
        if ($info['result'] === CURLE_OK &&
            curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) {

            $resp = curl_multi_getcontent($ch);

            if (function_exists("apcu_store")) {
                apcu_store($cache_key, $resp, $cache_ttl);
            }

            header("Content-Type: application/dns-message");
            echo $resp;

            curl_multi_close($mh);
            exit();
        }
    }

} while ($running);

curl_multi_close($mh);

error_json(502, "All upstream DoH failed");