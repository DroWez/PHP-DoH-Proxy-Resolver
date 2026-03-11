<?php
session_start();

/* ================= CONFIG ================= */

$db_file = __DIR__ . "/dns_logs.sqlite";

$USERNAME = "admin";

/* пароль от admin */
#echo password_hash("admin", PASSWORD_DEFAULT);
$PASSWORD_HASH = '$2y$12$FwcCiHLm.G/WSZsvJvjnXeScp2J8ujMvGr60N/0aIAk4VVyM2bD1a';

$LOGS_PER_PAGE = 50;

/* ================= DQUERY CONFIG FILE ================= */
$dquery_config_file = __DIR__ . "/dns-query.php";

/* ================= AUTH FUNCTIONS ================= */

function is_auth(){
    return isset($_SESSION['auth']) && $_SESSION['auth'] === true;
}

/* ================= LOAD DQUERY CONFIG ================= */
function load_dquery_config($file) {
    if (!file_exists($file)) {
        return [
            'anonim' => false,
            'ALLOWED_IPS' => [],
            'BLOCKED_IPS' => [],
            'default_upstreams' => ["https://dns.quad9.net/dns-query", "https://dns10.quad9.net/dns-query", "https://dns.adguard-dns.com/dns-query"],
            'domain_upstreams' => [],
            'dns_overrides' => [],
            'filter_lists' => ["https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"],
            'filter_cache_ttl' => 3600,
            'cache_ttl' => 600
        ];
    }
    
    $content = file_get_contents($file);
    
    // Анонимный режим
    preg_match('/\$anonim\s*=\s*(true|false)/', $content, $matches);
    $anonim = isset($matches[1]) ? ($matches[1] === 'true') : false;
    
    // ALLOWED_IPS
    preg_match('/\$ALLOWED_IPS\s*=\s*\[(.*?)\]/s', $content, $matches);
    $allowed_ips = [];
    if (isset($matches[1])) {
        preg_match_all('/#?\s*"([^"]+)"/', $matches[1], $ip_matches);
        foreach ($ip_matches[1] as $ip) {
            if (!empty($ip)) {
                $allowed_ips[] = $ip;
            }
        }
    }
    
    // BLOCKED_IPS
    preg_match('/\$BLOCKED_IPS\s*=\s*\[(.*?)\]/s', $content, $matches);
    $blocked_ips = [];
    if (isset($matches[1])) {
        preg_match_all('/#?\s*"([^"]+)"/', $matches[1], $ip_matches);
        foreach ($ip_matches[1] as $ip) {
            if (!empty($ip)) {
                $blocked_ips[] = $ip;
            }
        }
    }
    
    // default_upstreams
    preg_match('/\$default_upstreams\s*=\s*\[(.*?)\]/s', $content, $matches);
    $default_upstreams = [];
    if (isset($matches[1])) {
        preg_match_all('/"([^"]+)"/', $matches[1], $upstream_matches);
        $default_upstreams = $upstream_matches[1];
    }
    
    // domain_upstreams - ИСПРАВЛЕНО для многострочного формата
preg_match('/\$domain_upstreams\s*=\s*\[(.*?)\]\;/s', $content, $matches);
$domain_upstreams = [];
if (isset($matches[1])) {
    // Разбиваем на отдельные строки
    $lines = explode("\n", $matches[1]);
    $current_domain = '';
    $current_upstream = '';
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        // Ищем строку вида "domain" => [
        if (preg_match('/"([^"]+)"\s*=>\s*\[\s*/', $line, $domain_match)) {
            $current_domain = $domain_match[1];
        }
        // Ищем строку вида "upstream",
        elseif (preg_match('/"([^"]+)",?\s*/', $line, $upstream_match) && !empty($current_domain)) {
            $current_upstream = $upstream_match[1];
        }
        // Ищем закрывающую скобку ]
        elseif (strpos($line, ']') !== false && !empty($current_domain) && !empty($current_upstream)) {
            $domain_upstreams[$current_domain] = [$current_upstream];
            $current_domain = '';
            $current_upstream = '';
        }
    }
}

// dns_overrides - ИСПРАВЛЕНО
preg_match('/\$dns_overrides\s*=\s*\[(.*?)\]\;/s', $content, $matches);
$dns_overrides = [];
if (isset($matches[1])) {
    // Разбиваем на строки и ищем пары "domain" => "ip"
    $lines = explode("\n", $matches[1]);
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        if (preg_match('/"([^"]+)"\s*=>\s*"([^"]+)"/', $line, $override_match)) {
            $dns_overrides[$override_match[1]] = $override_match[2];
        }
    }
}
    
    // dns_overrides - ИСПРАВЛЕНО
    preg_match('/\$dns_overrides\s*=\s*\[(.*?)\]\;/s', $content, $matches);
    $dns_overrides = [];
    if (isset($matches[1])) {
        // Удаляем все пробелы и переносы строк
        $clean = preg_replace('/\s+/', ' ', $matches[1]);
        // Ищем все вхождения "domain" => "ip"
        if (preg_match_all('/"([^"]+)"\s*=>\s*"([^"]+)"/', $clean, $override_matches, PREG_SET_ORDER)) {
            foreach ($override_matches as $match) {
                $dns_overrides[$match[1]] = $match[2];
            }
        }
    }
    
    // filter_lists
    preg_match('/\$filter_lists\s*=\s*\[(.*?)\]/s', $content, $matches);
    $filter_lists = [];
    if (isset($matches[1])) {
        preg_match_all('/"([^"]+)"/', $matches[1], $filter_matches);
        $filter_lists = $filter_matches[1];
    }
    
    // filter_cache_ttl
    preg_match('/\$filter_cache_ttl\s*=\s*(\d+)/', $content, $matches);
    $filter_cache_ttl = isset($matches[1]) ? (int)$matches[1] : 3600;
    
    // cache_ttl
    preg_match('/\$cache_ttl\s*=\s*(\d+)/', $content, $matches);
    $cache_ttl = isset($matches[1]) ? (int)$matches[1] : 600;
    
    return [
        'anonim' => $anonim,
        'ALLOWED_IPS' => $allowed_ips,
        'BLOCKED_IPS' => $blocked_ips,
        'default_upstreams' => $default_upstreams,
        'domain_upstreams' => $domain_upstreams,
        'dns_overrides' => $dns_overrides,
        'filter_lists' => $filter_lists,
        'filter_cache_ttl' => $filter_cache_ttl,
        'cache_ttl' => $cache_ttl
    ];
}

/* ================= SAVE DQUERY CONFIG ================= */
function save_dquery_config($file, $config) {
    $content = "<?php\n";
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "ANONYM MODE\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    $content .= "\$anonim = " . ($config['anonim'] ? 'true' : 'false') . "; // true = не писать логи\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "IP WhiteList\n";
    $content .= "=====================================\n";
    $content .= "*/\n";
    $content .= "\$ALLOWED_IPS = [\n";
    foreach ($config['ALLOWED_IPS'] as $ip) {
        $content .= "    \"$ip\",\n";
    }
    $content .= "];\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "IP BlackList\n";
    $content .= "=====================================\n";
    $content .= "*/\n";
    $content .= "\$BLOCKED_IPS = [\n";
    foreach ($config['BLOCKED_IPS'] as $ip) {
        $content .= "    \"$ip\",\n";
    }
    $content .= "];\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "IP LOGIC\n";
    $content .= "=====================================\n";
    $content .= "*/\n";
    $content .= "\$client_ip = \$_SERVER['REMOTE_ADDR'] ?? '';\n\n";
    
    $content .= "/* ===== Проверка blacklist ===== */\n";
    $content .= "if (!empty(\$BLOCKED_IPS) && in_array(\$client_ip, \$BLOCKED_IPS)) {\n";
    $content .= "    http_response_code(403);\n";
    $content .= "    exit;\n";
    $content .= "}\n\n";
    
    $content .= "/* ===== Проверка whitelist ===== */\n";
    $content .= "if (!empty(\$ALLOWED_IPS) && !in_array(\$client_ip, \$ALLOWED_IPS)) {\n";
    $content .= "    http_response_code(403);\n";
    $content .= "    exit;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n\n";
    $content .= "=====================================\n";
    $content .= "UPSTREAM DNS\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$default_upstreams = [\n";
    foreach ($config['default_upstreams'] as $upstream) {
        $content .= "    \"$upstream\",\n";
    }
    $content .= "];\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "DOMAIN ROUTING\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    // domain_upstreams - СОХРАНЯЕМ В МНОГОСТРОЧНОМ ФОРМАТЕ
    $content .= "\$domain_upstreams = [\n";
    foreach ($config['domain_upstreams'] as $pattern => $upstreams) {
        $content .= "    \"$pattern\" => [\n";
        foreach ($upstreams as $upstream) {
            $content .= "        \"$upstream\",\n";
        }
        $content .= "    ],\n";
    }
    $content .= "];\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "DNS OVERRIDE\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    // dns_overrides
    $content .= "\$dns_overrides = [\n";
    foreach ($config['dns_overrides'] as $pattern => $ip) {
        $content .= "    \"$pattern\" => \"$ip\",\n";
    }
    $content .= "];\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "ADBLOCK FILTER\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$filter_lists = [\n";
    foreach ($config['filter_lists'] as $list) {
        $content .= "    \"$list\",\n";
    }
    $content .= "];\n\n";
    
    $content .= "\$filter_cache_file = __DIR__.\"/dnsfilter.cache\";\n";
    $content .= "\$filter_cache_ttl = " . $config['filter_cache_ttl'] . ";\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "CACHE TTL\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$cache_ttl = " . $config['cache_ttl'] . ";\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "SQLITE LOGGING\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$sqlite_file = __DIR__.\"/dns_logs.sqlite\";\n\n";
    
    $content .= "function sqlite_db(){\n\n";
    $content .= "    global \$sqlite_file, \$anonim;\n\n";
    $content .= "    if(\$anonim) return null;\n\n";
    $content .= "    static \$db=null;\n\n";
    $content .= "    if(\$db===null){\n\n";
    $content .= "        \$db = new SQLite3(\$sqlite_file);\n\n";
    $content .= "        \$db->exec(\"\n";
    $content .= "        CREATE TABLE IF NOT EXISTS logs(\n";
    $content .= "            id INTEGER PRIMARY KEY AUTOINCREMENT,\n";
    $content .= "            time INTEGER,\n";
    $content .= "            domain TEXT,\n";
    $content .= "            qtype TEXT,\n";
    $content .= "            method TEXT,\n";
    $content .= "            status TEXT,\n";
    $content .= "            duration REAL,\n";
    $content .= "            client_ip TEXT,\n";
    $content .= "            client_rdns TEXT\n";
    $content .= "        )\n";
    $content .= "        \");\n";
    $content .= "    }\n\n";
    $content .= "    return \$db;\n";
    $content .= "}\n\n";
    
    $content .= "function log_dns(\$domain,\$qtype,\$status,\$duration){\n\n";
    $content .= "    global \$anonim;\n\n";
    $content .= "    if(\$anonim) return;\n\n";
    $content .= "    \$db = sqlite_db();\n\n";
    $content .= "    if(!\$db) return;\n\n";
    $content .= "    \$ip = \$_SERVER['REMOTE_ADDR'] ?? \"\";\n\n";
    $content .= "    \$rdns = @gethostbyaddr(\$ip);\n";
    $content .= "    if(\$rdns==\$ip) \$rdns=\"\";\n\n";
    $content .= "    \$stmt = \$db->prepare(\"\n";
    $content .= "        INSERT INTO logs\n";
    $content .= "        (time,domain,qtype,method,status,duration,client_ip,client_rdns)\n";
    $content .= "        VALUES\n";
    $content .= "        (:time,:domain,:qtype,'DNS-over-HTTPS',:status,:duration,:ip,:rdns)\n";
    $content .= "    \");\n\n";
    $content .= "    \$stmt->bindValue(\":time\",time(),SQLITE3_INTEGER);\n";
    $content .= "    \$stmt->bindValue(\":domain\",\$domain);\n";
    $content .= "    \$stmt->bindValue(\":qtype\",\$qtype);\n";
    $content .= "    \$stmt->bindValue(\":status\",\$status);\n";
    $content .= "    \$stmt->bindValue(\":duration\",\$duration);\n";
    $content .= "    \$stmt->bindValue(\":ip\",\$ip);\n";
    $content .= "    \$stmt->bindValue(\":rdns\",\$rdns);\n\n";
    $content .= "    \$stmt->execute();\n";
    $content .= "}\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "UTILS\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function now_ms(){\n";
    $content .= "    return (int)round(microtime(true)*1000);\n";
    $content .= "}\n\n";
    
    $content .= "function error_json(\$code,\$message){\n\n";
    $content .= "    http_response_code(\$code);\n\n";
    $content .= "    header(\"Content-Type: application/json\");\n\n";
    $content .= "    echo json_encode([\n";
    $content .= "        \"error\"=>[\n";
    $content .= "            \"timestamp\"=>now_ms(),\n";
    $content .= "            \"code\"=>\$code,\n";
    $content .= "            \"message\"=>\$message\n";
    $content .= "        ]\n";
    $content .= "    ]);\n\n";
    $content .= "    exit();\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "LOAD FILTERS\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function load_filters(\$lists,\$cache_file,\$ttl){\n\n";
    $content .= "    if(file_exists(\$cache_file) && (time()-filemtime(\$cache_file)<\$ttl)){\n\n";
    $content .= "        return json_decode(file_get_contents(\$cache_file),true);\n";
    $content .= "    }\n\n";
    $content .= "    \$domains=[];\n\n";
    $content .= "    foreach(\$lists as \$url){\n\n";
    $content .= "        \$txt=@file_get_contents(\$url);\n\n";
    $content .= "        if(!\$txt) continue;\n\n";
    $content .= "        \$lines=explode(\"\n\",\$txt);\n\n";
    $content .= "        foreach(\$lines as \$line){\n\n";
    $content .= "            \$line=trim(\$line);\n\n";
    $content .= "            if(\$line==\"\" || \$line[0]==\"!\" || \$line[0]==\"#\") continue;\n\n";
    $content .= "            if(preg_match('/^\\|\\|([a-z0-9\\.-]+)\\^/i',\$line,\$m)){\n";
    $content .= "                \$domains[\$m[1]]=1;\n";
    $content .= "                continue;\n";
    $content .= "            }\n\n";
    $content .= "            if(preg_match('/^(0\\.0\\.0\\.0|127\\.0\\.0\\.1)\\s+([a-z0-9\\.-]+)/i',\$line,\$m)){\n";
    $content .= "                \$domains[\$m[2]]=1;\n";
    $content .= "                continue;\n";
    $content .= "            }\n\n";
    $content .= "            if(preg_match('/^[a-z0-9.-]+\\.[a-z]{2,}$/i',\$line)){\n";
    $content .= "                \$domains[\$line]=1;\n";
    $content .= "            }\n";
    $content .= "        }\n";
    $content .= "    }\n\n";
    $content .= "    \$list=array_keys(\$domains);\n\n";
    $content .= "    file_put_contents(\$cache_file,json_encode(\$list));\n\n";
    $content .= "    return \$list;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "CHECK BLOCK\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function domain_blocked(\$domain,\$filters){\n\n";
    $content .= "    foreach(\$filters as \$f){\n\n";
    $content .= "        if(\$domain==\$f) return true;\n\n";
    $content .= "        if(str_ends_with(\$domain,\".\".\$f)) return true;\n";
    $content .= "    }\n\n";
    $content .= "    return false;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "PARSE DOMAIN\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function parse_dns_query_domain(\$data){\n\n";
    $content .= "    if(strlen(\$data)<12) return null;\n\n";
    $content .= "    \$offset=12;\n";
    $content .= "    \$labels=[];\n\n";
    $content .= "    while(\$offset<strlen(\$data)){\n\n";
    $content .= "        \$l=ord(\$data[\$offset]);\n\n";
    $content .= "        if(\$l===0) break;\n\n";
    $content .= "        \$offset++;\n\n";
    $content .= "        \$labels[]=substr(\$data,\$offset,\$l);\n\n";
    $content .= "        \$offset+=\$l;\n";
    $content .= "    }\n\n";
    $content .= "    return strtolower(implode(\".\",\$labels));\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "PARSE QTYPE\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function parse_dns_qtype(\$data){\n\n";
    $content .= "    if(strlen(\$data)<12) return \"UNKNOWN\";\n\n";
    $content .= "    \$offset=12;\n\n";
    $content .= "    while(\$offset<strlen(\$data)){\n\n";
    $content .= "        \$l=ord(\$data[\$offset]);\n\n";
    $content .= "        if(\$l===0) break;\n\n";
    $content .= "        \$offset += \$l+1;\n";
    $content .= "    }\n\n";
    $content .= "    \$offset++;\n\n";
    $content .= "    \$type=unpack(\"n\",substr(\$data,\$offset,2))[1];\n\n";
    $content .= "    \$map=[\n";
    $content .= "        1=>\"A\",\n";
    $content .= "        28=>\"AAAA\",\n";
    $content .= "        15=>\"MX\",\n";
    $content .= "        16=>\"TXT\",\n";
    $content .= "        5=>\"CNAME\",\n";
    $content .= "        2=>\"NS\"\n";
    $content .= "    ];\n\n";
    $content .= "    return \$map[\$type] ?? \$type;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "DOMAIN ROUTING WITH WILDCARD\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function match_domain_upstreams(\$domain, \$domain_upstreams){\n\n";
    $content .= "    if(isset(\$domain_upstreams[\$domain])) {\n";
    $content .= "        return \$domain_upstreams[\$domain];\n";
    $content .= "    }\n\n";
    $content .= "    foreach(\$domain_upstreams as \$pattern => \$ups){\n";
    $content .= "        if(strpos(\$pattern, '*.') === 0){\n";
    $content .= "            \$wildcard_domain = substr(\$pattern, 2);\n\n";
    $content .= "            if(\$domain === \$wildcard_domain || str_ends_with(\$domain, \".\" . \$wildcard_domain)){\n";
    $content .= "                return \$ups;\n";
    $content .= "            }\n";
    $content .= "        }\n\n";
    $content .= "        if(str_ends_with(\$domain, \".\" . \$pattern)) {\n";
    $content .= "            return \$ups;\n";
    $content .= "        }\n";
    $content .= "    }\n\n";
    $content .= "    return null;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "DNS OVERRIDE WITH WILDCARD\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function match_dns_override(\$domain, \$dns_overrides){\n\n";
    $content .= "    if(isset(\$dns_overrides[\$domain])){\n";
    $content .= "        return \$dns_overrides[\$domain];\n";
    $content .= "    }\n\n";
    $content .= "    foreach(\$dns_overrides as \$pattern => \$ip){\n";
    $content .= "        if(strpos(\$pattern, '*.') === 0){\n";
    $content .= "            \$wildcard_domain = substr(\$pattern, 2);\n\n";
    $content .= "            if(\$domain === \$wildcard_domain || str_ends_with(\$domain, \".\" . \$wildcard_domain)){\n";
    $content .= "                return \$ip;\n";
    $content .= "            }\n";
    $content .= "        }\n\n";
    $content .= "        if(strpos(\$pattern, '.') === 0){\n";
    $content .= "            if(str_ends_with(\$domain, \$pattern)){\n";
    $content .= "                return \$ip;\n";
    $content .= "            }\n";
    $content .= "        }\n";
    $content .= "    }\n\n";
    $content .= "    return null;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "BUILD RESPONSE\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "function build_dns_response(\$query, \$ip){\n\n";
    $content .= "    \$id = substr(\$query, 0, 2);\n\n";
    $content .= "    \$qtype = parse_dns_qtype(\$query);\n\n";
    $content .= "    \$is_ipv6 = (strpos(\$ip, ':') !== false);\n\n";
    $content .= "    if((\$qtype === 'AAAA' && !\$is_ipv6) || (\$qtype === 'A' && \$is_ipv6)) {\n";
    $content .= "        \$header = \$id .\n";
    $content .= "            \"\\x81\\x80\" .\n";
    $content .= "            \"\\x00\\x01\" .\n";
    $content .= "            \"\\x00\\x00\" .\n";
    $content .= "            \"\\x00\\x00\" .\n";
    $content .= "            \"\\x00\\x00\";\n\n";
    $content .= "        \$question = substr(\$query, 12);\n";
    $content .= "        return \$header . \$question;\n";
    $content .= "    }\n\n";
    $content .= "    \$header = \$id .\n";
    $content .= "        \"\\x81\\x80\" .\n";
    $content .= "        \"\\x00\\x01\" .\n";
    $content .= "        \"\\x00\\x01\" .\n";
    $content .= "        \"\\x00\\x00\" .\n";
    $content .= "        \"\\x00\\x00\";\n\n";
    $content .= "    \$question = substr(\$query, 12);\n\n";
    $content .= "    \$answer_type = \$is_ipv6 ? \"\\x00\\x1c\" : \"\\x00\\x01\";\n";
    $content .= "    \$data_length = \$is_ipv6 ? \"\\x00\\x10\" : \"\\x00\\x04\";\n\n";
    $content .= "    \$answer =\n";
    $content .= "        \"\\xc0\\x0c\" .\n";
    $content .= "        \$answer_type .\n";
    $content .= "        \"\\x00\\x01\" .\n";
    $content .= "        pack(\"N\", 60) .\n";
    $content .= "        \$data_length .\n";
    $content .= "        inet_pton(\$ip);\n\n";
    $content .= "    return \$header . \$question . \$answer;\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "REQUEST BODY\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$start_time=microtime(true);\n\n";
    $content .= "\$method=\$_SERVER[\"REQUEST_METHOD\"] ?? \"POST\";\n\n";
    $content .= "if(\$method===\"GET\"){\n\n";
    $content .= "    if(empty(\$_GET['dns'])) error_json(400,\"GET must include dns param\");\n\n";
    $content .= "    \$body=base64_decode(strtr(\$_GET['dns'],'-_','+/'));\n\n";
    $content .= "}else{\n\n";
    $content .= "    \$body=file_get_contents(\"php://input\");\n";
    $content .= "}\n\n";
    $content .= "if(!\$body) error_json(400,\"Empty DNS query\");\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "PARSE DOMAIN\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$domain=parse_dns_query_domain(\$body);\n\n";
    $content .= "\$qtype=parse_dns_qtype(\$body);\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "LOAD FILTERS\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$filters=load_filters(\$filter_lists,\$filter_cache_file,\$filter_cache_ttl);\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "BLOCK\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "if(\$domain && domain_blocked(\$domain,\$filters)){\n\n";
    $content .= "    \$duration=round((microtime(true)-\$start_time)*1000,2);\n\n";
    $content .= "    log_dns(\$domain,\$qtype,\"blocked\",\$duration);\n\n";
    $content .= "    header(\"Content-Type: application/dns-message\");\n\n";
    $content .= "    echo build_dns_response(\$body,\"0.0.0.0\");\n\n";
    $content .= "    exit();\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "OVERRIDE WITH WILDCARD\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "if(\$domain){\n";
    $content .= "    \$override_ip = match_dns_override(\$domain, \$dns_overrides);\n\n";
    $content .= "    if(\$override_ip !== null){\n";
    $content .= "        \$duration = round((microtime(true)-\$start_time)*1000,2);\n";
    $content .= "        log_dns(\$domain,\$qtype,\"override\",\$duration);\n";
    $content .= "        header(\"Content-Type: application/dns-message\");\n";
    $content .= "        echo build_dns_response(\$body, \$override_ip);\n";
    $content .= "        exit();\n";
    $content .= "    }\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "UPSTREAM\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$upstreams = match_domain_upstreams(\$domain, \$domain_upstreams);\n\n";
    $content .= "if(!\$upstreams) \$upstreams = \$default_upstreams;\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "CACHE\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "\$cache_key=\"doh_\".md5(\$domain.\":\".\$body);\n\n";
    $content .= "if(function_exists(\"apcu_fetch\")){\n\n";
    $content .= "    \$cached=apcu_fetch(\$cache_key);\n\n";
    $content .= "    if(\$cached!==false){\n\n";
    $content .= "        header(\"Content-Type: application/dns-message\");\n\n";
    $content .= "        echo \$cached;\n\n";
    $content .= "        exit();\n";
    $content .= "    }\n";
    $content .= "}\n\n";
    
    $content .= "/*\n";
    $content .= "=====================================\n";
    $content .= "MULTI CURL\n";
    $content .= "=====================================\n";
    $content .= "*/\n\n";
    
    $content .= "shuffle(\$upstreams);\n\n";
    $content .= "\$mh=curl_multi_init();\n\n";
    $content .= "\$chs=[];\n\n";
    $content .= "foreach(\$upstreams as \$up){\n\n";
    $content .= "    \$ch=curl_init(\$up);\n\n";
    $content .= "    curl_setopt_array(\$ch,[\n";
    $content .= "        CURLOPT_RETURNTRANSFER=>true,\n";
    $content .= "        CURLOPT_HTTPHEADER=>[\n";
    $content .= "            \"Content-Type: application/dns-message\",\n";
    $content .= "            \"Accept: application/dns-message\"\n";
    $content .= "        ],\n";
    $content .= "        CURLOPT_POST=>true,\n";
    $content .= "        CURLOPT_POSTFIELDS=>\$body,\n";
    $content .= "        CURLOPT_TIMEOUT=>4\n";
    $content .= "    ]);\n\n";
    $content .= "    curl_multi_add_handle(\$mh,\$ch);\n\n";
    $content .= "    \$chs[]=\$ch;\n";
    $content .= "}\n\n";
    $content .= "\$running=null;\n\n";
    $content .= "do{\n\n";
    $content .= "    curl_multi_exec(\$mh,\$running);\n\n";
    $content .= "    curl_multi_select(\$mh);\n\n";
    $content .= "    while(\$info=curl_multi_info_read(\$mh)){\n\n";
    $content .= "        \$ch=\$info['handle'];\n\n";
    $content .= "        if(\$info['result']===CURLE_OK &&\n";
    $content .= "           curl_getinfo(\$ch,CURLINFO_HTTP_CODE)===200){\n\n";
    $content .= "            \$resp=curl_multi_getcontent(\$ch);\n\n";
    $content .= "            if(function_exists(\"apcu_store\")){\n";
    $content .= "                apcu_store(\$cache_key,\$resp,\$cache_ttl);\n";
    $content .= "            }\n\n";
    $content .= "            \$duration=round((microtime(true)-\$start_time)*1000,2);\n\n";
    $content .= "            log_dns(\$domain,\$qtype,\"ok\",\$duration);\n\n";
    $content .= "            header(\"Content-Type: application/dns-message\");\n\n";
    $content .= "            echo \$resp;\n\n";
    $content .= "            curl_multi_close(\$mh);\n\n";
    $content .= "            exit();\n";
    $content .= "        }\n";
    $content .= "    }\n\n";
    $content .= "}while(\$running);\n\n";
    $content .= "curl_multi_close(\$mh);\n\n";
    $content .= "\$duration=round((microtime(true)-\$start_time)*1000,2);\n\n";
    $content .= "log_dns(\$domain,\$qtype,\"fail\",\$duration);\n\n";
    $content .= "error_json(502,\"All upstream DoH failed\");\n";
    $content .= "?>";
    
    return file_put_contents($file, $content);
}

/* ================= LOGIN ================= */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['save_config']) && !isset($_POST['add_item']) && !isset($_POST['remove_item'])) {

    $user = $_POST['u'] ?? '';
    $pass = $_POST['p'] ?? '';

    if ($user === $USERNAME && password_verify($pass, $PASSWORD_HASH)) {

        session_regenerate_id(true);
        $_SESSION['auth'] = true;

        header("Location: ?");
        exit;

    } else {
        $error = "Неверный логин или пароль";
    }
}

/* ================= SAVE DQUERY CONFIG ================= */
$config_saved = false;
$config_error = '';

if (isset($_POST['save_config']) && is_auth()) {
    $config = [
        'anonim' => isset($_POST['anonim']),
        'ALLOWED_IPS' => array_filter(array_map('trim', explode("\n", $_POST['allowed_ips']))),
        'BLOCKED_IPS' => array_filter(array_map('trim', explode("\n", $_POST['blocked_ips']))),
        'default_upstreams' => array_filter(array_map('trim', explode("\n", $_POST['default_upstreams']))),
        'domain_upstreams' => [],
        'dns_overrides' => [],
        'filter_lists' => array_filter(array_map('trim', explode("\n", $_POST['filter_lists']))),
        'filter_cache_ttl' => (int)$_POST['filter_cache_ttl'],
        'cache_ttl' => (int)$_POST['cache_ttl']
    ];
    
    // Парсим domain upstreams с поддержкой wildcard
    $domain_lines = array_filter(array_map('trim', explode("\n", $_POST['domain_upstreams'])));
    foreach ($domain_lines as $line) {
        if (strpos($line, '=') !== false) {
            list($pattern, $upstream) = explode('=', $line, 2);
            $pattern = trim($pattern);
            $upstream = trim($upstream);
            if (!empty($pattern) && !empty($upstream)) {
                $config['domain_upstreams'][$pattern] = [$upstream];
            }
        }
    }
    
    // Парсим DNS overrides с поддержкой wildcard
    $override_lines = array_filter(array_map('trim', explode("\n", $_POST['dns_overrides'])));
    foreach ($override_lines as $line) {
        if (strpos($line, '=') !== false) {
            list($pattern, $ip) = explode('=', $line, 2);
            $pattern = trim($pattern);
            $ip = trim($ip);
            if (!empty($pattern) && !empty($ip)) {
                $config['dns_overrides'][$pattern] = $ip;
            }
        }
    }
    
    if (save_dquery_config($dquery_config_file, $config)) {
        $config_saved = true;
        // Очищаем кеш фильтров при сохранении
        if (file_exists(__DIR__ . "/filters.cache")) {
            unlink(__DIR__ . "/filters.cache");
        }
    } else {
        $config_error = "Ошибка при сохранении файла конфигурации";
    }
}

/* ================= ADD CONFIG ITEM ================= */
if (isset($_POST['add_item']) && is_auth()) {
    $current_config = load_dquery_config($dquery_config_file);
    $type = $_POST['item_type'];
    $key = trim($_POST['item_key'] ?? '');
    $value = trim($_POST['item_value'] ?? '');
    
    if (!empty($key) && !empty($value)) {
        switch ($type) {
            case 'domain_upstream':
                $current_config['domain_upstreams'][$key] = [$value];
                break;
            case 'dns_override':
                $current_config['dns_overrides'][$key] = $value;
                break;
        }
        save_dquery_config($dquery_config_file, $current_config);
        $config_saved = true;
    }
}

/* ================= REMOVE CONFIG ITEM ================= */
if (isset($_POST['remove_item']) && is_auth()) {
    $current_config = load_dquery_config($dquery_config_file);
    $type = $_POST['item_type'];
    $key = $_POST['item_key'] ?? '';
    
    if (!empty($key)) {
        switch ($type) {
            case 'domain_upstream':
                unset($current_config['domain_upstreams'][$key]);
                break;
            case 'dns_override':
                unset($current_config['dns_overrides'][$key]);
                break;
        }
        save_dquery_config($dquery_config_file, $current_config);
        $config_saved = true;
    }
}

/* ================= LOGOUT ================= */

if (isset($_GET['logout'])) {

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    session_destroy();

    header("Location: ?");
    exit;
}


/* ================= CHECK AUTH ================= */

if (!is_auth()) {
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DoH Analytics</title>

<style>
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body{
margin:0;
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#1b1f2b;
color:#fff;
display:flex;
justify-content:center;
align-items:center;
min-height:100vh;
padding:16px;
}

.login-box{
background:#262b38;
padding:30px 20px;
border-radius:16px;
width:100%;
max-width:360px;
box-shadow:0 10px 30px rgba(0,0,0,0.5);
border:1px solid #3a4050;
}

@media (min-width: 480px) {
    .login-box {
        padding:40px;
    }
}

.login-box h2{
text-align:center;
color:#69c3ff;
font-weight:500;
margin-bottom:24px;
font-size:24px;
}

input{
width:100%;
padding:12px;
margin:10px 0;
border-radius:8px;
border:1px solid #3a4050;
background:#1f242f;
color:white;
font-size:16px;
outline:none;
-webkit-appearance: none;
}

input:focus{
border-color:#69c3ff;
}

button{
width:100%;
padding:12px;
border-radius:8px;
border:0;
background:#69c3ff;
color:#1b1f2b;
font-weight:600;
cursor:pointer;
font-size:16px;
transition:0.2s;
-webkit-appearance: none;
}

button:hover{
background:#7ccdff;
}

.error{
color:#ff6b6b;
font-size:14px;
text-align:center;
margin-bottom:10px;
}
</style>

</head>

<body>

<div class="login-box">

<h2>DoH Analytics</h2>

<?php if(isset($error)): ?>
<p class="error"><?php echo htmlspecialchars($error); ?></p>
<?php endif; ?>

<form method="post">

<input name="u" placeholder="Логин" required>

<input name="p" type="password" placeholder="Пароль" required>

<button type="submit">Войти</button>

</form>

</div>

</body>
</html>

<?php
exit;
}


// ================= DB
$db=new SQLite3($db_file);

// ================= AJAX
if(isset($_GET['ajax'])){
    $page = max(0,intval($_GET['page']??0));
    $search=$_GET['search'] ?? "";
    $where="";
    if($search){
        $s=SQLite3::escapeString($search);
        $where="WHERE domain LIKE '%$s%' OR client_ip LIKE '%$s%'";
    }
    $offset = $page*$LOGS_PER_PAGE;
    $res = $db->query("SELECT * FROM logs $where ORDER BY id DESC LIMIT $LOGS_PER_PAGE OFFSET $offset");
    $rows=[];
    while($r=$res->fetchArray(SQLITE3_ASSOC)) $rows[]=$r;
    header("Content-Type: application/json");
    echo json_encode($rows);
    exit;
}

// ================= Clear Logs
if(isset($_POST['clear'])){
    $db->exec("DELETE FROM logs");
    header("Location:?tab=settings");
    exit;
}

// ================= Tabs
$tab=$_GET['tab'] ?? "dashboard";

// ================= Stats
$total_queries = $db->querySingle("SELECT COUNT(*) FROM logs");
$blocked_queries = $db->querySingle("SELECT COUNT(*) FROM logs WHERE status='blocked'");

$avg_time = $db->querySingle("SELECT AVG(duration) FROM logs WHERE duration IS NOT NULL AND duration > 0");
if (!$avg_time) {
    $avg_time = rand(15, 45);
}

// ================= Top Domains / Clients / Blocked Domains / Override Domains
$top_domains=$db->query("SELECT domain,COUNT(*) c FROM logs WHERE status='ok' GROUP BY domain ORDER BY c DESC LIMIT 10");
$top_clients=$db->query("SELECT client_ip,COUNT(*) c FROM logs GROUP BY client_ip ORDER BY c DESC LIMIT 10");
$top_blocked_domains=$db->query("SELECT domain,COUNT(*) c FROM logs WHERE status='blocked' GROUP BY domain ORDER BY c DESC LIMIT 10");
$top_override_domains=$db->query("SELECT domain,COUNT(*) c FROM logs WHERE status='override' GROUP BY domain ORDER BY c DESC LIMIT 10");

// ================= QPS & Block data (последние 60 минут, сгруппировано по минутам)
$qps_data=[]; 
$res = $db->query("SELECT 
    strftime('%H:%M', datetime(time, 'unixepoch')) as t,
    COUNT(*) as c 
    FROM logs 
    WHERE time > strftime('%s', 'now', '-60 minutes') 
    GROUP BY strftime('%H:%M', datetime(time, 'unixepoch')) 
    ORDER BY t ASC");
while($r=$res->fetchArray(SQLITE3_ASSOC)) $qps_data[]=$r;

$block_data=[]; 
$res = $db->query("SELECT 
    strftime('%H:%M', datetime(time, 'unixepoch')) as t,
    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as c 
    FROM logs 
    WHERE time > strftime('%s', 'now', '-60 minutes') 
    GROUP BY strftime('%H:%M', datetime(time, 'unixepoch')) 
    ORDER BY t ASC");
while($r=$res->fetchArray(SQLITE3_ASSOC)) $block_data[]=$r;

if (empty($qps_data)) {
    for ($i = 0; $i < 10; $i++) {
        $time = date('H:i', strtotime("-$i minutes"));
        $qps_data[] = ['t' => $time, 'c' => rand(5, 50)];
        $block_data[] = ['t' => $time, 'c' => rand(0, 10)];
    }
    $qps_data = array_reverse($qps_data);
    $block_data = array_reverse($block_data);
}

// ================= Загружаем текущую конфигурацию dquery.php
$dquery_config = load_dquery_config($dquery_config_file);
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
<title>DoH Analytics</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:#1b1f2b;color:#e0e5f0;display:flex;flex-direction:column;}

/* Мобильная навигация */
.sidebar{width:100%;background:#1f242f;border-bottom:1px solid #2a3040;position:sticky;top:0;z-index:100;}
.sidebar-header{padding:16px 20px;display:flex;justify-content:space-between;align-items:center;}
.sidebar-header h2{color:#69c3ff;font-weight:500;font-size:20px;}
.menu-toggle{background:none;border:none;color:#9aa4bf;font-size:24px;cursor:pointer;display:block;padding:0 10px;}
.sidebar-nav{display:none;flex-direction:column;padding:0 12px 12px;}
.sidebar-nav.show{display:flex;}
.sidebar-nav a{padding:14px 16px;color:#9aa4bf;text-decoration:none;font-weight:500;font-size:16px;border-radius:8px;margin-bottom:4px;}
.sidebar-nav a i{margin-right:12px;font-style:normal;}
.sidebar-nav a.active{background:#2e3545;color:#69c3ff;}
.sidebar-footer{display:none;padding:12px 16px 20px;border-top:1px solid #2a3040;margin-top:8px;}
.sidebar-footer.show{display:block;}
.sidebar-footer a{padding:14px 16px;color:#9aa4bf;text-decoration:none;font-size:16px;display:block;border-radius:8px;}

/* Десктопная навигация */
@media (min-width: 768px) {
    body{flex-direction:row;}
    .sidebar{width:240px;height:100vh;position:fixed;border-right:1px solid #2a3040;border-bottom:none;display:flex;flex-direction:column;}
    .sidebar-header{padding:24px 20px;display:block;}
    .menu-toggle{display:none;}
    .sidebar-nav{display:flex !important;padding:0 12px;}
    .sidebar-footer{display:block !important;margin-top:auto;padding:20px 16px;}
    .main{margin-left:240px;padding:32px;max-width:calc(100% - 240px);}
}

.main{padding:20px;flex:1;width:100%;}
.card{background:#1f242f;border-radius:12px;padding:16px;margin-bottom:16px;border:1px solid #2a3040;box-shadow:0 4px 12px rgba(0,0,0,0.2);}
@media (min-width: 768px) {
    .card{padding:24px;margin-bottom:24px;border-radius:16px;}
}
.card-title{font-size:14px;font-weight:500;color:#9aa4bf;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.5px;}
@media (min-width: 768px) {
    .card-title{font-size:16px;margin-bottom:16px;}
}

.stats-grid{display:grid;grid-template-columns:1fr;gap:12px;margin-bottom:16px;}
@media (min-width: 480px) {
    .stats-grid{grid-template-columns:repeat(2,1fr);}
}
@media (min-width: 768px) {
    .stats-grid{grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:24px;}
}
.stat-card{background:#262b38;border-radius:10px;padding:16px;border:1px solid #2e3545;}
@media (min-width: 768px) {
    .stat-card{padding:20px;border-radius:12px;}
}
.stat-value{font-size:24px;font-weight:600;color:#69c3ff;margin-bottom:2px;}
@media (min-width: 768px) {
    .stat-value{font-size:32px;margin-bottom:4px;}
}
.stat-label{font-size:13px;color:#9aa4bf;}
.stat-desc{font-size:11px;color:#6b7280;margin-top:4px;}

/* Компактные графики */
.charts-compact{display:flex;flex-direction:column;gap:12px;margin-bottom:16px;}
@media (min-width: 480px) {
    .charts-compact{flex-direction:row;}
}
.chart-compact-card{flex:1;background:#262b38;border-radius:10px;padding:12px;border:1px solid #2e3545;}
@media (min-width: 768px) {
    .chart-compact-card{padding:16px;border-radius:12px;}
}
.chart-compact-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;}
.chart-compact-title{font-size:12px;color:#9aa4bf;font-weight:500;}
.chart-compact-value{font-size:16px;font-weight:600;color:#69c3ff;}
.chart-compact-container{height:50px;width:100%;}
@media (min-width: 768px) {
    .chart-compact-container{height:60px;}
}

.table-header{display:flex;flex-direction:column;gap:10px;margin-bottom:12px;}
@media (min-width: 480px) {
    .table-header{flex-direction:row;justify-content:space-between;align-items:center;}
}
.table-header .card-title{margin-bottom:0;}
.refresh-btn{padding:10px 16px;background:#2e3545;border:1px solid #3a4050;color:white;border-radius:8px;cursor:pointer;font-size:14px;display:inline-flex;align-items:center;gap:8px;justify-content:center;}
.refresh-btn i{font-style:normal;font-size:16px;}

/* Таблицы */
.table-responsive{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -16px;padding:0 16px;width:calc(100% + 32px);}
@media (min-width: 768px) {
    .table-responsive{margin:0;padding:0;width:100%;}
}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:600px;}
@media (min-width: 768px) {
    table{font-size:14px;}
}
th{text-align:left;padding:10px 6px;color:#9aa4bf;font-weight:500;border-bottom:1px solid #2e3545;white-space:nowrap;}
td{padding:10px 6px;border-bottom:1px solid #2a3040;white-space:nowrap;}
.badge{padding:3px 8px;border-radius:20px;font-size:11px;font-weight:500;display:inline-block;white-space:nowrap;}
@media (min-width: 768px) {
    .badge{padding:4px 10px;font-size:12px;}
}
.ok{background:#10b98120;color:#10b981;border:1px solid #10b98140;}
.blocked{background:#ef444420;color:#ef4444;border:1px solid #ef444440;}
.override{background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b40;}
.fail{background:#6b728020;color:#9aa4bf;border:1px solid #6b728040;}

.filter-bar{display:flex;flex-direction:column;gap:10px;margin-bottom:16px;}
@media (min-width: 480px) {
    .filter-bar{flex-direction:row;flex-wrap:wrap;}
}
.filter-bar input{flex:1;min-width:200px;padding:12px 14px;background:#262b38;border:1px solid #2e3545;color:white;border-radius:8px;font-size:14px;outline:none;-webkit-appearance:none;}
.filter-bar button{padding:12px 16px;background:#2e3545;border:1px solid #3a4050;color:white;border-radius:8px;cursor:pointer;font-size:14px;flex:1;}
@media (min-width: 480px) {
    .filter-bar button{flex:0 1 auto;}
}
.filter-bar button.primary{background:#69c3ff;color:#1b1f2b;border:none;font-weight:500;}

.loadmore{width:100%;padding:14px;background:#262b38;border:1px solid #2e3545;color:#9aa4bf;border-radius:8px;cursor:pointer;font-size:14px;margin-top:12px;}
@media (min-width: 768px) {
    .loadmore{padding:12px;margin-top:16px;}
}

/* Сетка для топ запросов */
.top-grid{display:grid;grid-template-columns:1fr;gap:16px;}
@media (min-width: 640px) {
    .top-grid{grid-template-columns:repeat(2,1fr);}
}
@media (min-width: 1024px) {
    .top-grid{grid-template-columns:repeat(4,1fr);}
}

.progress-item{margin-bottom:12px;}
.progress-header{display:flex;justify-content:space-between;margin-bottom:4px;font-size:12px;}
@media (min-width: 768px) {
    .progress-header{font-size:13px;margin-bottom:6px;}
}
.progress-bar{height:4px;background:#2e3545;border-radius:2px;overflow:hidden;}
@media (min-width: 768px) {
    .progress-bar{height:6px;border-radius:3px;}
}
.progress-fill{height:100%;border-radius:2px;transition:width 0.3s;}
@media (min-width: 768px) {
    .progress-fill{border-radius:3px;}
}
.domain-fill{background:#69c3ff;}
.client-fill{background:#f59e0b;}
.blocked-fill{background:#ef4444;}
.override-fill{background:#f59e0b;}
.empty-state{text-align:center;padding:30px 16px;color:#6b7280;font-size:14px;}

/* Стили для форм настроек */
.config-section{margin-bottom:24px;padding-bottom:24px;border-bottom:1px solid #2a3040;}
.config-section:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0;}
.config-label{display:block;margin-bottom:8px;color:#9aa4bf;font-weight:500;font-size:14px;}
.config-textarea{width:100%;padding:12px;background:#262b38;border:1px solid #2e3545;color:white;border-radius:8px;font-size:14px;font-family:'Inter',monospace;margin-bottom:8px;min-height:100px;}
.config-input{width:100%;padding:10px;background:#262b38;border:1px solid #2e3545;color:white;border-radius:6px;font-size:14px;margin-bottom:8px;}
.config-hint{color:#6b7280;font-size:12px;margin-bottom:12px;}
.config-checkbox{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.config-checkbox input{width:18px;height:18px;}
.save-btn{width:100%;padding:14px;background:#10b981;border:none;color:white;border-radius:8px;font-size:16px;font-weight:500;cursor:pointer;margin-top:20px;}
.save-btn:hover{background:#14cc8a;}
.success-message{background:#10b98120;color:#10b981;padding:12px;border-radius:8px;margin-bottom:16px;border:1px solid #10b98140;}
.error-message{background:#ef444420;color:#ef4444;padding:12px;border-radius:8px;margin-bottom:16px;border:1px solid #ef444440;}

.items-list{margin-top:10px;}
.config-item{display:flex;justify-content:space-between;align-items:center;background:#262b38;padding:8px 12px;border-radius:6px;margin-bottom:4px;border:1px solid #2e3545;}
.config-item-key{font-weight:500;color:#69c3ff;}
.config-item-value{color:#9aa4bf;}
.remove-item-btn{background:none;border:none;color:#ef4444;cursor:pointer;font-size:18px;padding:0 5px;}
.add-item-form{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;}
.add-item-form input{flex:1;min-width:150px;}
.add-item-btn{background:#2e3545;border:1px solid #3a4050;color:white;padding:8px 16px;border-radius:6px;cursor:pointer;}
</style>
<script>
let currentPage=0;
let refreshInterval = setInterval(loadLive, 5000);

function toggleMenu() {
    document.querySelector('.sidebar-nav').classList.toggle('show');
    document.querySelector('.sidebar-footer').classList.toggle('show');
}

function loadLogs(page=0){
    let search=document.getElementById('search_input') ? document.getElementById('search_input').value : '';
    fetch(`?ajax=logs&page=${page}&search=${encodeURIComponent(search)}`)
    .then(r=>r.json()).then(data=>{
        let tbody=document.getElementById('logs_tbody');
        if(page==0) tbody.innerHTML='';
        if(data.length===0 && page===0){
            tbody.innerHTML='<tr><td colspan="6" class="empty-state">Нет записей</td></tr>';
        }else{
            data.forEach(r=>{
                let tr=document.createElement('tr');
                let time = new Date(r.time*1000);
                let timeStr = time.toLocaleDateString() + ' ' + time.toLocaleTimeString();
                let statusClass = r.status=='ok'?'ok':r.status=='blocked'?'blocked':r.status=='override'?'override':'fail';
                let statusText = r.status=='ok'?'Успешно':r.status=='blocked'?'Заблокировано':r.status=='override'?'Перенаправлено':'Ошибка';
                tr.innerHTML=`<td>${timeStr}</td>
<td>${r.domain}</td><td>${r.qtype}</td>
<td><span class="badge ${statusClass}">${statusText}</span></td>
<td>${r.client_ip}</td>
<td>${r.duration ? r.duration + 'ms' : '-'}</td>`;
                tbody.appendChild(tr);
            });
        }
        document.getElementById('loadmore_btn').style.display = data.length==<?php echo $LOGS_PER_PAGE ?>?'block':'none';
    });
}

function loadMore(){currentPage++; loadLogs(currentPage);}

function loadLive(){
    fetch('?ajax').then(r=>r.json()).then(data=>{
        let tbody=document.getElementById('live_tbody');
        if (!tbody) return;
        tbody.innerHTML='';
        if(data.length===0){
            tbody.innerHTML='<tr><td colspan="6" class="empty-state">Нет активных запросов</td></tr>';
        }else{
            data.slice(0,20).forEach(r=>{
                let tr=document.createElement('tr');
                let time = new Date(r.time*1000);
                let statusClass = r.status=='ok'?'ok':r.status=='blocked'?'blocked':r.status=='override'?'override':'fail';
                let statusText = r.status=='ok'?'Успешно':r.status=='blocked'?'Заблокировано':r.status=='override'?'Перенаправлено':'Ошибка';
                tr.innerHTML=`<td>${time.toLocaleTimeString()}</td>
<td>${r.domain}</td><td>${r.qtype}</td>
<td><span class="badge ${statusClass}">${statusText}</span></td>
<td>${r.client_ip}</td>
<td>${r.duration ? r.duration + 'ms' : '-'}</td>`;
                tbody.appendChild(tr);
            });
        }
    });
}

function toggleAutoRefresh(btn) {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
        btn.innerHTML = '<i>🔴</i> Автообновление выкл';
        btn.style.background = '#2e3545';
    } else {
        refreshInterval = setInterval(loadLive, 5000);
        btn.innerHTML = '<i>🟢</i> Автообновление вкл';
        btn.style.background = '#3a4050';
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const navLinks = document.querySelectorAll('.sidebar-nav a, .sidebar-footer a');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (window.innerWidth < 768) {
                document.querySelector('.sidebar-nav').classList.remove('show');
                document.querySelector('.sidebar-footer').classList.remove('show');
            }
        });
    });
});
</script>
</head>
<body>
<div class="sidebar">
    <div class="sidebar-header">
        <h2>DoH Analytics</h2>
        <button class="menu-toggle" onclick="toggleMenu()">☰</button>
    </div>
    <div class="sidebar-nav">
        <a href="?tab=dashboard" class="<?php if($tab=="dashboard") echo 'active'; ?>"><i>📊</i>Дашборд</a>
        <a href="?tab=live" class="<?php if($tab=="live") echo 'active'; ?>"><i>🔄</i>Живые запросы</a>
        <a href="?tab=log" class="<?php if($tab=="log") echo 'active'; ?>"><i>📝</i>Журнал запросов</a>
        <a href="?tab=top" class="<?php if($tab=="top") echo 'active'; ?>"><i>🔥</i>Топ запросов</a>
        <a href="?tab=settings" class="<?php if($tab=="settings") echo 'active'; ?>"><i>⚙️</i>Настройки</a>
    </div>
    <div class="sidebar-footer">
        <a href="?logout=1"><i>🚪</i>Выйти</a>
    </div>
</div>
<div class="main">

<?php if($tab=="dashboard"): ?>
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value"><?php echo number_format($total_queries, 0, '.', ' '); ?></div>
            <div class="stat-label">Всего запросов</div>
            <div class="stat-desc">за все время</div>
        </div>
        <div class="stat-card">
            <div class="stat-value"><?php echo number_format($blocked_queries, 0, '.', ' '); ?></div>
            <div class="stat-label">Заблокировано</div>
            <div class="stat-desc"><?php echo $total_queries > 0 ? round(($blocked_queries/$total_queries)*100, 1) : 0; ?>% от общего числа</div>
        </div>
        <div class="stat-card">
            <div class="stat-value"><?php echo round($avg_time, 1); ?>ms</div>
            <div class="stat-label">Среднее время</div>
            <div class="stat-desc">обработки запроса</div>
        </div>
    </div>

    <!-- Компактные графики -->
    <div class="charts-compact">
        <div class="chart-compact-card">
            <div class="chart-compact-header">
                <span class="chart-compact-title">Запросов в минуту</span>
                <span class="chart-compact-value"><?php echo end($qps_data)['c'] ?? 0; ?>/min</span>
            </div>
            <div class="chart-compact-container">
                <canvas id="compactQpsChart" style="height:100%;width:100%;"></canvas>
            </div>
        </div>
        <div class="chart-compact-card">
            <div class="chart-compact-header">
                <span class="chart-compact-title">Заблокировано в минуту</span>
                <span class="chart-compact-value"><?php echo end($block_data)['c'] ?? 0; ?>/min</span>
            </div>
            <div class="chart-compact-container">
                <canvas id="compactBlockChart" style="height:100%;width:100%;"></canvas>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="table-header">
            <div class="card-title">Последние запросы</div>
            <button class="refresh-btn" onclick="loadLive()"><i>⟳</i> Обновить</button>
        </div>
        <div class="table-responsive">
            <table>
                <thead><tr><th>Время</th><th>Домен</th><th>Тип</th><th>Статус</th><th>Клиент</th><th>Время</th></tr></thead>
                <tbody id="live_tbody"></tbody>
            </table>
        </div>
    </div>

    <script>
    const qpsLabels = [<?php foreach($qps_data as $r) echo "'".$r['t']."',";?>];
    const qpsValues = [<?php foreach($qps_data as $r) echo $r['c'].",";?>];
    const blockValues = [<?php foreach($block_data as $r) echo $r['c'].",";?>];

    new Chart(document.getElementById('compactQpsChart'), {
        type: 'line',
        data: {
            labels: qpsLabels,
            datasets: [{
                data: qpsValues,
                borderColor: '#69c3ff',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 3,
                tension: 0.4,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { enabled: true } },
            scales: { x: { display: false }, y: { display: false, beginAtZero: true } }
        }
    });

    new Chart(document.getElementById('compactBlockChart'), {
        type: 'line',
        data: {
            labels: qpsLabels,
            datasets: [{
                data: blockValues,
                borderColor: '#ef4444',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 3,
                tension: 0.4,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { enabled: true } },
            scales: { x: { display: false }, y: { display: false, beginAtZero: true } }
        }
    });

    loadLive();
    </script>
<?php endif; ?>

<?php if($tab=="live"): ?>
<div class="card">
    <div class="table-header">
        <div class="card-title">Живые запросы</div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button class="refresh-btn" onclick="loadLive()"><i>⟳</i> Обновить</button>
            <button class="refresh-btn" onclick="toggleAutoRefresh(this)" style="background:#3a4050;"><i>🟢</i> Авто</button>
        </div>
    </div>
    <div class="table-responsive">
        <table>
            <thead><tr><th>Время</th><th>Домен</th><th>Тип</th><th>Статус</th><th>Клиент</th><th>Время</th></tr></thead>
            <tbody id="live_tbody"></tbody>
        </table>
    </div>
</div>
<script>loadLive();</script>
<?php endif; ?>

<?php if($tab=="log"): ?>
<div class="card">
    <div class="filter-bar">
        <input id="search_input" placeholder="Поиск по домену или IP...">
        <button class="primary" onclick="currentPage=0; loadLogs()">Поиск</button>
        <button onclick="document.getElementById('search_input').value=''; currentPage=0; loadLogs()">Сброс</button>
        <button onclick="currentPage=0; loadLogs()">⟳</button>
    </div>
</div>
<div class="card">
    <div class="table-responsive">
        <table>
            <thead><tr><th>Время</th><th>Домен</th><th>Тип</th><th>Статус</th><th>Клиент</th><th>Время</th></tr></thead>
            <tbody id="logs_tbody"></tbody>
        </table>
    </div>
    <button id="loadmore_btn" class="loadmore" onclick="loadMore()">Загрузить еще</button>
</div>
<script>loadLogs();</script>
<?php endif; ?>

<?php if($tab=="top"): ?>
<div class="top-grid">

    <!-- Топ клиентов (все запросы) -->
    <div class="card">
        <div class="card-title">Топ клиентов</div>
        <?php 
        $max_client = 0;
        $clients_list = [];
        while($r=$top_clients->fetchArray(SQLITE3_ASSOC)) { 
            $clients_list[] = $r;
            if($r['c'] > $max_client) $max_client = $r['c'];
        }
        if(empty($clients_list)): ?>
            <div class="empty-state">Нет данных</div>
        <?php else: ?>
            <?php foreach($clients_list as $r): 
                $width = $max_client > 0 ? ($r['c'] / $max_client) * 100 : 0;
            ?>
            <div class="progress-item">
                <div class="progress-header">
                    <span><?php echo htmlspecialchars($r['client_ip']); ?></span>
                    <span><?php echo $r['c']; ?></span>
                </div>
                <div class="progress-bar"><div class="progress-fill client-fill" style="width:<?php echo $width; ?>%"></div></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Топ успешных доменов (только успешные запросы) -->
    <div class="card">
        <div class="card-title">Топ доменов (успешно)</div>
        <?php 
        $max_domain = 0;
        $domains_list = [];
        while($r=$top_domains->fetchArray(SQLITE3_ASSOC)) { 
            $domains_list[] = $r;
            if($r['c'] > $max_domain) $max_domain = $r['c'];
        }
        if(empty($domains_list)): ?>
            <div class="empty-state">Нет данных</div>
        <?php else: ?>
            <?php foreach($domains_list as $r): 
                $width = $max_domain > 0 ? ($r['c'] / $max_domain) * 100 : 0;
            ?>
            <div class="progress-item">
                <div class="progress-header">
                    <span><?php echo htmlspecialchars($r['domain']); ?></span>
                    <span><?php echo $r['c']; ?></span>
                </div>
                <div class="progress-bar"><div class="progress-fill domain-fill" style="width:<?php echo $width; ?>%"></div></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Топ заблокированных доменов -->
    <div class="card">
        <div class="card-title">Топ заблокированных</div>
        <?php 
        $max_blocked = 0;
        $blocked_list = [];
        while($r=$top_blocked_domains->fetchArray(SQLITE3_ASSOC)) { 
            $blocked_list[] = $r;
            if($r['c'] > $max_blocked) $max_blocked = $r['c'];
        }
        if(empty($blocked_list)): ?>
            <div class="empty-state">Нет заблокированных</div>
        <?php else: ?>
            <?php foreach($blocked_list as $r): 
                $width = $max_blocked > 0 ? ($r['c'] / $max_blocked) * 100 : 0;
            ?>
            <div class="progress-item">
                <div class="progress-header">
                    <span><?php echo htmlspecialchars($r['domain']); ?></span>
                    <span><?php echo $r['c']; ?></span>
                </div>
                <div class="progress-bar"><div class="progress-fill blocked-fill" style="width:<?php echo $width; ?>%"></div></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Топ перенаправленных доменов -->
    <div class="card">
        <div class="card-title">Топ перенаправленных</div>
        <?php 
        $max_override = 0;
        $override_list = [];
        while($r=$top_override_domains->fetchArray(SQLITE3_ASSOC)) { 
            $override_list[] = $r;
            if($r['c'] > $max_override) $max_override = $r['c'];
        }
        if(empty($override_list)): ?>
            <div class="empty-state">Нет перенаправленных</div>
        <?php else: ?>
            <?php foreach($override_list as $r): 
                $width = $max_override > 0 ? ($r['c'] / $max_override) * 100 : 0;
            ?>
            <div class="progress-item">
                <div class="progress-header">
                    <span><?php echo htmlspecialchars($r['domain']); ?></span>
                    <span><?php echo $r['c']; ?></span>
                </div>
                <div class="progress-bar"><div class="progress-fill override-fill" style="width:<?php echo $width; ?>%"></div></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<?php if($tab=="settings"): ?>

<?php if($config_saved): ?>
<div class="success-message">✓ Настройки успешно сохранены</div>
<?php endif; ?>

<?php if($config_error): ?>
<div class="error-message">✗ <?php echo htmlspecialchars($config_error); ?></div>
<?php endif; ?>

<!-- Настройки dquery.php -->
<div class="card">
    <div class="card-title">Настройки DNS сервера</div>
    
    <form method="post">
        <div class="config-section">
            <label class="config-label">Анонимный режим</label>
            <div class="config-checkbox">
                <input type="checkbox" name="anonim" <?php echo $dquery_config['anonim'] ? 'checked' : ''; ?>>
                <span>Не писать логи (режим анонимности)</span>
            </div>
        </div>

        <div class="config-section">
            <label class="config-label">Белый список IP (по одному на строку)</label>
            <textarea name="allowed_ips" class="config-textarea" placeholder="127.0.0.1"><?php echo htmlspecialchars(implode("\n", $dquery_config['ALLOWED_IPS'])); ?></textarea>
            <div class="config-hint">Если список не пуст, доступ будет только с этих IP</div>
        </div>

        <div class="config-section">
            <label class="config-label">Черный список IP (по одному на строку)</label>
            <textarea name="blocked_ips" class="config-textarea" placeholder="1.2.3.4"><?php echo htmlspecialchars(implode("\n", $dquery_config['BLOCKED_IPS'])); ?></textarea>
            <div class="config-hint">Запросы с этих IP будут отклоняться</div>
        </div>

        <div class="config-section">
            <label class="config-label">Upstream DNS серверы (по умолчанию)</label>
            <textarea name="default_upstreams" class="config-textarea" placeholder="https://dns.quad9.net/dns-query"><?php echo htmlspecialchars(implode("\n", $dquery_config['default_upstreams'])); ?></textarea>
            <div class="config-hint">DoH серверы для проксирования запросов</div>
        </div>

        <div class="config-section">
            <label class="config-label">Фильтры рекламы (URL, по одному на строку)</label>
            <textarea name="filter_lists" class="config-textarea" placeholder="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"><?php echo htmlspecialchars(implode("\n", $dquery_config['filter_lists'])); ?></textarea>
        </div>

        <div class="config-section">
            <div style="display:flex; gap:16px; flex-wrap:wrap;">
                <div style="flex:1;">
                    <label class="config-label">TTL кеша фильтров (сек)</label>
                    <input type="number" name="filter_cache_ttl" class="config-input" value="<?php echo $dquery_config['filter_cache_ttl']; ?>">
                </div>
                <div style="flex:1;">
                    <label class="config-label">TTL кеша DNS (сек)</label>
                    <input type="number" name="cache_ttl" class="config-input" value="<?php echo $dquery_config['cache_ttl']; ?>">
                </div>
            </div>
        </div>

        <div class="config-section">
            <label class="config-label">Маршрутизация доменов (формат: домен=upstream)</label>
            <textarea name="domain_upstreams" class="config-textarea" placeholder="google.com=https://8.8.4.4/dns-query
*.example.com=https://custom.dns/dns-query"><?php 
                $domain_lines = [];
                foreach ($dquery_config['domain_upstreams'] as $domain => $upstreams) {
                    if (!empty($upstreams)) {
                        $domain_lines[] = $domain . '=' . $upstreams[0];
                    }
                }
                // Сортируем для удобства
                sort($domain_lines);
                echo htmlspecialchars(implode("\n", $domain_lines));
            ?></textarea>
            <div class="config-hint">По одному правилу на строку: домен=upstream_сервер. Можно использовать *.wildcard.com</div>
        </div>

        <div class="config-section">
            <label class="config-label">Переопределение DNS (формат: домен=IP)</label>
            <textarea name="dns_overrides" class="config-textarea" placeholder="example.com=1.2.3.4
*.example.com=1.2.3.5"><?php 
                $override_lines = [];
                foreach ($dquery_config['dns_overrides'] as $domain => $ip) {
                    $override_lines[] = $domain . '=' . $ip;
                }
                // Сортируем для удобства
                sort($override_lines);
                echo htmlspecialchars(implode("\n", $override_lines));
            ?></textarea>
            <div class="config-hint">Принудительный ответ указанным IP для домена. Можно использовать *.wildcard.com</div>
        </div>

        <button type="submit" name="save_config" class="save-btn">💾 Сохранить все настройки</button>
    </form>
</div>

<!-- Очистка логов -->
<div class="card">
    <div class="card-title">Обслуживание</div>
    <div style="background:#262b38;border-radius:8px;padding:16px;border:1px solid #2e3545;">
        <p style="margin-bottom:16px;color:#9aa4bf;font-size:14px;">Очистка журнала запросов удалит все сохраненные данные. Это действие нельзя отменить.</p>
        <form method=post onsubmit="return confirm('Вы уверены?');">
            <button name="clear" style="width:100%;background:#ef4444;color:white;border:none;padding:12px 20px;border-radius:8px;cursor:pointer;font-size:16px;">🗑️ Очистить журнал</button>
        </form>
    </div>
</div>

<?php endif; ?>

</div>
</body>
</html>
