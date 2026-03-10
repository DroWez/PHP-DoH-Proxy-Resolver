<?php
/*
=====================================
ANONYM MODE
=====================================
*/

$anonim = false; // true = не писать логи

/*
=====================================
IP WhiteList
=====================================
*/
$ALLOWED_IPS = [
];

/*
=====================================
IP BlackList
=====================================
*/
$BLOCKED_IPS = [
];

/*
=====================================
IP LOGIC
=====================================
*/
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '';

/* ===== Проверка blacklist ===== */
if (!empty($BLOCKED_IPS) && in_array($client_ip, $BLOCKED_IPS)) {
    http_response_code(403);
    exit;
}

/* ===== Проверка whitelist ===== */
if (!empty($ALLOWED_IPS) && !in_array($client_ip, $ALLOWED_IPS)) {
    http_response_code(403);
    exit;
}

/*

=====================================
UPSTREAM DNS
=====================================
*/

$default_upstreams = [
    "https://dns.quad9.net/dns-query",
    "https://dns10.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query",
];

/*
=====================================
DOMAIN ROUTING
=====================================
*/

$domain_upstreams = [
];

/*
=====================================
DNS OVERRIDE
=====================================
*/

$dns_overrides = [
    "example.com" => "1.2.3.5",
];

/*
=====================================
ADBLOCK FILTER
=====================================
*/

$filter_lists = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
];

$filter_cache_file = __DIR__."/filters.cache";
$filter_cache_ttl = 3600;

/*
=====================================
CACHE TTL
=====================================
*/

$cache_ttl = 600;

/*
=====================================
SQLITE LOGGING
=====================================
*/

$sqlite_file = __DIR__."/dns_logs.sqlite";

function sqlite_db(){

    global $sqlite_file, $anonim;

    if($anonim) return null;

    static $db=null;

    if($db===null){

        $db = new SQLite3($sqlite_file);

        $db->exec("
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time INTEGER,
            domain TEXT,
            qtype TEXT,
            method TEXT,
            status TEXT,
            duration REAL,
            client_ip TEXT,
            client_rdns TEXT
        )
        ");
    }

    return $db;
}

function log_dns($domain,$qtype,$status,$duration){

    global $anonim;

    if($anonim) return;

    $db = sqlite_db();

    if(!$db) return;

    $ip = $_SERVER['REMOTE_ADDR'] ?? "";

    $rdns = @gethostbyaddr($ip);
    if($rdns==$ip) $rdns="";

    $stmt = $db->prepare("
        INSERT INTO logs
        (time,domain,qtype,method,status,duration,client_ip,client_rdns)
        VALUES
        (:time,:domain,:qtype,'DNS-over-HTTPS',:status,:duration,:ip,:rdns)
    ");

    $stmt->bindValue(":time",time(),SQLITE3_INTEGER);
    $stmt->bindValue(":domain",$domain);
    $stmt->bindValue(":qtype",$qtype);
    $stmt->bindValue(":status",$status);
    $stmt->bindValue(":duration",$duration);
    $stmt->bindValue(":ip",$ip);
    $stmt->bindValue(":rdns",$rdns);

    $stmt->execute();
}
/*
=====================================
UTILS
=====================================
*/

function now_ms(){
    return (int)round(microtime(true)*1000);
}

function error_json($code,$message){

    http_response_code($code);

    header("Content-Type: application/json");

    echo json_encode([
        "error"=>[
            "timestamp"=>now_ms(),
            "code"=>$code,
            "message"=>$message
        ]
    ]);

    exit();
}

/*
=====================================
LOAD FILTERS
=====================================
*/

function load_filters($lists,$cache_file,$ttl){

    if(file_exists($cache_file) && (time()-filemtime($cache_file)<$ttl)){

        return json_decode(file_get_contents($cache_file),true);
    }

    $domains=[];

    foreach($lists as $url){

        $txt=@file_get_contents($url);

        if(!$txt) continue;

        $lines=explode("
",$txt);

        foreach($lines as $line){

            $line=trim($line);

            if($line=="" || $line[0]=="!" || $line[0]=="#") continue;

            if(preg_match('/^\|\|([a-z0-9\.-]+)\^/i',$line,$m)){
                $domains[$m[1]]=1;
                continue;
            }

            if(preg_match('/^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9\.-]+)/i',$line,$m)){
                $domains[$m[2]]=1;
                continue;
            }

            if(preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i',$line)){
                $domains[$line]=1;
            }
        }
    }

    $list=array_keys($domains);

    file_put_contents($cache_file,json_encode($list));

    return $list;
}

/*
=====================================
CHECK BLOCK
=====================================
*/

function domain_blocked($domain,$filters){

    foreach($filters as $f){

        if($domain==$f) return true;

        if(str_ends_with($domain,".".$f)) return true;
    }

    return false;
}

/*
=====================================
PARSE DOMAIN
=====================================
*/

function parse_dns_query_domain($data){

    if(strlen($data)<12) return null;

    $offset=12;
    $labels=[];

    while($offset<strlen($data)){

        $l=ord($data[$offset]);

        if($l===0) break;

        $offset++;

        $labels[]=substr($data,$offset,$l);

        $offset+=$l;
    }

    return strtolower(implode(".",$labels));
}

/*
=====================================
PARSE QTYPE
=====================================
*/

function parse_dns_qtype($data){

    if(strlen($data)<12) return "UNKNOWN";

    $offset=12;

    while($offset<strlen($data)){

        $l=ord($data[$offset]);

        if($l===0) break;

        $offset += $l+1;
    }

    $offset++;

    $type=unpack("n",substr($data,$offset,2))[1];

    $map=[
        1=>"A",
        28=>"AAAA",
        15=>"MX",
        16=>"TXT",
        5=>"CNAME",
        2=>"NS"
    ];

    return $map[$type] ?? $type;
}

/*
=====================================
DOMAIN ROUTING
=====================================
*/

function match_domain_upstreams($domain,$domain_upstreams){

    foreach($domain_upstreams as $zone=>$ups){

        if($domain==$zone || str_ends_with($domain,".".$zone)){

            return $ups;
        }
    }

    return null;
}

/*
=====================================
BUILD RESPONSE
=====================================
*/

function build_dns_response($query,$ip){

    $id=substr($query,0,2);

    $header =
        $id .
        "\x81\x80" .
        "\x00\x01" .
        "\x00\x01" .
        "\x00\x00" .
        "\x00\x00";

    $question = substr($query,12);

    $answer =
        "\xc0\x0c".
        "\x00\x01".
        "\x00\x01".
        pack("N",60).
        "\x00\x04".
        inet_pton($ip);

    return $header.$question.$answer;
}

/*
=====================================
REQUEST BODY
=====================================
*/

$start_time=microtime(true);

$method=$_SERVER["REQUEST_METHOD"] ?? "POST";

if($method==="GET"){

    if(empty($_GET['dns'])) error_json(400,"GET must include dns param");

    $body=base64_decode(strtr($_GET['dns'],'-_','+/'));

}else{

    $body=file_get_contents("php://input");
}

if(!$body) error_json(400,"Empty DNS query");

/*
=====================================
PARSE DOMAIN
=====================================
*/

$domain=parse_dns_query_domain($body);

$qtype=parse_dns_qtype($body);

/*
=====================================
LOAD FILTERS
=====================================
*/

$filters=load_filters($filter_lists,$filter_cache_file,$filter_cache_ttl);

/*
=====================================
BLOCK
=====================================
*/

if($domain && domain_blocked($domain,$filters)){

    $duration=round((microtime(true)-$start_time)*1000,2);

    log_dns($domain,$qtype,"blocked",$duration);

    header("Content-Type: application/dns-message");

    echo build_dns_response($body,"0.0.0.0");

    exit();
}

/*
=====================================
OVERRIDE
=====================================
*/

if($domain && isset($dns_overrides[$domain])){

    $duration=round((microtime(true)-$start_time)*1000,2);

    log_dns($domain,$qtype,"override",$duration);

    header("Content-Type: application/dns-message");

    echo build_dns_response($body,$dns_overrides[$domain]);

    exit();
}

/*
=====================================
UPSTREAM
=====================================
*/

$upstreams=match_domain_upstreams($domain,$domain_upstreams);

if(!$upstreams) $upstreams=$default_upstreams;

/*
=====================================
CACHE
=====================================
*/

$cache_key="doh_".md5($domain.":".$body);

if(function_exists("apcu_fetch")){

    $cached=apcu_fetch($cache_key);

    if($cached!==false){

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

$mh=curl_multi_init();

$chs=[];

foreach($upstreams as $up){

    $ch=curl_init($up);

    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_HTTPHEADER=>[
            "Content-Type: application/dns-message",
            "Accept: application/dns-message"
        ],
        CURLOPT_POST=>true,
        CURLOPT_POSTFIELDS=>$body,
        CURLOPT_TIMEOUT=>4
    ]);

    curl_multi_add_handle($mh,$ch);

    $chs[]=$ch;
}

$running=null;

do{

    curl_multi_exec($mh,$running);

    curl_multi_select($mh);

    while($info=curl_multi_info_read($mh)){

        $ch=$info['handle'];

        if($info['result']===CURLE_OK &&
           curl_getinfo($ch,CURLINFO_HTTP_CODE)===200){

            $resp=curl_multi_getcontent($ch);

            if(function_exists("apcu_store")){
                apcu_store($cache_key,$resp,$cache_ttl);
            }

            $duration=round((microtime(true)-$start_time)*1000,2);

            log_dns($domain,$qtype,"ok",$duration);

            header("Content-Type: application/dns-message");

            echo $resp;

            curl_multi_close($mh);

            exit();
        }
    }

}while($running);

curl_multi_close($mh);

$duration=round((microtime(true)-$start_time)*1000,2);

log_dns($domain,$qtype,"fail",$duration);

error_json(502,"All upstream DoH failed");
?>
