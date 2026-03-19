<?php
/**
 * WP DB Debug Tool
 * Single-file WordPress database inspector.
 * Drop into any WordPress directory and visit in browser.
 *
 * Auto-detects database credentials via:
 *   1. wp-load.php → uses $wpdb
 *   2. wp-config.php → parses defines, uses $wpdb or raw connection
 *   3. Raw credential extraction from wp-config.php → mysqli/mysql
 *   4. Manual entry fallback
 */

// ─── Safety: only run in browser context ───
if (php_sapi_name() === 'cli') {
    die("This tool is meant to be accessed via a web browser.\n");
}

// ─── Helper: safe string truncation (mbstring may not be available) ───
function _dbdebug_truncate($str, $max = 300) {
    if (function_exists('mb_strimwidth')) {
        return mb_strimwidth($str, 0, $max, '...');
    }
    if (strlen($str) > $max) {
        return substr($str, 0, $max) . '...';
    }
    return $str;
}

// ─── Session for persisting manual creds across requests ───
session_start();

// ─── Environment info ───
$php_version    = phpversion();
$has_mysqli     = function_exists('mysqli_connect');
$has_mysql      = function_exists('mysql_connect');
$has_pdo_mysql  = class_exists('PDO') && in_array('mysql', PDO::getAvailableDrivers());
$server_software = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown';

// ─── Connection state ───
$connection       = null;   // The usable connection resource/object
$connection_type  = null;   // 'wpdb', 'mysqli', 'pdo', 'mysql'
$connection_method = null;  // Human-readable how we connected
$connection_error = null;
$wpdb_available   = false;

// ─── Common relative paths to try ───
function get_candidate_paths($filename) {
    $base = dirname(__FILE__);
    $candidates = array(
        $base . '/' . $filename,
        $base . '/../' . $filename,
        $base . '/../../' . $filename,
        $base . '/../../../' . $filename,
        $base . '/wp/' . $filename,
        $base . '/../wp/' . $filename,
        $base . '/wordpress/' . $filename,
        $base . '/../wordpress/' . $filename,
        $base . '/public_html/' . $filename,
        $base . '/../public_html/' . $filename,
        $base . '/htdocs/' . $filename,
        $base . '/../htdocs/' . $filename,
        $base . '/public/' . $filename,
        $base . '/../public/' . $filename,
        $base . '/web/' . $filename,
        $base . '/../web/' . $filename,
    );
    // Also check DOCUMENT_ROOT based paths
    if (!empty($_SERVER['DOCUMENT_ROOT'])) {
        $dr = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
        $candidates[] = $dr . '/' . $filename;
        $candidates[] = $dr . '/wp/' . $filename;
        $candidates[] = $dr . '/wordpress/' . $filename;
        $candidates[] = dirname($dr) . '/' . $filename;
    }
    // Deduplicate via realpath-safe comparison
    $seen = array();
    $unique = array();
    foreach ($candidates as $c) {
        $resolved = realpath($c);
        if ($resolved && !isset($seen[$resolved])) {
            $seen[$resolved] = true;
            $unique[] = $resolved;
        } elseif (!$resolved) {
            // File doesn't exist yet, skip
        }
    }
    return $unique;
}

/**
 * Extract DB defines from wp-config.php without executing it.
 */
function parse_wp_config($path) {
    $content = file_get_contents($path);
    if ($content === false) return null;

    $defines = array();
    $keys = array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_CHARSET', 'DB_COLLATE');
    foreach ($keys as $key) {
        // Match define('DB_NAME', 'value') with single or double quotes
        if (preg_match("/define\s*\(\s*['\"]" . preg_quote($key) . "['\"]\s*,\s*['\"](.*)['\"]\s*\)/U", $content, $m)) {
            $defines[$key] = $m[1];
        }
    }
    // Also grab $table_prefix
    if (preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]\s*;/', $content, $m)) {
        $defines['table_prefix'] = $m[1];
    } else {
        $defines['table_prefix'] = 'wp_';
    }

    if (empty($defines['DB_NAME']) || empty($defines['DB_USER'])) {
        return null;
    }
    return $defines;
}

/**
 * Parse DB_HOST into host and port (WordPress supports host:port and host:/path/to/socket).
 */
function parse_db_host($raw) {
    $host = $raw;
    $port = 3306;
    $socket = null;

    if (strpos($raw, ':') !== false) {
        list($h, $rest) = explode(':', $raw, 2);
        $host = $h;
        if ($rest[0] === '/') {
            $socket = $rest;
        } else {
            $port = (int) $rest;
        }
    }
    return array($host, $port, $socket);
}

/**
 * Try creating a raw DB connection with given credentials.
 * Returns [connection, type] or [null, null].
 */
function try_raw_connect($db_host, $db_user, $db_pass, $db_name) {
    global $has_mysqli, $has_pdo_mysql, $has_mysql;

    list($host, $port, $socket) = parse_db_host($db_host);

    // Prefer mysqli
    if ($has_mysqli) {
        $conn = @mysqli_connect($host, $db_user, $db_pass, $db_name, $port, $socket);
        if ($conn && !mysqli_connect_error()) {
            @mysqli_set_charset($conn, 'utf8mb4');
            return array($conn, 'mysqli');
        }
    }

    // Try PDO
    if ($has_pdo_mysql) {
        try {
            $dsn = "mysql:host={$host};port={$port};dbname={$db_name};charset=utf8mb4";
            if ($socket) {
                $dsn = "mysql:unix_socket={$socket};dbname={$db_name};charset=utf8mb4";
            }
            $pdo = new PDO($dsn, $db_user, $db_pass, array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ));
            return array($pdo, 'pdo');
        } catch (Exception $e) {
            // Fall through
        }
    }

    // Legacy mysql_
    if ($has_mysql) {
        $server = $socket ? "{$host}:{$socket}" : "{$host}:{$port}";
        $conn = @mysql_connect($server, $db_user, $db_pass);
        if ($conn) {
            if (@mysql_select_db($db_name, $conn)) {
                @mysql_set_charset('utf8mb4', $conn);
                return array($conn, 'mysql');
            }
        }
    }

    return array(null, null);
}

/**
 * Execute a query on whatever connection we have.
 * Returns ['columns' => [...], 'rows' => [...], 'affected' => int, 'error' => string|null, 'time' => float]
 */
function run_query($sql) {
    global $connection, $connection_type;

    $start = microtime(true);
    $result = array('columns' => array(), 'rows' => array(), 'affected' => 0, 'error' => null, 'time' => 0, 'insert_id' => null);

    try {
        if ($connection_type === 'wpdb') {
            /** @var wpdb $connection */
            $connection->suppress_errors(true);
            $connection->show_errors(false);

            $sql_trimmed = strtoupper(trim(preg_replace('/\s+/', ' ', $sql)));
            $is_select = (strpos($sql_trimmed, 'SELECT') === 0 || strpos($sql_trimmed, 'SHOW') === 0
                          || strpos($sql_trimmed, 'DESCRIBE') === 0 || strpos($sql_trimmed, 'DESC ') === 0
                          || strpos($sql_trimmed, 'EXPLAIN') === 0);

            if ($is_select) {
                $rows = $connection->get_results($sql, ARRAY_A);
                if ($connection->last_error) {
                    $result['error'] = $connection->last_error;
                } else {
                    $result['rows'] = $rows ? $rows : array();
                    if (!empty($result['rows'])) {
                        $result['columns'] = array_keys($result['rows'][0]);
                    }
                }
            } else {
                $res = $connection->query($sql);
                if ($connection->last_error) {
                    $result['error'] = $connection->last_error;
                } else {
                    $result['affected'] = (int) $connection->rows_affected;
                    $result['insert_id'] = $connection->insert_id;
                }
            }
        } elseif ($connection_type === 'mysqli') {
            $res = @mysqli_query($connection, $sql);
            if ($res === false) {
                $result['error'] = mysqli_error($connection);
            } elseif ($res === true) {
                $result['affected'] = mysqli_affected_rows($connection);
                $result['insert_id'] = mysqli_insert_id($connection);
            } else {
                $fields = mysqli_fetch_fields($res);
                foreach ($fields as $f) {
                    $result['columns'][] = $f->name;
                }
                while ($row = mysqli_fetch_assoc($res)) {
                    $result['rows'][] = $row;
                }
                mysqli_free_result($res);
            }
        } elseif ($connection_type === 'pdo') {
            /** @var PDO $connection */
            $stmt = $connection->prepare($sql);
            $stmt->execute();
            if ($stmt->columnCount() > 0) {
                $result['rows'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
                if (!empty($result['rows'])) {
                    $result['columns'] = array_keys($result['rows'][0]);
                }
            } else {
                $result['affected'] = $stmt->rowCount();
                $result['insert_id'] = $connection->lastInsertId();
            }
        } elseif ($connection_type === 'mysql') {
            $res = @mysql_query($sql, $connection);
            if ($res === false) {
                $result['error'] = mysql_error($connection);
            } elseif ($res === true) {
                $result['affected'] = mysql_affected_rows($connection);
                $result['insert_id'] = mysql_insert_id($connection);
            } else {
                $n = mysql_num_fields($res);
                for ($i = 0; $i < $n; $i++) {
                    $result['columns'][] = mysql_field_name($res, $i);
                }
                while ($row = mysql_fetch_assoc($res)) {
                    $result['rows'][] = $row;
                }
                mysql_free_result($res);
            }
        }
    } catch (Exception $e) {
        $result['error'] = $e->getMessage();
    }

    $result['time'] = round((microtime(true) - $start) * 1000, 2);
    return $result;
}

// ═══════════════════════════════════════════════════════════════
// CONNECTION STRATEGY
// ═══════════════════════════════════════════════════════════════

$tried_methods = array();
$manual_mode = isset($_POST['manual_connect']);
$disconnect = isset($_GET['disconnect']);

if ($disconnect) {
    unset($_SESSION['wpdbdebug_manual']);
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

if (!$manual_mode) {

    // ── Strategy 1: wp-load.php (full WordPress bootstrap) ──
    $wp_load_paths = get_candidate_paths('wp-load.php');
    foreach ($wp_load_paths as $path) {
        $tried_methods[] = "wp-load.php → {$path}";
        try {
            // Prevent redirects and theme output
            define('ABSPATH', dirname($path) . '/');
            define('WPINC', 'wp-includes');
            // Buffer any output WP might produce
            ob_start();
            // Suppress errors during load
            $old_level = error_reporting(0);
            @require_once $path;
            error_reporting($old_level);
            ob_end_clean();

            if (isset($GLOBALS['wpdb']) && is_object($GLOBALS['wpdb']) && !empty($GLOBALS['wpdb']->dbh)) {
                $connection = $GLOBALS['wpdb'];
                $connection_type = 'wpdb';
                $connection_method = "wp-load.php → \$wpdb";
                $wpdb_available = true;
                break;
            }
        } catch (Exception $e) {
            // Continue to next
        }
        break; // Only try the first found wp-load.php to avoid re-define conflicts
    }

    // ── Strategy 2: wp-config.php → require → check $wpdb ──
    if (!$connection) {
        $wp_config_paths = get_candidate_paths('wp-config.php');
        foreach ($wp_config_paths as $path) {
            $tried_methods[] = "wp-config.php (load) → {$path}";
            // First parse to get the creds regardless
            $creds = parse_wp_config($path);
            if (!$creds) continue;

            // If we didn't already try wp-load, see if loading wp-config gives us $wpdb
            if (!defined('ABSPATH')) {
                try {
                    ob_start();
                    $old_level = error_reporting(0);
                    @require_once $path;
                    error_reporting($old_level);
                    ob_end_clean();
                } catch (Exception $e) {
                    // Fine
                }
            }

            if (isset($GLOBALS['wpdb']) && is_object($GLOBALS['wpdb']) && !empty($GLOBALS['wpdb']->dbh)) {
                $connection = $GLOBALS['wpdb'];
                $connection_type = 'wpdb';
                $connection_method = "wp-config.php → \$wpdb";
                $wpdb_available = true;
                break;
            }

            // ── Strategy 3: Use parsed defines to connect raw ──
            $tried_methods[] = "wp-config.php (parsed) → {$path}";
            list($conn, $type) = try_raw_connect(
                $creds['DB_HOST'], $creds['DB_USER'], $creds['DB_PASSWORD'], $creds['DB_NAME']
            );
            if ($conn) {
                $connection = $conn;
                $connection_type = $type;
                $connection_method = "wp-config.php → parsed → {$type}";
                break;
            }
        }
    }

    // ── Strategy 4: Check session for saved manual creds ──
    if (!$connection && !empty($_SESSION['wpdbdebug_manual'])) {
        $m = $_SESSION['wpdbdebug_manual'];
        list($conn, $type) = try_raw_connect($m['host'], $m['user'], $m['pass'], $m['name']);
        if ($conn) {
            $connection = $conn;
            $connection_type = $type;
            $connection_method = "Manual (saved in session) → {$type}";
        } else {
            unset($_SESSION['wpdbdebug_manual']);
        }
    }
}

// ── Handle manual form submission ──
if ($manual_mode) {
    $m_host = isset($_POST['db_host']) ? $_POST['db_host'] : '127.0.0.1';
    $m_user = isset($_POST['db_user']) ? $_POST['db_user'] : '';
    $m_pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
    $m_name = isset($_POST['db_name']) ? $_POST['db_name'] : '';

    $tried_methods[] = "Manual → {$m_user}@{$m_host}/{$m_name}";
    list($conn, $type) = try_raw_connect($m_host, $m_user, $m_pass, $m_name);
    if ($conn) {
        $connection = $conn;
        $connection_type = $type;
        $connection_method = "Manual → {$type}";
        $_SESSION['wpdbdebug_manual'] = array(
            'host' => $m_host, 'user' => $m_user, 'pass' => $m_pass, 'name' => $m_name
        );
    } else {
        $connection_error = "Could not connect with the provided credentials.";
    }
}

// ═══════════════════════════════════════════════════════════════
// HANDLE QUERY
// ═══════════════════════════════════════════════════════════════

$query_sql = '';
$query_result = null;

if ($connection && isset($_POST['sql']) && !empty(trim($_POST['sql']))) {
    // User submitted their own query — always takes priority
    $query_sql = trim($_POST['sql']);
    $query_result = run_query($query_sql);
} elseif ($connection && isset($_GET['action'])) {
    // Quick-action button — only when no POST
    $actions = array(
        'show_tables' => 'SHOW TABLES',
        'show_users'  => 'SELECT ID, user_login, user_email, user_registered FROM %susers ORDER BY ID DESC LIMIT 50',
        'show_options' => 'SELECT option_id, option_name, LEFT(option_value, 200) as option_value, autoload FROM %soptions ORDER BY option_id LIMIT 100',
        'show_posts'  => 'SELECT ID, post_title, post_type, post_status, post_date FROM %sposts ORDER BY ID DESC LIMIT 50',
        'wp_version'  => "SELECT option_value FROM %soptions WHERE option_name = 'db_version'",
        'show_vars'   => 'SHOW VARIABLES',
        'show_status'  => 'SHOW STATUS',
        'show_processlist' => 'SHOW PROCESSLIST',
    );
    $action = $_GET['action'];
    if (isset($actions[$action])) {
        $prefix = 'wp_';
        if ($connection_type === 'wpdb' && !empty($connection->prefix)) {
            $prefix = $connection->prefix;
        } elseif (defined('DB_NAME') && !empty($GLOBALS['table_prefix'])) {
            $prefix = $GLOBALS['table_prefix'];
        }
        $query_sql = sprintf($actions[$action], $prefix);
        $query_result = run_query($query_sql);
    }
}

// Get current DB name for display
$current_db = '?';
if ($connection_type === 'wpdb' && !empty($connection->dbname)) {
    $current_db = $connection->dbname;
} elseif (defined('DB_NAME')) {
    $current_db = DB_NAME;
} elseif (!empty($_SESSION['wpdbdebug_manual']['name'])) {
    $current_db = $_SESSION['wpdbdebug_manual']['name'];
}

// ═══════════════════════════════════════════════════════════════
// OUTPUT
// ═══════════════════════════════════════════════════════════════

$self = htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>WP DB Debug</title>
<style>
    :root {
        --bg: #0e1117;
        --surface: #161b22;
        --surface2: #1c2129;
        --border: #2d333b;
        --border-focus: #58a6ff;
        --text: #c9d1d9;
        --text-dim: #8b949e;
        --text-bright: #e6edf3;
        --accent: #58a6ff;
        --accent-dim: #1f6feb;
        --green: #3fb950;
        --green-dim: #238636;
        --red: #f85149;
        --red-dim: #da3633;
        --orange: #d29922;
        --purple: #bc8cff;
        --mono: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', Consolas, monospace;
        --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: var(--sans);
        background: var(--bg);
        color: var(--text);
        font-size: 14px;
        line-height: 1.5;
        min-height: 100vh;
    }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 20px; }

    /* Header */
    .hdr {
        display: flex; align-items: center; gap: 16px;
        padding: 16px 0; border-bottom: 1px solid var(--border); margin-bottom: 20px;
        flex-wrap: wrap;
    }
    .hdr h1 {
        font-size: 18px; font-weight: 600; color: var(--text-bright);
        display: flex; align-items: center; gap: 8px;
    }
    .hdr h1 span { color: var(--accent); font-family: var(--mono); font-size: 14px; font-weight: 400; }
    .badge {
        display: inline-block; padding: 2px 8px; border-radius: 12px;
        font-size: 11px; font-weight: 500; font-family: var(--mono);
    }
    .badge-ok { background: var(--green-dim); color: var(--green); }
    .badge-err { background: var(--red-dim); color: #ffa198; }
    .badge-info { background: #30363d; color: var(--text-dim); }
    .hdr-right { margin-left: auto; display: flex; gap: 8px; align-items: center; }

    /* Environment bar */
    .env {
        display: flex; gap: 20px; flex-wrap: wrap;
        padding: 10px 14px; background: var(--surface); border: 1px solid var(--border);
        border-radius: 6px; margin-bottom: 16px; font-size: 12px; color: var(--text-dim);
    }
    .env strong { color: var(--text); font-weight: 500; }

    /* Connection info */
    .conn-info {
        padding: 12px 14px; border-radius: 6px; margin-bottom: 16px;
        font-size: 13px; border: 1px solid;
    }
    .conn-ok { background: rgba(63,185,80,0.08); border-color: var(--green-dim); }
    .conn-ok .label { color: var(--green); }
    .conn-fail { background: rgba(248,81,73,0.08); border-color: var(--red-dim); }
    .conn-fail .label { color: var(--red); }

    /* Quick actions */
    .actions {
        display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px;
    }
    .actions a, .actions button {
        display: inline-block; padding: 5px 12px; font-size: 12px;
        background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
        color: var(--text); text-decoration: none; cursor: pointer;
        font-family: var(--sans); transition: border-color 0.15s, background 0.15s;
    }
    .actions a:hover, .actions button:hover {
        border-color: var(--border-focus); background: var(--surface2);
    }

    /* SQL form */
    .sql-form { margin-bottom: 16px; }
    .sql-form textarea {
        width: 100%; min-height: 100px; padding: 12px;
        background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
        color: var(--text-bright); font-family: var(--mono); font-size: 13px;
        resize: vertical; outline: none; transition: border-color 0.15s;
    }
    .sql-form textarea:focus { border-color: var(--border-focus); }
    .sql-form .bar {
        display: flex; justify-content: space-between; align-items: center;
        margin-top: 8px; gap: 10px;
    }
    .btn {
        padding: 7px 20px; border: none; border-radius: 6px; cursor: pointer;
        font-size: 13px; font-weight: 500; font-family: var(--sans);
    }
    .btn-primary { background: var(--accent-dim); color: #fff; }
    .btn-primary:hover { background: var(--accent); }
    .btn-danger { background: var(--red-dim); color: #fff; }
    .btn-danger:hover { background: var(--red); }

    /* Results */
    .result-meta {
        display: flex; gap: 16px; padding: 8px 0; font-size: 12px; color: var(--text-dim);
        margin-bottom: 8px; flex-wrap: wrap;
    }
    .result-meta span strong { color: var(--text); }
    .tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 6px; }
    table {
        width: 100%; border-collapse: collapse; font-size: 13px;
        font-family: var(--mono);
    }
    thead { background: var(--surface2); position: sticky; top: 0; z-index: 1; }
    th {
        padding: 8px 12px; text-align: left; font-weight: 600;
        color: var(--text-bright); border-bottom: 2px solid var(--border);
        white-space: nowrap;
    }
    td {
        padding: 6px 12px; border-bottom: 1px solid var(--border);
        max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        color: var(--text);
    }
    tr:hover td { background: rgba(88,166,255,0.04); }
    td.null-val { color: var(--text-dim); font-style: italic; }
    .error-box {
        padding: 12px 14px; background: rgba(248,81,73,0.08);
        border: 1px solid var(--red-dim); border-radius: 6px; color: var(--red);
        font-family: var(--mono); font-size: 13px; margin-bottom: 16px;
    }
    .affected-box {
        padding: 12px 14px; background: rgba(63,185,80,0.08);
        border: 1px solid var(--green-dim); border-radius: 6px; color: var(--green);
        font-size: 13px;
    }

    /* Manual form */
    .manual-form {
        background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
        padding: 20px; max-width: 460px;
    }
    .manual-form h2 { font-size: 15px; margin-bottom: 14px; color: var(--text-bright); }
    .field { margin-bottom: 12px; }
    .field label { display: block; font-size: 12px; color: var(--text-dim); margin-bottom: 4px; font-weight: 500; }
    .field input {
        width: 100%; padding: 8px 10px; background: var(--bg); border: 1px solid var(--border);
        border-radius: 4px; color: var(--text-bright); font-family: var(--mono); font-size: 13px;
        outline: none;
    }
    .field input:focus { border-color: var(--border-focus); }

    /* Tried methods */
    details { margin-top: 12px; font-size: 12px; color: var(--text-dim); }
    details summary { cursor: pointer; color: var(--text-dim); }
    details pre {
        margin-top: 6px; padding: 10px; background: var(--surface);
        border: 1px solid var(--border); border-radius: 4px; font-size: 11px;
        overflow-x: auto; color: var(--text);
    }

    /* Keyboard hint */
    kbd {
        display: inline-block; padding: 1px 5px; font-size: 11px;
        background: var(--surface2); border: 1px solid var(--border); border-radius: 3px;
        font-family: var(--mono); color: var(--text-dim);
    }

    /* Warning banner */
    .warn-banner {
        padding: 10px 14px; background: rgba(210,153,34,0.1);
        border: 1px solid rgba(210,153,34,0.3); border-radius: 6px;
        color: var(--orange); font-size: 12px; margin-bottom: 16px;
    }
</style>
</head>
<body>
<div class="wrap">

    <!-- Header -->
    <div class="hdr">
        <h1>
            &#9751; WP DB Debug
            <span>v1.0</span>
        </h1>
        <?php if ($connection): ?>
            <span class="badge badge-ok">Connected</span>
        <?php else: ?>
            <span class="badge badge-err">No Connection</span>
        <?php endif; ?>
        <div class="hdr-right">
            <?php if ($connection): ?>
                <a href="<?php echo $self ?>?disconnect=1" style="font-size:12px;color:var(--red);text-decoration:none;">Disconnect</a>
            <?php endif; ?>
        </div>
    </div>

    <!-- Security warning -->
    <div class="warn-banner">
        &#9888; This tool provides full database access. <strong>Delete this file</strong> when you're done debugging.
    </div>

    <!-- Environment -->
    <div class="env">
        <span><strong>PHP</strong> <?php echo htmlspecialchars($php_version) ?></span>
        <span><strong>Server</strong> <?php echo htmlspecialchars($server_software) ?></span>
        <span><strong>mysqli</strong> <?php echo $has_mysqli ? '&#10003;' : '&#10007;' ?></span>
        <span><strong>PDO MySQL</strong> <?php echo $has_pdo_mysql ? '&#10003;' : '&#10007;' ?></span>
        <span><strong>mysql_*</strong> <?php echo $has_mysql ? '&#10003;' : '&#10007;' ?></span>
        <span><strong>Dir</strong> <?php echo htmlspecialchars(basename(dirname(__FILE__))); ?>/</span>
    </div>

    <?php if ($connection): ?>
        <!-- Connection info -->
        <div class="conn-info conn-ok">
            <span class="label">&#10003; Connected</span> via <strong><?php echo htmlspecialchars($connection_method) ?></strong>
            &nbsp;&middot;&nbsp; Database: <strong><?php echo htmlspecialchars($current_db) ?></strong>
            &nbsp;&middot;&nbsp; Driver: <strong><?php echo htmlspecialchars($connection_type) ?></strong>
        </div>

        <!-- Quick actions -->
        <div class="actions">
            <a href="<?php echo $self ?>?action=show_tables">SHOW TABLES</a>
            <a href="<?php echo $self ?>?action=show_users">Users</a>
            <a href="<?php echo $self ?>?action=show_options">Options</a>
            <a href="<?php echo $self ?>?action=show_posts">Posts</a>
            <a href="<?php echo $self ?>?action=wp_version">WP DB Version</a>
            <a href="<?php echo $self ?>?action=show_vars">Server Variables</a>
            <a href="<?php echo $self ?>?action=show_status">Server Status</a>
            <a href="<?php echo $self ?>?action=show_processlist">Process List</a>
        </div>

        <!-- SQL form -->
        <form method="post" action="<?php echo $self; ?>" class="sql-form" id="sqlForm">
            <textarea name="sql" id="sqlInput" placeholder="SELECT * FROM wp_options LIMIT 10;"
                      spellcheck="false" autocomplete="off"><?php echo htmlspecialchars($query_sql) ?></textarea>
            <div class="bar">
                <span style="font-size:12px;color:var(--text-dim);">
                    <kbd>Ctrl</kbd>+<kbd>Enter</kbd> to execute &nbsp;&middot;&nbsp; Separate multiple queries with <kbd>;</kbd>
                </span>
                <button type="submit" class="btn btn-primary">Execute</button>
            </div>
        </form>

        <!-- Results -->
        <?php if ($query_result !== null): ?>
            <?php if ($query_result['error']): ?>
                <div class="error-box">&#10007; <?php echo htmlspecialchars($query_result['error']) ?></div>
            <?php elseif (!empty($query_result['rows'])): ?>
                <div class="result-meta">
                    <span><strong><?php echo count($query_result['rows']) ?></strong> rows</span>
                    <span><strong><?php echo count($query_result['columns']) ?></strong> columns</span>
                    <span><strong><?php echo $query_result['time'] ?></strong> ms</span>
                </div>
                <div class="tbl-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <?php foreach ($query_result['columns'] as $col): ?>
                                    <th><?php echo htmlspecialchars($col) ?></th>
                                <?php endforeach; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($query_result['rows'] as $i => $row): ?>
                                <tr>
                                    <td style="color:var(--text-dim);font-size:11px;"><?php echo $i + 1 ?></td>
                                    <?php foreach ($query_result['columns'] as $col): ?>
                                        <?php if ($row[$col] === null): ?>
                                            <td class="null-val">NULL</td>
                                        <?php else: ?>
                                            <td title="<?php echo htmlspecialchars($row[$col]); ?>"><?php echo htmlspecialchars(_dbdebug_truncate($row[$col], 300)); ?></td>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="affected-box">
                    &#10003; Query OK. <strong><?php echo $query_result['affected'] ?></strong> row(s) affected.
                    <?php if ($query_result['insert_id']): ?>
                        Insert ID: <strong><?php echo $query_result['insert_id'] ?></strong>
                    <?php endif; ?>
                    <span style="float:right;color:var(--text-dim);font-size:12px;"><?php echo $query_result['time'] ?> ms</span>
                </div>
            <?php endif; ?>
        <?php endif; ?>

    <?php else: ?>
        <!-- No connection: show manual form -->
        <?php if ($connection_error): ?>
            <div class="error-box"><?php echo htmlspecialchars($connection_error) ?></div>
        <?php endif; ?>

        <div class="conn-info conn-fail">
            <span class="label">&#10007; Could not auto-detect database connection.</span>
            Please enter credentials manually below.
        </div>

        <form method="post" class="manual-form">
            <h2>Manual Database Connection</h2>
            <div class="field">
                <label>DB Host</label>
                <input type="text" name="db_host" value="<?php echo htmlspecialchars(isset($_POST['db_host']) ? $_POST['db_host'] : '127.0.0.1'); ?>" placeholder="127.0.0.1">
            </div>
            <div class="field">
                <label>DB Name</label>
                <input type="text" name="db_name" value="<?php echo htmlspecialchars(isset($_POST['db_name']) ? $_POST['db_name'] : ''); ?>" placeholder="wordpress" required>
            </div>
            <div class="field">
                <label>DB User</label>
                <input type="text" name="db_user" value="<?php echo htmlspecialchars(isset($_POST['db_user']) ? $_POST['db_user'] : 'root'); ?>" placeholder="root" required>
            </div>
            <div class="field">
                <label>DB Password</label>
                <input type="password" name="db_pass" value="" placeholder="••••••••">
            </div>
            <button type="submit" name="manual_connect" value="1" class="btn btn-primary" style="margin-top:4px;">Connect</button>
        </form>

        <?php if (!empty($tried_methods)): ?>
            <details>
                <summary>Connection attempts (<?php echo count($tried_methods) ?> tried)</summary>
                <pre><?php foreach ($tried_methods as $t): echo htmlspecialchars($t) . "\n"; endforeach; ?></pre>
            </details>
        <?php endif; ?>

    <?php endif; ?>

</div>

<script>
// Ctrl+Enter to submit
var sqlInput = document.getElementById('sqlInput');
var sqlForm = document.getElementById('sqlForm');
if (sqlInput) {
    sqlInput.onkeydown = function(e) {
        if ((e.ctrlKey || e.metaKey) && (e.key === 'Enter' || e.keyCode === 13)) {
            if (e.preventDefault) e.preventDefault();
            sqlForm.submit();
        }
    };
    sqlInput.focus();
}
// Click on a table cell to expand it
var cells = document.getElementsByTagName('td');
for (var ci = 0; ci < cells.length; ci++) {
    (function(td) {
        if (td.className === 'null-val') return;
        td.style.cursor = 'pointer';
        td.onclick = function() {
            if (this.style.whiteSpace === 'normal') {
                this.style.whiteSpace = 'nowrap';
                this.style.maxWidth = '400px';
            } else {
                this.style.whiteSpace = 'normal';
                this.style.maxWidth = 'none';
            }
        };
    })(cells[ci]);
}
</script>
</body>
</html>
