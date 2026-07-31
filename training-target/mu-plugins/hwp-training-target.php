<?php
/**
 * Plugin Name: HWP Training Target
 * Description: Intentionally vulnerable plugin for HWP security training.
 * Version: 1.0.0
 * Author: @etragardh
 *
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  WARNING: THIS PLUGIN IS INTENTIONALLY VULNERABLE                 ║
 * ║  DO NOT INSTALL ON ANY PRODUCTION SITE                            ║
 * ║  FOR AUTHORIZED SECURITY TRAINING ONLY                           ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * One REST endpoint per HWP capability — a pure 1:1 lab. Each endpoint is
 * named after the capability it teaches, and there is exactly one matching
 * exploit at exploits/hwp-training/1.0.0-<capability>/.
 *
 * All endpoints are under: /wp-json/hwp-training/v1/
 *
 * The 15 canonical HWP capabilities:
 *   RCE      — PHP code execution via eval()                 (/rce)
 *   LFI      — Local file inclusion via file_get_contents()  (/lfi)
 *   AFU      — Arbitrary file upload (no validation)         (/afu)
 *   RFI      — Remote file inclusion (fetch URL + include)   (/rfi)
 *   SQLI     — SQL injection, write via $wpdb->query()       (/sqli)
 *   SQLIq    — SQL injection, read via $wpdb->get_results()  (/sqliq)
 *   CODEINJ  — Deferred PHP code injection into a file       (/codeinj)
 *   XSS      — Stored XSS via unescaped option               (/xss)
 *   XSSr     — Reflected XSS (echoes a param into HTML)      (/xssr)
 *   OBJINJ   — Object injection via unserialize()            (/objinj)
 *   AFD      — Arbitrary file deletion via unlink()          (/afd)
 *   FILEDL   — Arbitrary file download via readfile()        (/filedl)
 *   AUTH     — Auth: create/steal an admin session           (/auth)
 *   PRIVESC  — Raise the current low-priv user to admin      (/privesc)
 *   OTHER    — Operator action / data leak, no payload       (/other)
 *
 * The plugin also enqueues a CSS file so the scanner can fingerprint it:
 *   /wp-content/mu-plugins/hwp-training-target/style.css?ver=1.0.0
 */

defined('ABSPATH') || exit;

// =====================================================================
// FRONTEND CSS — Makes the plugin detectable by the scanner
// =====================================================================

add_action('wp_enqueue_scripts', function () {
    $css_url = plugin_dir_url(__FILE__) . 'hwp-training-target/style.css';
    wp_enqueue_style('hwp-training-target', $css_url, [], '1.0.0');
});


// =====================================================================
// REST API REGISTRATION — one route per capability
// =====================================================================

add_action('rest_api_init', function () {

    $namespace = 'hwp-training/v1';

    // -----------------------------------------------------------------
    // RCE — Remote Code Execution via eval()
    // Vulnerability: user-supplied PHP is passed straight to eval().
    // HWP capability: RCE   Expects: PHP code   Returns: its output
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/rce', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $code = $request->get_param('code');
            if (empty($code)) {
                return new WP_REST_Response(['error' => 'Missing "code" parameter'], 400);
            }
            $code = preg_replace('/^<\?php\s*/', '', $code);
            $code = preg_replace('/\s*\?>$/', '', $code);
            // VULNERABLE: direct eval() of user input
            ob_start();
            eval($code);
            $output = ob_get_clean();
            return new WP_REST_Response(['success' => true, 'output' => $output]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // LFI — Local File Inclusion
    // Vulnerability: user-supplied path read with no validation.
    // HWP capability: LFI   Expects: file path   Returns: file contents
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/lfi', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $file = $request->get_param('file');
            if (empty($file)) {
                return new WP_REST_Response(['error' => 'Missing "file" parameter'], 400);
            }
            // VULNERABLE: no path validation
            $contents = @file_get_contents($file);
            if ($contents === false) {
                return new WP_REST_Response(['success' => false, 'error' => 'Could not read file'], 404);
            }
            return new WP_REST_Response(['success' => true, 'output' => $contents]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // AFU — Arbitrary File Upload
    // Vulnerability: upload with no type/content validation, stored in web root.
    // HWP capability: AFU   Expects: file (multipart)   Returns: url + path
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/afu', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $files = $request->get_file_params();
            if (empty($files['file'])) {
                return new WP_REST_Response(['error' => 'Missing "file" upload'], 400);
            }
            $uploaded = $files['file'];
            // VULNERABLE: no validation, no rename, stored in web root
            $upload_dir  = wp_upload_dir();
            $target_path = $upload_dir['path'] . '/' . basename($uploaded['name']);
            $target_url  = $upload_dir['url'] . '/' . basename($uploaded['name']);
            if (move_uploaded_file($uploaded['tmp_name'], $target_path)) {
                return new WP_REST_Response(['success' => true, 'url' => $target_url, 'path' => $target_path]);
            }
            return new WP_REST_Response(['success' => false, 'error' => 'Upload failed'], 500);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // RFI — Remote File Inclusion
    // Vulnerability: a user-supplied URL is fetched and include()'d as PHP.
    // HWP capability: RFI   Expects: url   Returns: output of included PHP
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/rfi', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $url = $request->get_param('url');
            if (empty($url)) {
                return new WP_REST_Response(['error' => 'Missing "url" parameter'], 400);
            }
            // VULNERABLE: fetch remote content and include it as PHP
            $content = @file_get_contents($url);
            if ($content === false) {
                return new WP_REST_Response(['success' => false, 'error' => 'Could not fetch remote URL'], 400);
            }
            $upload_dir = wp_upload_dir();
            $tmp_file   = $upload_dir['path'] . '/hwp-rfi-' . wp_generate_password(8, false) . '.php';
            $tmp_url    = $upload_dir['url'] . '/' . basename($tmp_file);
            file_put_contents($tmp_file, $content);
            ob_start();
            include $tmp_file;
            $output = ob_get_clean();
            @unlink($tmp_file);
            return new WP_REST_Response(['success' => true, 'output' => $output, 'url' => $tmp_url, 'path' => $tmp_file]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // SQLI — SQL Injection (write: INSERT/UPDATE/DELETE, statement)
    // Vulnerability: raw SQL from user input to $wpdb->query().
    // HWP capability: SQLI   Expects: SQL statement   Returns: rows + insert_id
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/sqli', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            global $wpdb;
            $sql = $request->get_param('sql');
            if (empty($sql)) {
                return new WP_REST_Response(['error' => 'Missing "sql" parameter'], 400);
            }
            // VULNERABLE: raw execution, no prepare()
            $result = $wpdb->query($sql);
            if ($result === false) {
                return new WP_REST_Response(['success' => false, 'error' => $wpdb->last_error], 500);
            }
            return new WP_REST_Response(['success' => true, 'rows_affected' => $result, 'insert_id' => $wpdb->insert_id]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // SQLIq — SQL Injection (in-query read: SELECT via UNION/blind)
    // Vulnerability: raw SELECT from user input to $wpdb->get_results().
    // HWP capability: SQLIq   Expects: SELECT query   Returns: rows
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/sqliq', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            global $wpdb;
            $sql = $request->get_param('sql');
            if (empty($sql)) {
                return new WP_REST_Response(['error' => 'Missing "sql" parameter'], 400);
            }
            // VULNERABLE: raw SELECT execution
            $results = $wpdb->get_results($sql);
            if ($wpdb->last_error) {
                return new WP_REST_Response(['success' => false, 'error' => $wpdb->last_error], 500);
            }
            return new WP_REST_Response(['success' => true, 'output' => $results]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // CODEINJ — PHP Code Injection (deferred execution)
    // Vulnerability: PHP written to a file that is include()'d on admin_init.
    // HWP capability: CODEINJ   Expects: PHP code   Returns: confirmation + path
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/codeinj', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $code = $request->get_param('code');
            if (empty($code)) {
                return new WP_REST_Response(['error' => 'Missing "code" parameter'], 400);
            }
            // VULNERABLE: append user PHP to a file that gets included later
            $target_file = __DIR__ . '/hwp-training-target/injected.php';
            if (!is_dir(dirname($target_file))) {
                mkdir(dirname($target_file), 0755, true);
            }
            $result = file_put_contents($target_file, "\n" . $code, FILE_APPEND);
            if ($result === false) {
                return new WP_REST_Response(['success' => false, 'error' => 'Could not write to file'], 500);
            }
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Code injected — executes on next admin page load',
                'path'    => $target_file,
            ]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // XSS — Stored Cross-Site Scripting
    // Vulnerability: user input is stored and rendered unescaped in wp_footer.
    // HWP capability: XSS   Expects: JavaScript   Returns: confirmation
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/xss', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $payload = $request->get_param('payload');
            if (empty($payload)) {
                return new WP_REST_Response(['error' => 'Missing "payload" parameter'], 400);
            }
            // VULNERABLE: store unsanitised content rendered later on every page
            update_option('hwp_training_xss_stored', $payload);
            return new WP_REST_Response([
                'success' => true,
                'message' => 'XSS payload stored — renders on all frontend pages',
            ]);
        },
        'permission_callback' => '__return_true',
    ]);

    // GET to verify the stored XSS payload
    register_rest_route($namespace, '/xss', [
        'methods'  => 'GET',
        'callback' => function () {
            return new WP_REST_Response(['stored_payload' => get_option('hwp_training_xss_stored', '')]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // XSSr — Reflected Cross-Site Scripting
    // Vulnerability: the "q" URL parameter is reflected into HTML unescaped,
    //                so it executes when the crafted URL is opened in a browser.
    // HWP capability: XSSr   Expects: JS via ?q=   Returns: HTML with the reflection
    //
    // Note: hackwp's XSSr exploits do NOT fire this — they build the crafted
    // URL and the framework displays it for the operator to paste in a browser.
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/xssr', [
        'methods'  => 'GET',
        'callback' => function (WP_REST_Request $request) {
            $search = $request->get_param('q');
            // VULNERABLE: user input reflected directly into HTML
            $html = '<!DOCTYPE html><html><body>'
                  . '<h1>Search Results</h1>'
                  . '<p>You searched for: ' . $search . '</p>'
                  . '<p>No results found.</p>'
                  . '</body></html>';
            $response = new WP_REST_Response();
            $response->set_headers(['Content-Type' => 'text/html']);
            $response->set_data($html);
            return $response;
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // OBJINJ — Object Injection via unserialize()
    // Vulnerability: user input passed to unserialize() (POP-chain gadgets below).
    // HWP capability: OBJINJ   Expects: serialized PHP object   Returns: result
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/objinj', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $data = $request->get_param('data');
            if (empty($data)) {
                return new WP_REST_Response(['error' => 'Missing "data" parameter'], 400);
            }
            // VULNERABLE: direct unserialize() of user input
            $obj = unserialize($data);
            return new WP_REST_Response([
                'success' => true,
                'type'    => gettype($obj),
                'output'  => is_object($obj) ? get_class($obj) : print_r($obj, true),
            ]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // AFD — Arbitrary File Deletion
    // Vulnerability: deletes a user-supplied path with no validation.
    // HWP capability: AFD   Expects: file path   Returns: confirmation
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/afd', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $file = $request->get_param('file');
            if (empty($file)) {
                return new WP_REST_Response(['error' => 'Missing "file" parameter'], 400);
            }
            // VULNERABLE: no path validation — can delete any file
            if (!file_exists($file)) {
                return new WP_REST_Response(['success' => false, 'error' => 'File not found'], 404);
            }
            $deleted = @unlink($file);
            return new WP_REST_Response([
                'success' => $deleted,
                'message' => $deleted ? "File deleted: {$file}" : "Failed to delete: {$file}",
            ]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // FILEDL — Arbitrary File Download
    // Vulnerability: streams any file by path as a download (raw bytes).
    // HWP capability: FILEDL   Expects: file path (?file=)   Returns: raw file
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/filedl', [
        'methods'  => 'GET',
        'callback' => function (WP_REST_Request $request) {
            $file = $request->get_param('file');
            if (empty($file)) {
                return new WP_REST_Response(['error' => 'Missing "file" parameter'], 400);
            }
            // VULNERABLE: no path validation, serves any readable file
            if (!file_exists($file) || !is_readable($file)) {
                return new WP_REST_Response(['success' => false, 'error' => 'File not found or not readable'], 404);
            }
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($file) . '"');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // AUTH — Authentication (create/steal an admin session)
    // Vulnerability: creates an admin account (or authenticates) and returns a
    //                valid session with no authorisation check.
    // HWP capability: AUTH   Expects: optional user/pass   Returns: session + creds
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/auth', [
        'methods'  => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $user = $request->get_param('user');
            $pass = $request->get_param('pass');

            if (!empty($user) && !empty($pass)) {
                // VULNERABLE: no rate limiting / brute-force protection
                $wp_user = wp_authenticate($user, $pass);
                if (is_wp_error($wp_user)) {
                    return new WP_REST_Response(['success' => false, 'error' => 'Invalid credentials'], 401);
                }
            } else {
                // VULNERABLE: create an admin with no authorisation check
                $user  = 'hwp_' . wp_generate_password(6, false);
                $pass  = wp_generate_password(16, true);
                $email = $user . '@hwp-training.local';
                $user_id = wp_create_user($user, $pass, $email);
                if (is_wp_error($user_id)) {
                    return new WP_REST_Response(['success' => false, 'error' => $user_id->get_error_message()], 500);
                }
                $wp_user = new WP_User($user_id);
                $wp_user->set_role('administrator');
            }

            wp_set_current_user($wp_user->ID);
            wp_set_auth_cookie($wp_user->ID, true);

            $cookies = [];
            foreach (headers_list() as $header) {
                if (stripos($header, 'Set-Cookie:') === 0) {
                    $cookie_str = trim(substr($header, 11));
                    $parts = explode('=', explode(';', $cookie_str)[0], 2);
                    if (count($parts) === 2) {
                        $cookies[$parts[0]] = $parts[1];
                    }
                }
            }

            return new WP_REST_Response([
                'success'     => true,
                'credentials' => ['user' => $user, 'pass' => $pass],
                'session'     => $cookies,
                'user_id'     => $wp_user->ID,
                'message'     => 'Admin session created',
            ]);
        },
        'permission_callback' => '__return_true',
    ]);


    // -----------------------------------------------------------------
    // PRIVESC — Privilege Escalation
    // Vulnerability: any logged-in user can escalate their OWN account to
    //                administrator — the handler requires login but forgets to
    //                check the user's capability/role.
    // HWP capability: PRIVESC   Expects: an authenticated (low-priv) session
    //                Returns: confirmation the current user is now admin
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/privesc', [
        'methods'  => 'POST',
        'callback' => function () {
            // VULNERABLE: no current_user_can() / role check
            $uid  = get_current_user_id();
            $user = new WP_User($uid);
            $user->set_role('administrator');
            return new WP_REST_Response([
                'success' => true,
                'user_id' => $uid,
                'role'    => 'administrator',
                'message' => "User {$uid} escalated to administrator",
            ]);
        },
        // Login required (realistic) — the MISSING role check is the vuln.
        'permission_callback' => function () { return is_user_logged_in(); },
    ]);


    // -----------------------------------------------------------------
    // OTHER — Operator action / data leak (no chain payload)
    // Vulnerability: an admin-only info endpoint with no capability check —
    //                leaks sensitive configuration to anyone. The leak IS the
    //                vulnerability; nothing is delivered to the chain.
    // HWP capability: OTHER   Expects: nothing   Returns: sensitive config
    // -----------------------------------------------------------------
    register_rest_route($namespace, '/other', [
        'methods'  => 'GET',
        'callback' => function () {
            // VULNERABLE: no capability check
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Broken access control — admin data exposed',
                'config'  => [
                    'db_host'      => DB_HOST,
                    'db_name'      => DB_NAME,
                    'db_user'      => DB_USER,
                    'db_password'  => DB_PASSWORD,
                    'auth_key'     => defined('AUTH_KEY') ? AUTH_KEY : 'not set',
                    'secret_key'   => defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'not set',
                    'table_prefix' => $GLOBALS['wpdb']->prefix,
                    'abspath'      => ABSPATH,
                    'site_url'     => site_url(),
                ],
            ]);
        },
        'permission_callback' => '__return_true',
    ]);

});


// =====================================================================
// FRONTEND OUTPUT — Renders the stored XSS payload (for XSS testing)
// =====================================================================

add_action('wp_footer', function () {
    $stored = get_option('hwp_training_xss_stored', '');
    if (!empty($stored)) {
        // VULNERABLE: no esc_html() — stored XSS renders here
        echo '<!-- HWP Training: Stored XSS output -->';
        echo '<div class="hwp-xss-output"><script>' . $stored . '</script></div>';
    }
});


// =====================================================================
// ADMIN OUTPUT — Executes injected PHP (for CODEINJ testing)
// =====================================================================

add_action('admin_init', function () {
    $injected_file = __DIR__ . '/hwp-training-target/injected.php';
    if (file_exists($injected_file)) {
        // VULNERABLE: including a file that contains attacker-injected PHP
        include $injected_file;
    }
});


// =====================================================================
// POP GADGET — target for OBJINJ (the 1.0.0-pop-rce transformer builds this)
// =====================================================================

/**
 * Direct RCE gadget: eval() in __destruct. The pop-rce transformer serialises
 * this with attacker PHP in $code; unserialize() at /objinj triggers it.
 */
class HWP_Training_Gadget_RCE {

    /** @var string PHP code to execute */
    public $code = '';

    public function __destruct() {
        if (!empty($this->code)) {
            eval($this->code);
        }
    }
}
