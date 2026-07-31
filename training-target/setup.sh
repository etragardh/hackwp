#!/bin/sh
# ╔══════════════════════════════════════════════════════════════════╗
# ║  HWP Training Target — WordPress Setup Script                  ║
# ║  Runs via WP-CLI container on first boot                       ║
# ╚══════════════════════════════════════════════════════════════════╝

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  HWP Training Target — Setup                            ║"
echo "╚══════════════════════════════════════════════════════════╝"

# Wait for WordPress files to be available (the wordpress container
# copies them into the shared volume on first start)
echo "[*] Waiting for WordPress files..."
MAX_WAIT=120
WAITED=0
while [ ! -f /var/www/html/wp-includes/version.php ]; do
    sleep 2
    WAITED=$((WAITED + 2))
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[!] Timed out waiting for WordPress files"
        exit 1
    fi
done
echo "[+] WordPress files found"

# Wait for database to accept connections through WordPress
echo "[*] Waiting for database connection via WordPress..."
WAITED=0
while ! wp db check --quiet 2>/dev/null; do
    sleep 2
    WAITED=$((WAITED + 2))
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[!] Timed out waiting for database"
        exit 1
    fi
done
echo "[+] Database connection established"

# Check if WordPress is already installed
if wp core is-installed 2>/dev/null; then
    echo "[+] WordPress is already installed — skipping setup"
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Ready!                                                 ║"
    echo "║  WordPress:  ${WP_URL:-http://localhost}                ║"
    echo "║  WP Admin:   ${WP_URL:-http://localhost}/wp-admin       ║"
    echo "║  User: ${WP_ADMIN_USER:-admin} / Pass: ${WP_ADMIN_PASSWORD:-admin}  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    exit 0
fi

# Install WordPress
echo "[*] Installing WordPress..."
wp core install \
    --url="${WP_URL:-http://localhost}" \
    --title="HWP Training Target" \
    --admin_user="${WP_ADMIN_USER:-admin}" \
    --admin_password="${WP_ADMIN_PASSWORD:-admin}" \
    --admin_email="${WP_ADMIN_EMAIL:-admin@hwp-training.local}" \
    --skip-email

echo "[+] WordPress installed"

# Configure permalinks (needed for REST API routes)
echo "[*] Setting permalink structure..."
wp rewrite structure '/%postname%/' --hard

# Enable REST API (should be on by default, but make sure)
echo "[*] Configuring WordPress settings..."

# Set site description
wp option update blogdescription "Intentionally Vulnerable — HWP Security Training"

# Enable open registration + a low-priv default role (subscriber is the account
# the PRIVESC exploit escalates)
wp option update users_can_register 1
wp option update default_role subscriber

# Set timezone
wp option update timezone_string "Europe/Stockholm"

# Disable auto-updates (we want a stable training target)
wp config set WP_AUTO_UPDATE_CORE false --raw 2>/dev/null || true

# Enable debug logging (useful for training)
wp config set WP_DEBUG true --raw 2>/dev/null || true
wp config set WP_DEBUG_LOG true --raw 2>/dev/null || true
wp config set WP_DEBUG_DISPLAY true --raw 2>/dev/null || true

# Create test users at different privilege levels
echo "[*] Creating test users..."
wp user create editor editor@hwp-training.local --role=editor --user_pass=editor 2>/dev/null || true
wp user create author author@hwp-training.local --role=author --user_pass=author 2>/dev/null || true
wp user create subscriber subscriber@hwp-training.local --role=subscriber --user_pass=subscriber 2>/dev/null || true

# Create a test post and page (gives the site some content)
echo "[*] Creating test content..."
wp post create --post_title="Welcome to HWP Training" \
    --post_content="This is an intentionally vulnerable WordPress installation for security training. <strong>Do not expose to the internet.</strong>" \
    --post_status=publish \
    --post_author=1

wp post create --post_type=page \
    --post_title="About This Lab" \
    --post_content="This lab is part of the HackWP security training framework. Each REST endpoint under /wp-json/hwp-training/v1/ represents a different vulnerability type." \
    --post_status=publish \
    --post_author=1

# Flush rewrite rules
wp rewrite flush --hard

# Ensure the mu-plugins subdirectory is writable (for CODEINJ testing)
echo "[*] Setting permissions..."
if [ -d /var/www/html/wp-content/mu-plugins/hwp-training-target ]; then
    chmod 777 /var/www/html/wp-content/mu-plugins/hwp-training-target
fi

# Ensure uploads directory exists and is writable
mkdir -p /var/www/html/wp-content/uploads
chmod 777 /var/www/html/wp-content/uploads

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Setup Complete!                                        ║"
echo "║                                                         ║"
echo "║  WordPress:  ${WP_URL:-http://localhost}                ║"
echo "║  WP Admin:   ${WP_URL:-http://localhost}/wp-admin       ║"
echo "║  REST API:   ${WP_URL:-http://localhost}/wp-json/hwp-training/v1/ ║"
echo "║                                                         ║"
echo "║  Credentials:                                           ║"
echo "║    ${WP_ADMIN_USER:-admin} / ${WP_ADMIN_PASSWORD:-admin} (administrator) ║"
echo "║    editor     / editor     (editor)                     ║"
echo "║    author     / author     (author)                     ║"
echo "║    subscriber / subscriber (subscriber)                 ║"
echo "║                                                         ║"
echo "║  Database:                                              ║"
echo "║    root / ${MARIADB_ROOT_PASSWORD:-rootpass} (phpMyAdmin)║"
echo "║    ${WORDPRESS_DB_USER:-wordpress} / ${WORDPRESS_DB_PASSWORD:-wordpress} ║"
echo "╚══════════════════════════════════════════════════════════╝"
