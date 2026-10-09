#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENDPOINT="${ROOT_DIR}/admin/index.php"
WORK_DIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "${SERVER_PID}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    chmod -R u+rwX "${WORK_DIR}" >/dev/null 2>&1 || true
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Required command not found: %s\n' "$1" >&2
        exit 1
    }
}

require_command curl
require_command php

mkdir -p \
    "${WORK_DIR}/web/admin" \
    "${WORK_DIR}/private" \
    "${WORK_DIR}/sessions"
cp "${ENDPOINT}" "${WORK_DIR}/web/admin/index.php"

TEST_USERNAME="integration-admin"
TEST_PASSWORD="Correct-Horse-Battery-Staple"
INITIAL_HASH="$(
    php -r 'echo password_hash($argv[1], PASSWORD_BCRYPT, ["cost" => 5]);' \
        "${TEST_PASSWORD}"
)"
printf '%s:%s\n' "${TEST_USERNAME}" "${INITIAL_HASH}" \
    >"${WORK_DIR}/private/admin.htpasswd"
chmod 600 "${WORK_DIR}/private/admin.htpasswd"

PORT="${COSMICNOON_ADMIN_AUTH_TEST_PORT:-$((20000 + ($$ % 20000)))}"
BASE_URL="http://127.0.0.1:${PORT}/admin/"
php \
    -d "session.save_path=${WORK_DIR}/sessions" \
    -S "127.0.0.1:${PORT}" \
    -t "${WORK_DIR}/web" \
    >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 50); do
    if curl -s -o /dev/null "${BASE_URL}"; then
        break
    fi
    sleep 0.05
done

request_login_page() {
    local prefix="$1"
    curl -sS \
        -D "${WORK_DIR}/${prefix}-headers" \
        -o "${WORK_DIR}/${prefix}-body" \
        "${BASE_URL}"
}

extract_session_id() {
    local headers="$1"
    sed -n \
        's/^Set-Cookie: cosmicnoon_admin=\([^;[:space:]]*\).*/\1/p' \
        "${headers}" \
        | tr -d '\r' \
        | tail -n 1
}

extract_login_token() {
    local body="$1"
    sed -n \
        's/.*name="login_token" value="\([^"]*\)".*/\1/p' \
        "${body}" \
        | tail -n 1
}

request_login_page initial
SESSION_ID="$(extract_session_id "${WORK_DIR}/initial-headers")"
LOGIN_TOKEN="$(extract_login_token "${WORK_DIR}/initial-body")"
[[ -n "${SESSION_ID}" && -n "${LOGIN_TOKEN}" ]] || {
    printf 'Could not establish an admin login session.\n' >&2
    exit 1
}

printf 'Checking per-IP throttling...\n'
for attempt in $(seq 1 6); do
    status="$(
        curl -sS \
            -D "${WORK_DIR}/failed-${attempt}-headers" \
            -o "${WORK_DIR}/failed-${attempt}-body" \
            -w '%{http_code}' \
            -H "Cookie: cosmicnoon_admin=${SESSION_ID}" \
            --data-urlencode "admin_action=login" \
            --data-urlencode "login_token=${LOGIN_TOKEN}" \
            --data-urlencode "username=${TEST_USERNAME}" \
            --data-urlencode "password=wrong-password" \
            "${BASE_URL}"
    )"
    if [[ "${attempt}" -le 5 ]]; then
        [[ "${status}" == "200" ]] || {
            printf 'Attempt %s was limited too early with status %s.\n' \
                "${attempt}" "${status}" >&2
            exit 1
        }
    else
        [[ "${status}" == "429" ]] || {
            printf 'Expected the sixth attempt to return 429, got %s.\n' \
                "${status}" >&2
            exit 1
        }
        grep -qi '^Retry-After:' "${WORK_DIR}/failed-${attempt}-headers"
    fi
done

if grep -R -F -q \
    -e "${TEST_USERNAME}" \
    -e '127.0.0.1' \
    "${WORK_DIR}/private/admin-auth"; then
    printf 'Throttle storage exposed a raw login identifier.\n' >&2
    exit 1
fi

rm -rf "${WORK_DIR}/private/admin-auth"
request_login_page success
SESSION_ID="$(extract_session_id "${WORK_DIR}/success-headers")"
LOGIN_TOKEN="$(extract_login_token "${WORK_DIR}/success-body")"

printf 'Checking successful login and password-hash upgrade...\n'
success_status="$(
    curl -sS \
        -D "${WORK_DIR}/login-success-headers" \
        -o "${WORK_DIR}/login-success-body" \
        -w '%{http_code}' \
        -H "Cookie: cosmicnoon_admin=${SESSION_ID}" \
        --data-urlencode "admin_action=login" \
        --data-urlencode "login_token=${LOGIN_TOKEN}" \
        --data-urlencode "username=${TEST_USERNAME}" \
        --data-urlencode "password=${TEST_PASSWORD}" \
        "${BASE_URL}"
)"
[[ "${success_status}" == "303" ]] || {
    printf 'Expected successful login status 303, got %s.\n' \
        "${success_status}" >&2
    exit 1
}
AUTHENTICATED_SESSION_ID="$(
    extract_session_id "${WORK_DIR}/login-success-headers"
)"
[[ -n "${AUTHENTICATED_SESSION_ID}" ]] || {
    printf 'Successful login did not rotate the session identifier.\n' >&2
    exit 1
}

php -r '
    [$username, $hash] = explode(":", trim(file_get_contents($argv[1])), 2);
    if ($username !== $argv[2] || !password_verify($argv[3], $hash)) {
        exit(1);
    }
    if (password_needs_rehash(
        $hash,
        in_array("argon2id", password_algos(), true)
            ? PASSWORD_ARGON2ID
            : PASSWORD_BCRYPT,
        in_array("argon2id", password_algos(), true)
            ? ["memory_cost" => 65536, "time_cost" => 4, "threads" => 2]
            : ["cost" => 12]
    )) {
        exit(2);
    }
' "${WORK_DIR}/private/admin.htpasswd" "${TEST_USERNAME}" "${TEST_PASSWORD}"

printf 'Checking CSRF-protected logout...\n'
CSRF_TOKEN="$(
    php \
        -d "session.save_path=${WORK_DIR}/sessions" \
        -r '
            session_name("cosmicnoon_admin");
            session_id($argv[1]);
            session_start();
            echo $_SESSION["csrf_token"] ?? "";
            session_write_close();
        ' \
        "${AUTHENTICATED_SESSION_ID}"
)"
[[ -n "${CSRF_TOKEN}" ]] || {
    printf 'Authenticated session did not contain a CSRF token.\n' >&2
    exit 1
}
logout_status="$(
    curl -sS \
        -o "${WORK_DIR}/logout-body" \
        -w '%{http_code}' \
        -H "Cookie: cosmicnoon_admin=${AUTHENTICATED_SESSION_ID}" \
        --data-urlencode "admin_action=logout" \
        --data-urlencode "csrf_token=${CSRF_TOKEN}" \
        "${BASE_URL}"
)"
[[ "${logout_status}" == "303" ]] || {
    printf 'Expected logout status 303, got %s.\n' "${logout_status}" >&2
    exit 1
}

after_logout_status="$(
    curl -sS \
        -o "${WORK_DIR}/after-logout-body" \
        -w '%{http_code}' \
        -H "Cookie: cosmicnoon_admin=${AUTHENTICATED_SESSION_ID}" \
        "${BASE_URL}"
)"
[[ "${after_logout_status}" == "200" ]] || {
    printf 'Expected logged-out status 200, got %s.\n' \
        "${after_logout_status}" >&2
    exit 1
}
grep -q 'Sign in securely' "${WORK_DIR}/after-logout-body"

printf 'Checking fail-closed throttle storage...\n'
rm -rf "${WORK_DIR}/private/admin-auth"
chmod 500 "${WORK_DIR}/private"
request_login_page fail-closed
FAIL_CLOSED_SESSION_ID="$(
    extract_session_id "${WORK_DIR}/fail-closed-headers"
)"
FAIL_CLOSED_TOKEN="$(
    extract_login_token "${WORK_DIR}/fail-closed-body"
)"
fail_closed_status="$(
    curl -sS \
        -o "${WORK_DIR}/fail-closed-response" \
        -w '%{http_code}' \
        -H "Cookie: cosmicnoon_admin=${FAIL_CLOSED_SESSION_ID}" \
        --data-urlencode "admin_action=login" \
        --data-urlencode "login_token=${FAIL_CLOSED_TOKEN}" \
        --data-urlencode "username=${TEST_USERNAME}" \
        --data-urlencode "password=${TEST_PASSWORD}" \
        "${BASE_URL}"
)"
[[ "${fail_closed_status}" == "503" ]] || {
    printf 'Expected unavailable throttle storage to return 503, got %s.\n' \
        "${fail_closed_status}" >&2
    exit 1
}

printf 'Admin authentication integration tests passed.\n'
