#!/usr/bin/env bash
# Author: Kevin Veen-Birkenbach <kevin@veen.world> - https://www.veen.world
set -Eeuo pipefail

APP_ID="${APP_ID:-oidc_login}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
INFO_XML="${REPO_ROOT}/appinfo/info.xml"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-oidc-login-compat}"

NEXTCLOUD_HOST_PORT="${NEXTCLOUD_HOST_PORT:-8080}"
MOCK_OAUTH2_HOST_PORT="${MOCK_OAUTH2_HOST_PORT:-8090}"
NEXTCLOUD_BASE_URL="${NEXTCLOUD_BASE_URL:-http://127.0.0.1:${NEXTCLOUD_HOST_PORT}}"
MOCK_OAUTH2_BASE_URL="${MOCK_OAUTH2_BASE_URL:-http://127.0.0.1:${MOCK_OAUTH2_HOST_PORT}/default}"
OIDC_PROVIDER_URL="${OIDC_PROVIDER_URL:-http://host.docker.internal:${MOCK_OAUTH2_HOST_PORT}/default}"
NEXTCLOUD_IMAGE_TAG="${NEXTCLOUD_IMAGE_TAG:-latest}"
UPDATE_INFO="${UPDATE_INFO:-0}"
OIDC_USERNAME="${OIDC_USERNAME:-oidc-ci-user}"
LAST_NEXTCLOUD_MAJOR=""

export MOCK_OAUTH2_HOST_PORT
export NEXTCLOUD_BASE_URL
export NEXTCLOUD_HOST_PORT
export NEXTCLOUD_IMAGE_TAG
export OIDC_PROVIDER_URL

write_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT}"
  fi
}

compose() {
  docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
}

occ() {
  compose exec -T -u www-data nextcloud php occ "$@"
}

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

finish() {
  cleanup
}

read_app_version() {
  python3 - "${INFO_XML}" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
print(root.findtext('version'))
PY
}

read_nextcloud_max_version() {
  python3 - "${INFO_XML}" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
dependency = root.find('./dependencies/nextcloud')
print(dependency.attrib['max-version'])
PY
}

update_nextcloud_max_version() {
  python3 - "${INFO_XML}" "$1" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
content = path.read_text()
updated = re.sub(
    r'(<nextcloud\b[^>]*\bmax-version=")[^"]+(")',
    rf'\g<1>{version}\2',
    content,
    count=1,
)
if updated == content:
    raise SystemExit('Could not update nextcloud max-version in appinfo/info.xml')
path.write_text(updated)
PY
}

wait_for_url() {
  local url="$1"

  for _ in $(seq 1 90); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for ${url}" >&2
  return 1
}

wait_for_occ() {
  local status

  for _ in $(seq 1 120); do
    if status="$(occ status --output=json 2>/dev/null)"; then
      if printf '%s' "${status}" | python3 -c 'import json, sys; print(str(json.load(sys.stdin).get("installed") is True).lower())' | grep -qx true; then
        return 0
      fi
    fi
    sleep 3
  done

  echo 'Timed out waiting for Nextcloud occ.' >&2
  return 1
}

nextcloud_major_version() {
  local status
  status="$(occ status --output=json)"
  printf '%s' "${status}" | python3 -c 'import json, sys; payload = json.load(sys.stdin); version = payload.get("versionstring") or payload.get("version") or ""; print(str(version).split(".")[0])'
}

nextcloud_version_string() {
  local status
  status="$(occ status --output=json)"
  printf '%s' "${status}" | python3 -c 'import json, sys; payload = json.load(sys.stdin); print(payload.get("versionstring") or payload.get("version") or "")'
}

configure_nextcloud() {
  occ config:system:set trusted_domains 0 --value=127.0.0.1
  occ config:system:set trusted_domains 1 --value=localhost
  occ config:system:set trusted_domains 2 --value=host.docker.internal
  occ config:system:set overwrite.cli.url --value="${NEXTCLOUD_BASE_URL}"
  occ config:system:set oidc_login_provider_url --value="${OIDC_PROVIDER_URL}"
  occ config:system:set oidc_login_client_id --value=nextcloud
  occ config:system:set oidc_login_client_secret --value=nextcloud-secret
  occ config:system:set oidc_login_auto_redirect --type=boolean --value=true
  occ config:system:set oidc_login_disable_registration --type=boolean --value=false
  occ config:system:set oidc_login_use_id_token --type=boolean --value=true
  occ config:system:set oidc_login_tls_verify --type=boolean --value=false
  occ config:system:set oidc_login_scope --value='openid profile email'
  occ config:system:set oidc_login_code_challenge_method --value=''
  occ config:system:set oidc_login_attributes id --value=sub
  occ config:system:set oidc_login_attributes name --value=name
  occ config:system:set oidc_login_attributes mail --value=email
  occ config:system:set oidc_login_attributes groups --value=groups
}

print_diagnostics() {
  compose ps || true
  compose logs --no-color --tail=200 nextcloud mock-oauth2 || true
}

run_oidc_login() {
  local body_file
  local cookie_file
  local login_succeeded
  local user_response

  body_file="$(mktemp)"
  cookie_file="$(mktemp)"
  login_succeeded=0

  for _ in $(seq 1 10); do
    if curl -fsSL \
      --max-redirs 20 \
      --resolve "host.docker.internal:${MOCK_OAUTH2_HOST_PORT}:127.0.0.1" \
      --cookie "${cookie_file}" \
      --cookie-jar "${cookie_file}" \
      --output "${body_file}" \
      "${NEXTCLOUD_BASE_URL}/login"; then
      login_succeeded=1
      break
    fi
    sleep 3
  done

  if [ "${login_succeeded}" != '1' ]; then
    cat "${body_file}" >&2 || true
    rm -f "${body_file}" "${cookie_file}"
    return 1
  fi

  if ! user_response="$(curl -fsS \
    --cookie "${cookie_file}" \
    --header 'OCS-APIRequest: true' \
    "${NEXTCLOUD_BASE_URL}/ocs/v2.php/cloud/user?format=json")"; then
    cat "${body_file}" >&2 || true
    rm -f "${body_file}" "${cookie_file}"
    return 1
  fi

  printf '%s' "${user_response}" | python3 -c 'import json, sys
expected_user = sys.argv[1]
payload = json.load(sys.stdin)
status_code = payload.get("ocs", {}).get("meta", {}).get("statuscode")
user_id = payload.get("ocs", {}).get("data", {}).get("id")
if status_code != 200 or user_id != expected_user:
    raise SystemExit(f"OIDC login returned unexpected user payload: {payload!r}")' "${OIDC_USERNAME}"

  rm -f "${body_file}" "${cookie_file}"
}

run_compatibility_test() {
  cleanup

  compose up -d || return 1
  wait_for_url "${MOCK_OAUTH2_BASE_URL}/.well-known/openid-configuration" || return 1
  wait_for_occ || return 1

  local detected_version
  local detected_major
  detected_version="$(nextcloud_version_string)" || return 1
  detected_major="$(nextcloud_major_version)" || return 1
  LAST_NEXTCLOUD_MAJOR="${detected_major}"

  write_output nextcloud_version "${detected_version}"
  write_output nextcloud_major "${detected_major}"

  configure_nextcloud || return 1
  occ app:enable "${APP_ID}" || return 1
  wait_for_url "${NEXTCLOUD_BASE_URL}/status.php" || return 1
  run_oidc_login || return 1
}

main() {
  trap finish EXIT

  local app_version
  local current_max
  app_version="$(read_app_version)"
  current_max="$(read_nextcloud_max_version)"

  write_output app_version "${app_version}"
  write_output current_max_version "${current_max}"
  write_output changed false

  echo "::group::Compatibility test with current appinfo/info.xml"
  if run_compatibility_test; then
    echo 'Current app metadata is installable and OIDC login works.'
    echo '::endgroup::'
    if [ "${UPDATE_INFO}" = '1' ] && [ "${current_max}" -lt "${LAST_NEXTCLOUD_MAJOR}" ]; then
      update_nextcloud_max_version "${LAST_NEXTCLOUD_MAJOR}"
      write_output proposed_max_version "${LAST_NEXTCLOUD_MAJOR}"
      write_output changed true
      echo "Prepared max-version update from ${current_max} to ${LAST_NEXTCLOUD_MAJOR}."
    fi
    return 0
  fi
  echo '::endgroup::'

  if [ "${UPDATE_INFO}" != '1' ]; then
    echo 'Compatibility test failed and UPDATE_INFO is not enabled.' >&2
    print_diagnostics
    return 1
  fi

  local target_major
  target_major="${LAST_NEXTCLOUD_MAJOR}"
  if [ -z "${target_major}" ]; then
    target_major="$(nextcloud_major_version 2>/dev/null || true)"
  fi
  if [ -z "${target_major}" ]; then
    echo 'Could not determine the latest Nextcloud major version.' >&2
    print_diagnostics
    return 1
  fi

  if [ "${current_max}" -ge "${target_major}" ]; then
    echo "Current max-version (${current_max}) is already >= Nextcloud ${target_major}; not changing metadata." >&2
    print_diagnostics
    return 1
  fi

  local original_info
  original_info="$(mktemp)"
  cp "${INFO_XML}" "${original_info}"
  update_nextcloud_max_version "${target_major}"
  write_output proposed_max_version "${target_major}"

  echo "::group::Compatibility test after raising max-version to ${target_major}"
  if run_compatibility_test; then
    echo "Nextcloud ${target_major} compatibility is green after updating max-version."
    echo '::endgroup::'
    write_output changed true
    return 0
  fi
  echo '::endgroup::'

  cp "${original_info}" "${INFO_XML}"
  echo "Raising max-version to ${target_major} did not pass the compatibility test." >&2
  print_diagnostics
  return 1
}

main "$@"
