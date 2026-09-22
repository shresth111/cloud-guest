#!/usr/bin/env bash
#
# On-box half of the CD pipeline. Runs on the app server (i-0cf9b79511abe6000)
# as `ubuntu`, delivered by SSM SendCommand from GitHub Actions -- the whole
# file is base64'd into the command payload, so there is nothing to bootstrap
# on the box and the version that runs is always the version in the repo that
# triggered the deploy.
#
#   remote-deploy.sh <service> <image-ref>
#
#     api       -> also recreates celery-worker and celery-beat, which run the
#                  SAME image and would otherwise be left on the old code
#                  talking to a migrated database.
#     frontend  -> recreates frontend only.
#
# CANONICAL COPY. cloudguest-foundation/deploy/remote-deploy.sh is a verbatim
# duplicate so that repo's workflow is self-contained (same deliberate
# duplication the repos already use for MIN_PAGES). Fix bugs here and copy
# across in the same PR. This paragraph is the only sanctioned difference;
# diff the two files before merging either. Last synced: the build:->image:
# conversion from foundation #153.
#
# WHY IMAGE REFS AND NOT `git pull && docker compose build`
# ---------------------------------------------------------
# Confirmed on the box 2026-08-27: both checkouts under ~/deploy have
# uncommitted local modifications (foundation: MasterShell.tsx, routeTree.gen.ts,
# two untracked files; cloud-guest: nine modified files under
# backend/app/domains/wireguard plus ops/hub-agents/wg_agent.py). A `git pull`
# deploy would either refuse to merge or quietly ship whatever a human left in
# the working tree. A `git checkout -f`/`git clean` deploy would delete
# ~/deploy/cloud-guest/backend/.env, which is the stack's entire production
# configuration and is not in git. Neither is a thing to automate.
#
# CORRECTION 2026-08-27, later the same day: both checkouts are CLEAN again --
# they were tidied by a stash plus a deploy-branch checkout, which is also
# where ~/deploy/frontend-worktree-backup-*.tgz came from. The dirty-tree
# observation above was real but point-in-time, so do not cite it as current
# state. It is not what carries this argument in any case: "clean right now"
# is not a property a deploy pipeline can be built on, since the next person
# to debug something on the box makes it false again without telling anyone.
# The load-bearing half is the sentence about `.env`, and that is unchanged --
# verified still present, 7019 bytes, mode 600, ubuntu-owned, untracked, and
# with no other copy anywhere.
#
# Building here is also a bad trade on its own terms: m6i.large, 2 vCPU,
# ~1 GB free RAM while serving live traffic. A bun/vite build and a pip
# install alongside uvicorn and two celery workers is a latency incident.
#
# WHAT THIS SCRIPT ASSUMES EXISTS (see the enable-list)
#   * ~/deploy/docker-compose.yml with `image: ${API_IMAGE}` /
#     `image: ${FRONTEND_IMAGE}` instead of `build:` stanzas -- the version
#     committed alongside this file at deploy/docker-compose.prod.yml.
#   * The instance role can pull from ECR and (for api) write to
#     s3://wyfy-guest-app-storage-1787805585.
#
set -euo pipefail

SERVICE="${1:?usage: remote-deploy.sh <api|frontend> <image-ref>}"
IMAGE="${2:?usage: remote-deploy.sh <api|frontend> <image-ref>}"

DEPLOY_DIR="${DEPLOY_DIR:-/home/ubuntu/deploy}"
ENV_FILE="$DEPLOY_DIR/.deploy.env"
REGION="${AWS_REGION:-ap-south-1}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-300}"   # api runs `alembic upgrade head` before
                                          # uvicorn binds, so first-byte can be slow
BACKUP_BUCKET="${BACKUP_BUCKET:-wyfy-guest-app-storage-1787805585}"
DB_BACKUP="${DB_BACKUP:-1}"
# The outgoing-mail mailboxes live in Secrets Manager, not in the box's .env
# (the repositories are public, so a credential in git is a leaked credential
# -- see this file's own header). MAIL_SECRET_ID empty disables the fetch
# entirely and leaves today's behaviour untouched.
MAIL_SECRET_ID="${MAIL_SECRET_ID:-cloudguest/prod/mail}"
MAIL_ENV_FILE="$DEPLOY_DIR/mail.env"
# The Slack incoming-webhook URL for Master-console onboarding status. Same
# reasoning as the mail block above -- the repositories are public and a
# webhook URL is a bearer credential -- and a SEPARATE secret rather than a key
# inside cloudguest/prod/mail: it is not mail, it is read by a different
# feature, and keeping them apart means the instance role can be narrowed to
# one or the other later without untangling a shared blob.
#
# SLACK_SECRET_ID empty disables the fetch entirely; so does the secret not
# existing, which is the state of every environment until someone creates it.
# In both cases the backend sees no webhook and the feature is inert --
# onboarding is unaffected either way. See
# backend/app/domains/notification/onboarding_slack.py.
#
# If you would rather not create (and grant the instance role) a second
# secret, set SLACK_SECRET_ID=cloudguest/prod/mail in ~/deploy/.deploy.env and
# put CLOUDGUEST_SLACK_ONBOARDING_WEBHOOK_URL in the mail secret instead.
# materialise_slack_env below selects by key prefix, not by secret name, so
# that works with no code change and no new IAM statement -- it just writes
# slack.env from the mail secret. Nothing else in the mail secret matches
# CLOUDGUEST_SLACK_*, so nothing else moves.
SLACK_SECRET_ID="${SLACK_SECRET_ID:-cloudguest/prod/slack}"
SLACK_ENV_FILE="$DEPLOY_DIR/slack.env"

case "$SERVICE" in
  api)      VAR=API_IMAGE;      TARGETS=(api celery-worker celery-beat) ;;
  frontend) VAR=FRONTEND_IMAGE; TARGETS=(frontend) ;;
  *) echo "ERROR: unknown service '$SERVICE' (expected api|frontend)" >&2; exit 2 ;;
esac

log()  { echo "[deploy $(date -u +%H:%M:%S)] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

cd "$DEPLOY_DIR" || die "no such directory: $DEPLOY_DIR"
[[ -f docker-compose.yml ]] || die "no docker-compose.yml in $DEPLOY_DIR"

# The box's compose must reference the image this pipeline built, not carry
# `build:` stanzas (those would rebuild from the box's dirty checkouts on a
# 2-vCPU box serving live traffic). If it still does -- the one-time
# enable-list step to install deploy/docker-compose.prod.yml was never run --
# neutralise the build stanzas IN PLACE rather than refusing: back the file
# up, convert each service's `build:` block to the matching `image:` ref
# (frontend -> ${FRONTEND_IMAGE}, everything else -> ${API_IMAGE}), and abort
# with a restore if any survives. This preserves everything else in the
# operator's file byte-for-byte (ports, env_file, named volumes, an nginx
# service, healthchecks) -- only build->image changes -- and self-heals the
# deploy without anyone SSHing to the box. The deploy below only ever
# `up -d`s the target service, so the database and other services are never
# recreated by this.
if grep -qE '^[[:space:]]*build:' docker-compose.yml; then
  bak="docker-compose.yml.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp docker-compose.yml "$bak"
  log "docker-compose.yml still has build: stanzas -- converting to image: refs in place (backup: $bak)"
  awk '
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { svc=$0; sub(/:.*/,"",svc); gsub(/ /,"",svc) }
    /^    build:/ { print "    image: " (svc=="frontend" ? "${FRONTEND_IMAGE}" : "${API_IMAGE}"); inb=1; next }
    inb { if ($0 ~ /^      /) next; inb=0 }
    { print }
  ' "$bak" > docker-compose.yml
  if grep -qE '^[[:space:]]*build:' docker-compose.yml; then
    cp "$bak" docker-compose.yml
    die "could not convert every build: stanza in docker-compose.yml automatically.
     Restored $bak and refused to deploy -- install deploy/docker-compose.prod.yml
     by hand (see the enable-list) rather than shipping a half-converted file."
  fi
  log "converted build: stanzas to image: refs"
fi

# --- .deploy.env ----------------------------------------------------------
# compose resolves EVERY variable in the file on every `up`, including for
# services this deploy is not touching, so both vars must always be present.
# Seed missing ones from what is actually running rather than guessing.
current_image_of() {
  # Prefer compose's default <project>-<service>-1 naming, but fall back to a
  # container_name: cloudguest-<service> (what the pre-enable-list box was
  # started with by hand) so seeding works before the first pipeline deploy
  # has renamed anything.
  docker inspect --format '{{.Config.Image}}' "deploy-$1-1" 2>/dev/null \
    || docker inspect --format '{{.Config.Image}}' "cloudguest-$1" 2>/dev/null \
    || true
}

touch "$ENV_FILE"
read_var() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

for pair in "API_IMAGE:api" "FRONTEND_IMAGE:frontend"; do
  v="${pair%%:*}"; s="${pair##*:}"
  if [[ -z "$(read_var "$v")" ]]; then
    seed="$(current_image_of "$s")"
    [[ -n "$seed" ]] || die "$v unset and deploy-$s-1 is not running -- cannot seed
     $ENV_FILE safely. Set it by hand to the image that should be running."
    log "seeding $v from the running container: $seed"
    printf '%s=%s\n' "$v" "$seed" >> "$ENV_FILE"
  fi
done

PREVIOUS="$(read_var "$VAR")"
[[ -n "$PREVIOUS" ]] || die "could not determine the previous $VAR -- no rollback target"
log "service=$SERVICE  previous=$PREVIOUS  new=$IMAGE"

if [[ "$PREVIOUS" == "$IMAGE" ]]; then
  log "already running $IMAGE; re-running up -d anyway (idempotent, no-op if converged)"
fi

# --- pull BEFORE touching anything ---------------------------------------
# A pull failure (bad tag, expired ECR auth, no disk) must not leave prod
# half-deployed, so it happens while the old containers are still serving.
REGISTRY="${IMAGE%%/*}"
if [[ "$REGISTRY" == *.dkr.ecr.*.amazonaws.com ]]; then
  log "authenticating to $REGISTRY"
  aws ecr get-login-password --region "$REGION" \
    | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null \
    || die "ECR login failed -- does the instance role have ecr:GetAuthorizationToken?"
fi
log "pulling $IMAGE"
docker pull "$IMAGE" >/dev/null || die "docker pull $IMAGE failed; nothing changed"

# --- pre-migration database backup ---------------------------------------
# The api image runs `alembic upgrade head` in its CMD, so shipping it IS
# running a migration. Rolling the image back does NOT roll the schema back;
# this dump is the only thing standing between a bad migration and a restore
# from whenever the last manual backup happened to be.
if [[ "$SERVICE" == "api" && "$DB_BACKUP" == "1" ]]; then
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  KEY="db-backups/pre-deploy-$STAMP.sql.gz"
  log "dumping database to s3://$BACKUP_BUCKET/$KEY"
  if docker exec deploy-postgres-1 pg_dump -U cloudguest -d cloudguest \
       | gzip -9 \
       | aws s3 cp - "s3://$BACKUP_BUCKET/$KEY" --region "$REGION" >/dev/null; then
    log "backup ok: s3://$BACKUP_BUCKET/$KEY"
  else
    die "pre-deploy database backup FAILED. Refusing to run migrations without one.
     Fix the backup path (instance role s3:PutObject on $BACKUP_BUCKET) or
     re-run with DB_BACKUP=0 if you have a dump from elsewhere."
  fi
fi

# --- swap -----------------------------------------------------------------
set_var() {
  local name="$1" value="$2" tmp
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  grep -vE "^$name=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$name" "$value" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# --- mail.env, from Secrets Manager ---------------------------------------
# The outgoing-mail mailboxes are read from Secrets Manager on every deploy and
# written to a file compose loads *after* the base env_file, so these keys
# override the box's .env for exactly these keys and nothing else. Two
# deliberate properties:
#
#   * A mailbox is spliced in only when its `*_SMTP_PASSWORD` is non-empty. The
#     secret ships with the host/username/from filled and the passwords blank
#     (they are Google App Passwords, minted per mailbox in the admin console),
#     so a half-filled secret must NOT put a host in front of the app with no
#     password to authenticate it -- that turns "not configured yet" into "tries
#     and fails on every send". Blank password = that mailbox is left exactly as
#     the box has it today.
#   * Every failure is fail-open: a missing secret, a denied GetSecretValue, a
#     broken JSON or a box without python3 all log a WARNING and write an empty
#     file. Mail configuration is not what a deploy is for, and a deploy that
#     refuses to ship an image because a secret could not be read is a worse
#     outage than an unfilled mailbox.
#
# Nothing here prints a value: the log names how many keys were written and
# which mailboxes they belong to, never what they contain.
materialise_mail_env() {
  if [[ -z "$MAIL_SECRET_ID" ]]; then
    log "MAIL_SECRET_ID is empty -- leaving $MAIL_ENV_FILE alone"
    return 0
  fi
  : > "$MAIL_ENV_FILE"; chmod 600 "$MAIL_ENV_FILE"

  local raw summary
  if ! raw="$(aws secretsmanager get-secret-value --region "$REGION" \
                --secret-id "$MAIL_SECRET_ID" --query SecretString --output text 2>&1)"; then
    log "WARNING: could not read secret '$MAIL_SECRET_ID' ($raw)"
    log "WARNING: continuing with no mail overrides -- mail behaviour is unchanged"
    return 0
  fi

  # The JSON arrives on STDIN, so the program cannot also come from stdin
  # (`python3 -` would consume it and hand json.load an empty string -- the
  # failure is a "not valid JSON" warning and an empty mail.env, i.e. silently
  # no mail config at all). Hence a temp file for the program.
  local py summary
  py="$(mktemp)"
  cat > "$py" <<'PY'
import json, sys

target = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception as exc:  # noqa: BLE001 -- any unreadable secret means "no overrides"
    print(f"WARNING: secret is not valid JSON ({exc})", file=sys.stderr)
    sys.exit(0)
if not isinstance(data, dict):
    print("WARNING: secret is not a JSON object", file=sys.stderr)
    sys.exit(0)

# One mailbox at a time: the whole block, or none of it.
out, mailboxes = {}, []
for prefix in ("", "ADMIN_", "DEMO_", "ALERT_", "SUPPORT_", "INVOICE_"):
    password = str(data.get(f"CLOUDGUEST_{prefix}SMTP_PASSWORD") or "").strip()
    if not password:
        continue
    mailboxes.append(prefix.rstrip("_").lower() or "default")
    for key, value in data.items():
        if key.startswith(f"CLOUDGUEST_{prefix}SMTP_") and str(value).strip():
            out[key] = str(value)

# Keys that are not a mailbox and carry no password of their own.
for key in (
    "CLOUDGUEST_EMAIL_DELIVERY_PROVIDER",
    "CLOUDGUEST_DEMO_REQUEST_NOTIFY_EMAIL",
):
    value = data.get(key)
    if value is not None and str(value).strip():
        out[key] = str(value)

with open(target, "w", encoding="utf-8") as handle:
    for key in sorted(out):
        handle.write(f"{key}={out[key]}\n")

print(f"{len(out)} keys written, mailboxes: {', '.join(mailboxes) or 'none filled yet'}")
PY

  if ! summary="$(printf '%s' "$raw" | python3 "$py" "$MAIL_ENV_FILE")"; then
    rm -f "$py"
    log "WARNING: python3 could not build $MAIL_ENV_FILE -- continuing with no mail overrides"
    return 0
  fi
  rm -f "$py"
  log "mail.env: ${summary:-nothing written -- see the warning above}"
}

# The Slack webhook, materialised exactly the way the mailboxes above are and
# for the same reason: it is a credential, and these repositories are public.
#
# Deliberately narrower than materialise_mail_env: it writes ONLY keys starting
# with CLOUDGUEST_SLACK_, so a stray key added to the secret cannot become
# backend configuration by accident.
#
# Every failure path is "continue with no webhook", never "fail the deploy". An
# unreadable secret must not take the API down, and the feature it configures
# is optional by design.
#
# Nothing here prints a value: the log names which keys were written.
materialise_slack_env() {
  if [[ -z "$SLACK_SECRET_ID" ]]; then
    log "SLACK_SECRET_ID is empty -- leaving $SLACK_ENV_FILE alone"
    return 0
  fi
  : > "$SLACK_ENV_FILE"; chmod 600 "$SLACK_ENV_FILE"

  local raw summary
  if ! raw="$(aws secretsmanager get-secret-value --region "$REGION" \
                --secret-id "$SLACK_SECRET_ID" --query SecretString --output text 2>&1)"; then
    log "WARNING: could not read secret '$SLACK_SECRET_ID' ($raw)"
    log "WARNING: continuing with no webhook -- onboarding notifications stay off"
    return 0
  fi

  # Same stdin/temp-file dance as materialise_mail_env, for the same reason
  # written out there: the JSON arrives on STDIN, so the program cannot also
  # come from stdin.
  local py
  py="$(mktemp)"
  cat > "$py" <<'SLACKPY'
import json, sys

target = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception as exc:  # any unreadable secret means "no webhook"
    print(f"WARNING: secret is not valid JSON ({exc})", file=sys.stderr)
    sys.exit(0)
if not isinstance(data, dict):
    print("WARNING: secret is not a JSON object", file=sys.stderr)
    sys.exit(0)

out = {
    key: str(value)
    for key, value in data.items()
    if key.startswith("CLOUDGUEST_SLACK_") and str(value).strip()
}

with open(target, "w", encoding="utf-8") as handle:
    for key in sorted(out):
        handle.write(f"{key}={out[key]}\n")

print(f"{len(out)} keys written: {', '.join(sorted(out)) or 'none'}")
SLACKPY

  if ! summary="$(printf '%s' "$raw" | python3 "$py" "$SLACK_ENV_FILE")"; then
    rm -f "$py"
    log "WARNING: python3 could not build $SLACK_ENV_FILE -- continuing with no webhook"
    return 0
  fi
  rm -f "$py"
  log "slack.env: ${summary:-nothing written -- see the warning above}"
}

# Wait for ONE container to report healthy. Used to gate the celery services on
# the migration having finished; see compose_up.
wait_one_healthy() {
  local name="deploy-$1-1" deadline=$(( SECONDS + HEALTH_TIMEOUT )) status
  while (( SECONDS < deadline )); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck:{{.State.Status}}{{end}}' "$name" 2>/dev/null || echo missing)"
    case "$status" in
      healthy)                 return 0 ;;
      no-healthcheck:running)  return 0 ;;   # nothing to wait on
      unhealthy|exited|dead)   return 1 ;;
    esac
    sleep 3
  done
  return 1
}

compose_up() {
  # --no-deps so postgres/redis are never recreated by an app deploy; they hold
  # the only stateful thing here and have no business bouncing for a code push.
  #
  # ORDERING, for an api deploy: the api image runs `alembic upgrade head` in its
  # CMD, so shipping api IS running a migration. Bringing api up alongside
  # celery-worker/celery-beat leaves a writer alive on the OLD image while that
  # migration runs. A writer that does not know about a new constraint can insert
  # a row mid-migration, and for a CREATE UNIQUE INDEX CONCURRENTLY that is not a
  # transient error -- it leaves an INVALID index behind, which then crash-loops
  # api on its next boot. So: stop the writers, migrate, and only then start them
  # again on the new image. `up -d` returns as soon as the container is created,
  # NOT when alembic has finished, so the gate has to be api's healthcheck.
  #
  # Cost is a few seconds of deferred background work. Celery redelivers, and
  # beat's schedule is wall-clock, so nothing is lost.
  if [[ "$SERVICE" != "api" ]]; then
    docker compose --env-file "$ENV_FILE" up -d --no-deps "${TARGETS[@]}"
    return
  fi

  log "stopping celery-worker/celery-beat so no writer is live during alembic"
  docker compose --env-file "$ENV_FILE" stop celery-worker celery-beat || true

  docker compose --env-file "$ENV_FILE" up -d --no-deps api

  log "waiting up to ${HEALTH_TIMEOUT}s for api (this is alembic running)"
  if ! wait_one_healthy api; then
    # Deliberately do NOT start the writers, and do NOT die here: returning with
    # celery down makes the caller's wait_healthy fail, which runs the existing
    # rollback. Starting a writer against a schema we are about to roll the image
    # away from is the one thing that turns a failed deploy into a corrupt one.
    log "WARNING: api not healthy -- alembic may have failed"
    log "WARNING: leaving celery-worker/celery-beat STOPPED; check: docker logs deploy-api-1"
    log "WARNING: if a CONCURRENTLY-built index is INVALID, drop it before retrying"
    return 0
  fi

  log "api healthy (migration done); starting celery-worker/celery-beat"
  docker compose --env-file "$ENV_FILE" up -d --no-deps celery-worker celery-beat
}

wait_healthy() {
  local deadline=$(( SECONDS + HEALTH_TIMEOUT )) name status
  while (( SECONDS < deadline )); do
    local all_ok=1
    for t in "${TARGETS[@]}"; do
      name="deploy-$t-1"
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name" 2>/dev/null || echo missing)"
      case "$status" in
        healthy|running) ;;
        *) all_ok=0 ;;
      esac
    done
    (( all_ok == 1 )) && return 0
    sleep 5
  done
  return 1
}

report() {
  for t in "${TARGETS[@]}"; do
    echo "--- deploy-$t-1 ---"
    docker inspect --format '{{.Config.Image}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "deploy-$t-1" 2>/dev/null || echo "(missing)"
    docker logs --tail 40 "deploy-$t-1" 2>&1 | sed 's/^/    /' || true
  done
}

log "switching $VAR -> $IMAGE"
set_var "$VAR" "$IMAGE"

# Before the swap, and only for the backend: the frontend service reads no mail
# keys, so a frontend deploy has no business touching this file at all.
if [[ "$SERVICE" == "api" ]]; then
  materialise_mail_env
  materialise_slack_env
fi

if ! compose_up; then
  log "compose up failed; rolling back to $PREVIOUS"
  report
  set_var "$VAR" "$PREVIOUS"
  compose_up || true
  die "deploy failed at compose up; rolled back to $PREVIOUS"
fi

log "waiting up to ${HEALTH_TIMEOUT}s for ${TARGETS[*]} to report healthy"
if ! wait_healthy; then
  log "NOT healthy within ${HEALTH_TIMEOUT}s -- rolling back to $PREVIOUS"
  report
  set_var "$VAR" "$PREVIOUS"
  compose_up || true
  if wait_healthy; then
    die "deploy of $IMAGE failed health check; rolled back to $PREVIOUS, which is healthy.
     NOTE: if this was the api image, any alembic migration it applied is STILL
     APPLIED. Check the pre-deploy dump above before assuming prod is as it was."
  fi
  die "deploy of $IMAGE failed health check AND the rollback to $PREVIOUS is not
     healthy either. The stack needs a human NOW."
fi

log "healthy: ${TARGETS[*]}"
report

# Keep the disk from filling with superseded layers, but only untagged ones --
# never prune by age, or a rollback target disappears exactly when it is needed.
docker image prune -f >/dev/null 2>&1 || true

log "done: $SERVICE now on $IMAGE"
