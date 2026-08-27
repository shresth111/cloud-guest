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
# across in the same PR.
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

case "$SERVICE" in
  api)      VAR=API_IMAGE;      TARGETS=(api celery-worker celery-beat) ;;
  frontend) VAR=FRONTEND_IMAGE; TARGETS=(frontend) ;;
  *) echo "ERROR: unknown service '$SERVICE' (expected api|frontend)" >&2; exit 2 ;;
esac

log()  { echo "[deploy $(date -u +%H:%M:%S)] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

cd "$DEPLOY_DIR" || die "no such directory: $DEPLOY_DIR"
[[ -f docker-compose.yml ]] || die "no docker-compose.yml in $DEPLOY_DIR"

if grep -qE '^\s*build:' docker-compose.yml; then
  die "$DEPLOY_DIR/docker-compose.yml still has build: stanzas.
     Install deploy/docker-compose.prod.yml first -- see the enable-list.
     Refusing to deploy against a compose file that would rebuild from the
     box's dirty checkouts instead of using the image this pipeline built."
fi

# --- .deploy.env ----------------------------------------------------------
# compose resolves EVERY variable in the file on every `up`, including for
# services this deploy is not touching, so both vars must always be present.
# Seed missing ones from what is actually running rather than guessing.
current_image_of() {
  docker inspect --format '{{.Config.Image}}' "deploy-$1-1" 2>/dev/null || true
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

compose_up() {
  # --no-deps so postgres/redis are never recreated by an app deploy; they hold
  # the only stateful thing here and have no business bouncing for a code push.
  docker compose --env-file "$ENV_FILE" up -d --no-deps "${TARGETS[@]}"
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
