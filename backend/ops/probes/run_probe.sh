#!/bin/bash
# Ship one probe from this directory to the app server and run it inside the
# API container.  Usage: run_probe.sh t2_above_dynamic.py [router-ip]
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
PROBE="${1:?usage: run_probe.sh <probe.py> [router-ip]}"
ROUTER="${2:-10.20.0.14}"
D=/Users/shresth/.claude/jobs/333a326b/tmp
mkdir -p "$D"
[ -f "$D/eic_key" ] || ssh-keygen -q -t ed25519 -N '' -f "$D/eic_key"
HOST=ubuntu@13.203.112.174
SSHOPTS="-i $D/eic_key -o StrictHostKeyChecking=no -o ConnectTimeout=20"

aws ec2-instance-connect send-ssh-public-key \
  --region ap-south-1 \
  --instance-id i-0cf9b79511abe6000 \
  --instance-os-user ubuntu \
  --ssh-public-key file://$D/eic_key.pub \
  --query RequestId --output text >/dev/null 2>&1

ssh $SSHOPTS $HOST "cat > /tmp/$PROBE" < "$SRC/$PROBE"
ssh $SSHOPTS $HOST "docker cp /tmp/$PROBE deploy-api-1:/tmp/$PROBE && docker exec deploy-api-1 python /tmp/$PROBE $ROUTER"
