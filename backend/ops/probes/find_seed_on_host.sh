#!/bin/bash
# Look on the app server for a script that could have written the
# `deadbeef-` demo fixtures. Read-only: find and grep, nothing else.
set -u
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

ssh $SSHOPTS $HOST 'echo "=== python/sql files in home and deploy ==="; ls -la ~ /home/ubuntu/deploy 2>/dev/null | grep -Ei "\.py|\.sql|seed" | head -20; echo; echo "=== grep for the fixture id scheme ==="; grep -rl "deadbeef-000" ~ /opt /srv /root 2>/dev/null | head -10; echo; echo "=== grep for the demo names ==="; grep -rl "Aurora Riverside" ~ /opt /srv /root 2>/dev/null | head -10; echo "(done)"'
