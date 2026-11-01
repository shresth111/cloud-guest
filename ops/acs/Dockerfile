# GenieACS (CWMP + NBI), unmodified upstream release, AGPL-3.0.
#
# We run it as a separate process and patch nothing, so there is nothing of
# ours to distribute (PRD §4.6). One image, three commands: genieacs-cwmp,
# genieacs-nbi, genieacs-fs (fs is not started in Phase 1).
#
# Version: 1.2.16 (2026-03-29), the latest 1.2.x on npm when this was written
# (2026-10-22). 1.2.15 fixed an RCE in the UI's /api/ping; we run no UI, but
# pin >= 1.2.16 anyway. Bump deliberately: `npm view genieacs versions`.
FROM node:20-bookworm-slim

ARG GENIEACS_VERSION=1.2.16

RUN npm install -g --omit=dev "genieacs@${GENIEACS_VERSION}" \
 && npm cache clean --force \
 && test -x "$(command -v genieacs-cwmp)" && test -x "$(command -v genieacs-nbi)"

# Unprivileged runtime user. /opt/genieacs/ext holds extension scripts
# (none are active in Phase 1; see genieacs-config.md "Fallback").
RUN groupadd --system genieacs \
 && useradd --system --gid genieacs --home-dir /opt/genieacs --shell /usr/sbin/nologin genieacs \
 && mkdir -p /opt/genieacs/ext \
 && chown -R genieacs:genieacs /opt/genieacs

ENV GENIEACS_EXT_DIR=/opt/genieacs/ext \
    NODE_ENV=production

LABEL org.opencontainers.image.title="wyfy-genieacs" \
      org.opencontainers.image.description="Unmodified GenieACS ${GENIEACS_VERSION} for the Wyfy ISP partner TR-069 control plane" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      wyfy.genieacs.version="${GENIEACS_VERSION}"

USER genieacs
WORKDIR /opt/genieacs

# No default CMD on purpose: compose names the process explicitly.
