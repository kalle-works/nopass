# Tooling image for the backup and restore-drill CronJobs. The tools are
# installed at build time so the jobs run with a read-only root filesystem and
# fetch nothing from the internet at runtime.
# Build from the repo root: docker build -f ops/Dockerfile .

FROM postgres:17-alpine@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb

RUN apk add --no-cache age openssl git openssh-client

COPY ops/backup.sh ops/restore-drill.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/backup.sh /usr/local/bin/restore-drill.sh

# uid 70 is the postgres user of the base image; the drill needs it for initdb
USER 70
