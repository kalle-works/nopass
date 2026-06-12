# Multi-stage build for the nopwd web app (Next.js standalone).
# Build from the repo root:
#   docker build -f apps/web/Dockerfile \
#     --build-arg NEXT_PUBLIC_API_URL=https://api.nopwd.dev .

FROM node:22-slim AS builder
WORKDIR /build
RUN corepack enable

ARG NEXT_PUBLIC_API_URL=https://api.nopwd.dev
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY apps/web/package.json apps/web/
COPY packages ./packages
RUN pnpm install --frozen-lockfile --filter @nopass/web...

COPY apps/web ./apps/web
RUN pnpm --filter @nopass/web build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
RUN useradd --system --uid 10001 nopass

COPY --from=builder /build/apps/web/.next/standalone ./
COPY --from=builder /build/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder /build/apps/web/public ./apps/web/public

USER nopass
EXPOSE 3000
ENV HOSTNAME=0.0.0.0 PORT=3000
CMD ["node", "apps/web/server.js"]
