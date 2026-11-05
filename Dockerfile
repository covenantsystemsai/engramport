# EngramPort server image for the D-06 hosting design (docs/hosting.md):
# Amazon ECS on Fargate, behind an Application Load Balancer, with the
# Postgres store on Supabase.
#
# Two stages: the first builds, the second carries only what runs. The base
# image is pinned by digest (a multi-architecture index, so the same pin
# builds for Graviton/arm64 and for x86). Update the digest on purpose, in a
# reviewed change.
#
# Nothing secret is in this image. Secrets reach the container as environment
# variables at start, from AWS Secrets Manager (see deploy/engramport.env.example).

ARG NODE_IMAGE=node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production \
    ENGRAMPORT_MODE=http \
    ENGRAMPORT_PORT=8080 \
    ENGRAMPORT_STORE=postgres
WORKDIR /app
# Owned by root and only readable by the user the server runs as, so the
# server can't change its own code. The task also runs with a read-only root
# filesystem.
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# Supabase's CA certificate, so the database's TLS certificate is verified.
# It is public; see deploy/certs/README.md.
COPY deploy/certs/ ./certs/
USER node
EXPOSE 8080
# ECS stops a task with SIGTERM; the server finishes what is in flight, closes
# its database pool and exits (src/shutdown.ts).
STOPSIGNAL SIGTERM
CMD ["node", "dist/index.js"]
