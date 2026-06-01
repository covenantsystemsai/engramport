# EngramPort MCP server — Cloud Run deployable image.
#
# Production OIDC path uses the GCE metadata server (src/auth.ts ->
# fetchTokenFromMetadataServer). The container runs as the service account
# genesis-runtime@an2b-beast-prod.iam.gserviceaccount.com which has invoker
# on Eidetic V3. No gcloud SDK needed in this image: metadata-server access
# is built into Cloud Run, the SA identity is automatic, the token is
# audience-scoped to the target URL by the metadata endpoint itself.
#
# Local-dev gcloud fallback path remains in src/auth.ts for off-cloud use.

FROM node:20-slim AS runtime

WORKDIR /app

# Install production deps first (cacheable layer).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Build artifacts.
COPY dist ./dist

# Cloud Run injects PORT via env; ENGRAMPORT_MODE=http is the deployable mode.
ENV ENGRAMPORT_MODE=http \
    ENGRAMPORT_PORT=8080 \
    NODE_ENV=production

EXPOSE 8080
CMD ["node", "dist/index.js"]
