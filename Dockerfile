# Stage 1: Build
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/

RUN npm run build
RUN npm prune --production

# Stage 2: Production Minimal Runtime
FROM node:22-alpine AS runner

RUN apk --no-cache add ca-certificates curl && \
    addgroup -S -g 10001 aeitron && \
    adduser -S -u 10001 -G aeitron aeitron

WORKDIR /app

COPY --chown=aeitron:aeitron package.json ./
COPY --chown=aeitron:aeitron --from=builder /app/node_modules ./node_modules
COPY --chown=aeitron:aeitron --from=builder /app/dist ./dist

# Create persistent state directory owned by non-root aeitron user
RUN mkdir -p /app/.aeitron-state /var/lib/aeitron-mcp && \
    chown -R aeitron:aeitron /app/.aeitron-state /var/lib/aeitron-mcp && \
    chmod 700 /app/.aeitron-state /var/lib/aeitron-mcp

VOLUME ["/app/.aeitron-state"]

USER 10001:10001

ENV NODE_ENV=production \
    AEITRON_ENV=production \
    AEITRON_STORAGE_DIR=/app/.aeitron-state \
    PORT=3005 \
    HOST=0.0.0.0

EXPOSE 3005

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3005/health || exit 1

CMD ["node", "dist/src/http.js"]

