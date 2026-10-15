# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-bookworm-slim
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/ki4hrg/technitium-block-page" \
      org.opencontainers.image.revision="${REVISION}"
# Let the unprivileged node user bind :80 for the block page.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_bind_service=+ep /usr/local/bin/node \
    && apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production DATA_DIR=/data POLICY_FILE=/config/policy.yaml
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 80 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
