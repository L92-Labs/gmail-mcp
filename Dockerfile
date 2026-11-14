# Build with pnpm, ship dist + prod deps only. Runtime has no build tooling.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable pnpm && corepack pnpm fetch
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN corepack pnpm install --frozen-lockfile --offline && corepack pnpm run build \
    && corepack pnpm install --prod --frozen-lockfile --offline

FROM node:24-alpine
WORKDIR /app
# Servers have no desktop keyring; fail over to 0600 files explicitly and quietly.
ENV NODE_ENV=production GMAIL_MCP_KEYRING=file
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
USER node
EXPOSE 3016
# Unauthenticated /mcp must 401; anything else means the server or config is broken.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3016)+'/mcp',{method:'POST'}).then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["node", "dist/index.js"]
