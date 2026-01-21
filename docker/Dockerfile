# MCP SSDLC Security Toolkit - Docker Image
# Multi-stage build for minimal production image

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM node:20-alpine AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8.15.0 --activate

WORKDIR /app

# Copy package files for dependency caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json ./packages/core/
COPY packages/security-kb/package.json ./packages/security-kb/
COPY packages/ssdlc-planner/package.json ./packages/ssdlc-planner/
# Copy tsconfig files BEFORE install (needed by build)
COPY tsconfig.base.json tsconfig.json ./
COPY packages/core/tsconfig.json ./packages/core/
COPY packages/core/tsup.config.ts ./packages/core/
COPY packages/security-kb/tsconfig.json ./packages/security-kb/
COPY packages/security-kb/tsup.config.ts ./packages/security-kb/
COPY packages/ssdlc-planner/tsconfig.json ./packages/ssdlc-planner/
COPY packages/ssdlc-planner/tsup.config.ts ./packages/ssdlc-planner/

# Install ALL dependencies (including devDependencies for build)
RUN pnpm install --frozen-lockfile

# Copy source code AFTER install (preserves node_modules symlinks)
COPY packages/core/src/ ./packages/core/src/
COPY packages/security-kb/src/ ./packages/security-kb/src/
COPY packages/security-kb/scripts/ ./packages/security-kb/scripts/
COPY packages/ssdlc-planner/src/ ./packages/ssdlc-planner/src/
COPY packages/ssdlc-planner/templates/ ./packages/ssdlc-planner/templates/

# Copy data files needed for security-kb
COPY data/cwec/ ./data/cwec/
COPY data/nist/ ./data/nist/
COPY data/top10_owasp/ ./data/top10_owasp/

# Build all packages
RUN pnpm build

# Seed the security database
WORKDIR /app/packages/security-kb
RUN pnpm seed || echo "Seeding will happen at runtime"

# Prune devDependencies for production
WORKDIR /app
RUN pnpm prune --prod

# ============================================================================
# Stage 2: Production
# ============================================================================
FROM node:20-alpine AS production

# Security: Create non-root user
RUN addgroup -g 1001 -S mcp && \
    adduser -S mcp -u 1001 -G mcp

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8.15.0 --activate

WORKDIR /app

# Copy package files first (needed for pnpm symlinks)
COPY --from=builder /app/package.json ./
COPY --from=builder /app/pnpm-workspace.yaml ./
COPY --from=builder /app/pnpm-lock.yaml ./

# Copy built artifacts and dependencies
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/packages/core/node_modules ./packages/core/node_modules
COPY --from=builder /app/packages/security-kb/dist ./packages/security-kb/dist
COPY --from=builder /app/packages/security-kb/package.json ./packages/security-kb/
COPY --from=builder /app/packages/security-kb/node_modules ./packages/security-kb/node_modules
COPY --from=builder /app/packages/security-kb/data ./packages/security-kb/data
COPY --from=builder /app/packages/ssdlc-planner/dist ./packages/ssdlc-planner/dist
COPY --from=builder /app/packages/ssdlc-planner/package.json ./packages/ssdlc-planner/
COPY --from=builder /app/packages/ssdlc-planner/node_modules ./packages/ssdlc-planner/node_modules
COPY --from=builder /app/packages/ssdlc-planner/templates ./packages/ssdlc-planner/templates

# Copy domain configurations
COPY config/ ./config/

# Create data directory for security.db
RUN mkdir -p /app/packages/security-kb/data && \
    chown -R mcp:mcp /app

# Switch to non-root user
USER mcp

# Environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info

# The MCP server uses stdio, so no ports to expose
# Health check via simple node check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD node -e "console.log('healthy')" || exit 1

# Entry point - MCP server using stdio
ENTRYPOINT ["node", "/app/packages/ssdlc-planner/dist/index.js"]

# ============================================================================
# Stage 3: Development
# ============================================================================
FROM node:20-alpine AS development

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8.15.0 --activate

# Install development tools
RUN apk add --no-cache git

WORKDIR /app

# Copy everything for development
COPY . .

# Install all dependencies including devDependencies
RUN pnpm install

# Expose ports for development tools
EXPOSE 3000 9229

# Development command
CMD ["pnpm", "dev"]
