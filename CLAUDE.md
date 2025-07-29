# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Build**: `npm run build` - Compiles TypeScript to JavaScript in the `dist/` folder
- **Development**: `npm run dev` - Starts development server with hot reload using ts-node-dev
- **Production**: `npm start` - Runs the compiled application from `dist/index.js`
- **Test**: `npm test` - Runs Jest test suite
- **Database**: Use Prisma CLI for database operations (`npx prisma generate`, `npx prisma migrate`, etc.)

## Architecture Overview

WPFort is a WordPress security platform backend built with Express.js, TypeScript, and PostgreSQL. The application provides security scanning, threat detection, and management capabilities for WordPress websites.

### Core Structure

- **Entry Point**: `src/index.ts` - Initializes Express server with comprehensive environment validation
- **Routes**: `src/routes/` - Modular API endpoints organized by feature area
- **Services**: `src/services/` - Business logic and external integrations
- **Database**: Prisma ORM with PostgreSQL, schema defined in `prisma/schema.prisma`
- **Middleware**: Authentication (`verify-token.ts`) and webhook verification (`verify-webhook.ts`)

### Key Components

**Database Models**: Users, Websites, WebsiteScans, ScanDetections, Subscriptions, Insights, RecommendedActions, WebhookSecrets, and quarantine/deletion tracking.

**API Routes**:
- `/api/sites` - Website management
- `/api/scans` - Security scanning operations
- `/api/firewall` - Firewall management  
- `/api/backups` - Backup operations
- `/api/files` - File management and quarantine
- `/api/webhooks` - Webhook handling
- `/api/wordpress` - WordPress-specific operations
- `/api/operator` - Administrative operations
- `/api/events` - Event management
- `/api/emails` - Email notifications

**Services**:
- `logger.ts` - Structured logging with Grafana Loki integration
- `wpsec.ts` - WordPress security API integration
- `pusher.ts` - Real-time updates
- `email.ts` - Email notifications
- Store services for scans, updates, and core reinstalls

### Environment Configuration

The application requires extensive environment variables including:
- Database connection (`DATABASE_URL`)
- Redis configuration (`REDIS_SERVER`, credentials)
- API keys (`WPFORT_API_KEY`, `WPFORT_SERVER_API_KEY`)
- Logging (`GRAFANA_LOKI_HOST`, credentials, `LOG_LEVEL`)
- Server configuration (`PORT`, `NODE_ENV`)

Environment variables are loaded from `.env.local` and validated at startup with detailed error messages.

### Development Patterns

- All routes protected by token verification middleware
- Comprehensive structured logging with component and event tagging
- Error handling middleware with proper status codes and logging
- TypeScript strict mode enabled
- PostgreSQL with UUID primary keys and proper indexing
- Prisma for type-safe database operations