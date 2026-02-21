# Bee-Learnt API

A comprehensive Express.js TypeScript backend API powering the Bee-Learnt educational platform. Built with Drizzle ORM, featuring dual-database architecture, role-based access control, real-time WebSocket support, and extensive educational features.

## 🎯 Features

### Core Features
- **Role-Based Access Control (RBAC)** - Support for STUDENT, PARENT, TUTOR, and ADMIN roles
- **Multi-Tenant Authentication** - Neon Auth OAuth integration + local JWT authentication
- **Real-Time Communication** - Socket.io WebSocket server for live updates
- **Error Monitoring** - Sentry integration for production error tracking
- **API Documentation** - Swagger/OpenAPI auto-generated docs at `/api-docs`
- **Health Checks** - Built-in monitoring endpoints

### Educational Features
- **Curriculum Management** - NSC curriculum, modules, lessons, and learning resources
- **Assessment System** - Quizzes, question banks, and adaptive assessments
- **Learning Analytics** - Progress tracking, performance metrics, and insights
- **Gamification** - Points, badges, leaderboards, and achievement systems
- **AI Tutoring** - OpenAI integration for intelligent learning assistance
- **Study Management** - Study goals, notes, resources, and learning paths
- **Collaboration** - Study groups, messaging, and real-time collaboration
- **Attendance Tracking** - Real-time attendance management for tutors
- **Parent-Student Linking** - Multi-tier relationships with role hierarchy
- **Resource Management** - Subject resources, external content, and media
- **Scheduling** - Timetables, events, calendars, and appointment management

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| Express.js | 5.1.0 | Web framework |
| TypeScript | 5.x | Type safety |
| Drizzle ORM | 0.41.0 | Database ORM & migrations |
| PostgreSQL | (via Neon) | Primary database |
| Neon Serverless | 0.10.4 | Database client |
| Better Auth | 1.2.0 | Authentication library |
| JWT (jose) | 6.1.0 | Token management |
| Socket.io | 4.x | Real-time WebSocket |
| OpenAI | 4.77.0 | AI tutoring features |
| Zod | 4.x | Schema validation |
| Sentry | 10.38.0 | Error monitoring |
| Swagger UI | Latest | API documentation |
| Biome | 2.x | Linting & formatting |

## 📁 Project Structure

```
src/
├── app.ts                 # Express app configuration
├── server.ts              # HTTP server & Socket.io setup entry point
├── instrument.ts          # Sentry APM instrumentation
├── config/                # Configuration files
│   ├── env.ts            # Environment variables schema
│   └── swagger.ts        # OpenAPI/Swagger config
├── core/                  # Core infrastructure
│   ├── database/         # Database connections & schemas
│   │   ├── index.ts      # Main appDb (beelearnt)
│   │   ├── neon-auth-db.ts # authDb (neondb)
│   │   └── schema/       # Drizzle ORM schemas
│   ├── middleware/       # Express middleware
│   │   ├── auth.ts       # Authentication middleware
│   │   ├── error-handler.ts
│   │   └── not-found.ts
│   └── utils/            # Core utilities
├── clients/               # External service clients
│   ├── openai.ts         # OpenAI API client
│   └── email.ts          # Nodemailer email setup
├── routes/                # API route handlers (47+ routes)
│   ├── auth.routes.ts
│   ├── students.routes.ts
│   ├── quizzes.routes.ts
│   ├── lessons.routes.ts
│   ├── progress.routes.ts
│   └── ... (more routes)
├── controllers/           # Route logic & request handling
├── services/              # Business logic layer
│   ├── user.service.ts
│   ├── quiz.service.ts
│   ├── lesson.service.ts
│   └── ... (more services)
├── modules/               # Feature modules
│   ├── auth/             # Authentication module
│   ├── users/            # User management
│   ├── students/         # Student-specific features
│   ├── assessments/      # Quizzes & assessments
│   ├── progress/         # Progress tracking
│   ├── questions/        # Question bank
│   ├── notifications/    # Notification system
│   └── ... (more modules)
├── socket/                # WebSocket handlers
│   ├── index.ts          # Socket.io initialization
│   └── handlers/         # Event handlers
├── shared/                # Shared utilities
│   ├── utils/            # Helper functions
│   ├── types/            # TypeScript type definitions
│   ├── constants/        # App constants
│   └── errors/           # Custom error classes
├── di/                    # Dependency injection setup
├── seed/                  # Database seeders & migrations
│   ├── seed.ts           # Main seeder
│   ├── seed-curriculum.ts
│   ├── migrate-*.ts      # Schema migrations
│   └── reset-db.ts       # Database reset
└── Education/             # Education-specific domain logic
```

## 🚀 Getting Started

### Prerequisites

- **Node.js** v18 or higher
- **npm** or **yarn**
- **PostgreSQL** database (via Neon)
- Environment variables configured (see `.env.example`)

### Installation

```bash
# Install dependencies
npm install
```

### Environment Setup

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:
```env
# Server
PORT=3001
NODE_ENV=development

# Database - Primary (beelearnt)
DATABASE_URL=postgresql://user:password@host:5432/beelearnt

# Database - Auth (neondb) - Optional
NEON_AUTH_DATABASE_URL=postgresql://user:password@host:5432/neondb

# Authentication
JWT_SECRET=your-secret-key
NEON_AUTH_ENABLED=false

# CORS
CORS_ORIGIN=http://localhost:3000

# OpenAI (for AI tutoring)
OPENAI_API_KEY=sk-...

# Email (SMTP)
FROM_EMAIL=auth@mail.myneon.app
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Sentry (optional)
SENTRY_DSN=https://...@sentry.io/...
```

### Database Setup

Initialize the database schema:

```bash
# Generate migrations
npm run db:generate

# Apply migrations
npm run db:migrate
# or push schema (for development)
npm run db:push
```

### Seeding Data

```bash
# Seed all data (users, curriculum, etc.)
npm run seed:all

# Or individually:
npm run seed                    # Base data
npm run seed:curriculum        # NSC curriculum
npm run seed:nsc-papers        # NSC past papers
npm run seed:resources         # Subject resources
```

### Running Development Server

```bash
npm run dev
```

The API will be available at `http://localhost:3001`

**API Documentation:** http://localhost:3001/api-docs
**Health Check:** http://localhost:3001/health

### Building for Production

```bash
# Build TypeScript
npm run build

# Start production server
npm run start
```

## 📝 Available Scripts

```bash
# Development
npm run dev                 # Start dev server with hot reload

# Building
npm run build               # Compile TypeScript to JavaScript
npm run typecheck           # Type check without emitting

# Production
npm run start               # Start production server

# Database
npm run db:generate         # Generate migration files
npm run db:migrate          # Apply migrations
npm run db:push             # Push schema to database
npm run db:studio           # Open Drizzle Studio admin

# Seeding & Migrations
npm run seed                # Seed base data
npm run seed:all            # Seed all data
npm run seed:curriculum     # Seed curriculum
npm run seed:nsc-papers     # Seed NSC papers
npm run seed:resources      # Seed resources
npm run db:reset            # Reset & reseed database
npm run migrate:all         # Run all migrations

# Administration
npm run check:tables        # Verify database tables
npm run check:env           # Verify environment setup
npm run test:connection     # Test database connection
npm run sync:neon-auth      # Sync Neon Auth users

# Code Quality
npm run lint                # Lint code
npm run format              # Format code
```

## 🏗️ Architecture

### Dual-Database Architecture

The API uses **two separate PostgreSQL databases**:

1. **beelearnt** (`appDb`)
   - Application data: users, roles, subjects, modules, lessons, quizzes, progress, etc.
   - 55+ core tables
   - Connection via `DATABASE_URL`

2. **neondb** (`authDb`)
   - Neon Auth system: identities, OAuth accounts, sessions, organizations
   - Auto-created by Neon Auth
   - Connection via `NEON_AUTH_DATABASE_URL` (optional)

**Important:** No cross-database JOINs possible. Each database is queried independently.

### Authentication Flow

```
1. User Registration/Login
   ↓
2. Hash password (bcryptjs) or validate Neon Auth token
   ↓
3. Create/sync user in beelearnt.users (appDb)
   ↓
4. Resolve role (organization member role or user role)
   ↓
5. Generate JWT token (jose)
   ↓
6. Return token to client
```

### Role Hierarchy

```
ADMIN > TUTOR > PARENT > STUDENT

Organization Member Roles (from neondb):
  - owner/admin     → ADMIN
  - parent/guardian → PARENT
  - member/student  → STUDENT
```

### Request Flow

```
HTTP Request
  ↓
CORS Middleware
  ↓
Body Parsing Middleware
  ↓
Authentication Middleware (sets req.user)
  ↓
Route Handler → Controller → Service → Database
  ↓
Error Handling Middleware
  ↓
HTTP Response
```

## 🔐 Security Features

- **CORS** - Configurable cross-origin resource sharing
- **JWT** - Secure token-based authentication
- **Bcrypt** - Password hashing with salt rounds
- **Sentry** - Real-time error tracking and alerting
- **Request Validation** - Zod schema validation on all inputs
- **Role-Based Access** - RBAC middleware on protected routes

## 📡 Real-Time Features

### Socket.io Integration

Connected to the Express server for real-time communication:

```
WebSocket Connection
  ↓
Socket.io Handler
  ↓
Event Emission
  ↓
Client Notification/Update
```

**Supported events:**
- `message` - Real-time messaging
- `notification` - System notifications
- `progress_update` - Live progress updates
- `quiz_attempt` - Live quiz interactions

## 📊 API Endpoints

**47+ API routes** organized by feature:

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/exchange-neon-token` - OAuth token exchange
- `GET /api/auth/me` - Current user info

### Students
- `GET /api/students/dashboard` - Student dashboard data
- `GET /api/students/progress` - Learning progress
- `GET /api/students/badges` - Earned badges
- `GET /api/students/analytics` - Performance analytics

### Quizzes & Assessments
- `GET /api/quizzes` - List all quizzes
- `POST /api/quizzes/:id/attempts` - Start quiz attempt
- `PUT /api/quizzes/attempts/:id/submit` - Submit quiz

### Lessons & Modules
- `GET /api/modules` - List modules
- `GET /api/lessons` - List lessons
- `POST /api/lessons/:id/complete` - Mark lesson complete

### Progress & Analytics
- `GET /api/progress` - User progress data
- `GET /api/analytics` - Platform analytics
- `GET /api/analytics/admin` - Admin analytics

### More routes:
- `assignments`, `attempts`, `attendance`, `badges`, `challenges`
- `collaboration`, `curriculum`, `events`, `leaderboard`
- `learning-path`, `messaging`, `notes`, `notifications`
- `parent`, `resources`, `study`, `timetable`, and more...

See the route files in `src/routes/` for complete documentation.

## 🧪 Testing

```bash
# Run tests (if configured)
npm run test

# Integration tests
npm run test:integration

# Connection tests
npm run test:connection

# Schema sync tests
npm run test:schema-sync
```

## 🐛 Debugging

### Sentry Integration

Errors are automatically sent to Sentry in production. Configuration in `src/instrument.ts`.

### Swagger Documentation

Auto-generated API docs available at:
```
http://localhost:3001/api-docs
```

### Database Studio

View and edit database directly with Drizzle Studio:
```bash
npm run db:studio
```

## 🔍 Common Issues

### Database Connection Failed

```
Error: unable to connect to database
```

**Solution:**
- Verify `DATABASE_URL` is correct
- Check database server is running
- Run `npm run test:connection`

### Migration Conflicts

```
Error: Migration already exists
```

**Solution:**
```bash
npm run db:push    # For development
npm run db:migrate # For production
```

### Environment Variables Not Loading

**Solution:**
```bash
# Verify environment file
npm run check:env

# Check .env is in project root
ls -la .env
```

### Port Already in Use

```
Error: listen EADDRINUSE :::3001
```

**Solution:**
```bash
# Use different port
PORT=3002 npm run dev

# Or kill process on port 3001
lsof -i :3001 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

## 📚 Documentation

- [API Endpoints](../docs/api/endpoints.md) - Complete endpoint reference
- [Architecture Guide](../docs/architecture/two-database-architecture.md) - System architecture
- [Authentication Guide](../docs/guides/authentication.md) - Auth implementation
- [Database Sync Guide](../docs/guides/database-sync.md) - Multi-database sync patterns

## 🚀 Deployment

### Environment Variables for Production

```env
NODE_ENV=production
PORT=3001
DATABASE_URL=postgresql://...
CORS_ORIGIN=https://yourdomain.com
JWT_SECRET=<strong-random-secret>
SENTRY_DSN=https://...@sentry.io/...
```

### Docker Deployment (Example)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 3001
CMD ["npm", "start"]
```

## 🤝 Contributing

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make changes and test thoroughly
3. Format code: `npm run format`
4. Commit with clear messages
5. Push and create a Pull Request

## 📄 License

This project is part of the Bee-Learnt educational platform.

---

**Backend API Documentation:** Run `npm run dev` and visit http://localhost:3001/api-docs

**Happy Building! 🚀**
