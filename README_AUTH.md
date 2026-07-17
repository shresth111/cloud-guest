# CloudGuest Authentication & Identity Module (Module 003)

Complete, production-grade authentication system for CloudGuest multi-tenant SaaS platform.

## Overview

This module provides comprehensive authentication and identity management including:
- User registration and login
- JWT-based token authentication
- Password security with Argon2 hashing
- Email verification
- Password reset functionality
- Multi-device session management
- Account lockout and rate limiting
- Security audit trails

## Features

### ✅ Authentication
- Email/password login
- User registration
- JWT access tokens (15 min expiry)
- Refresh token rotation (7 day expiry)
- Token revocation and blacklisting
- Session management with device tracking

### ✅ Security
- Argon2id password hashing
- Rate limiting (5 attempts per 15 minutes)
- Account lockout (30 minutes after 5 failed attempts)
- Device fingerprinting and IP tracking
- Failed login attempt logging
- Suspicious activity detection
- Constant-time password comparison

### ✅ Password Management
- Password strength validation
- Password history (prevent reuse of last 5)
- Password expiry tracking
- Change password endpoint
- Forgot password flow
- Reset password with token

### ✅ Email Verification
- Email verification tokens
- Resend verification email
- Token expiry (24 hours)
- Verify email endpoint

### ✅ Multi-Session Management
- Multiple devices per user
- Per-session revocation
- Logout from all devices
- Device name tracking
- IP address and user agent tracking
- Location detection

### ✅ Audit & Logging
- Login attempt tracking
- Failed login reasons
- Device and IP logging
- Session creation/revocation events
- Password change auditing

## Architecture

```
┌─────────────────────────────────────┐
│     FastAPI Routes (v1/auth)       │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│    Middleware & Dependencies        │
│  - JWT Authentication               │
│  - Current User Injection           │
│  - Device Info Extraction           │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│  Application Layer (Services)       │
│  - AuthService                      │
│  - PasswordService                  │
│  - TokenService                     │
│  - SecurityService                  │
│  - SessionService                   │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│  Infrastructure Layer               │
│  - UserRepository                   │
│  - SessionRepository                │
│  - PasswordHistoryRepository        │
│  - JWTHandler                       │
│  - PasswordHasher                   │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│  Data Layer                         │
│  - PostgreSQL (Users, Sessions)     │
│  - Redis (Tokens, Cache)            │
└─────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env

# Run migrations
alembic upgrade head

# Start application
uvicorn app.main:app --reload
```

### Environment Variables

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost/cloudguest_db

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET_KEY=your-secret-key-min-32-characters-for-hs256
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30
RATE_LIMIT_WINDOW_MINUTES=15

# Email (for verification and password reset)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SENDER_EMAIL=noreply@cloudguest.io
```

## API Endpoints

### Authentication

#### POST /api/v1/auth/register
Register new user account.

**Request:**
```json
{
  "first_name": "Shresth",
  "last_name": "Pathak",
  "email": "shresth@example.com",
  "username": "shresth_p",
  "password": "SecurePass123!@#",
  "phone": "+91-9876543210",
  "timezone": "Asia/Kolkata",
  "language": "en"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully. Please verify your email.",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "shresth@example.com",
    "username": "shresth_p",
    "is_verified": false
  },
  "verification_email_sent": true
}
```

#### POST /api/v1/auth/login
Authenticate user with email and password.

**Request:**
```json
{
  "email": "shresth@example.com",
  "password": "SecurePass123!@#",
  "device_name": "Chrome on Windows 10"
}
```

**Response (200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "shresth@example.com",
    "username": "shresth_p",
    "is_verified": true,
    "status": "active"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_expires_in": 604800
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### POST /api/v1/auth/refresh
Refresh access token using refresh token (supports token rotation).

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

#### POST /api/v1/auth/logout
Logout and revoke current session.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

#### POST /api/v1/auth/verify-email
Verify email address using token from email.

**Request:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200):**
```json
{
  "message": "Email verified successfully"
}
```

#### POST /api/v1/auth/forgot-password
Initiate password reset (sends email with reset link).

**Request:**
```json
{
  "email": "shresth@example.com"
}
```

**Response (200):**
```json
{
  "message": "If an account exists with that email, a password reset link has been sent."
}
```

#### POST /api/v1/auth/reset-password
Reset password using token from email.

**Request:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "new_password": "NewSecurePass123!@#"
}
```

**Response (200):**
```json
{
  "message": "Password reset successfully. Please login with new password."
}
```

#### POST /api/v1/auth/change-password
Change password (authenticated, requires current password).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "current_password": "OldPass123!@#",
  "new_password": "NewPass123!@#"
}
```

**Response (200):**
```json
{
  "message": "Password changed successfully. Please login again."
}
```

#### GET /api/v1/auth/me
Get current authenticated user info.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "first_name": "Shresth",
  "last_name": "Pathak",
  "email": "shresth@example.com",
  "username": "shresth_p",
  "is_verified": true,
  "status": "active",
  "last_login_at": "2024-01-20T14:22:30Z",
  "timezone": "Asia/Kolkata",
  "language": "en"
}
```

#### GET /api/v1/auth/sessions
List all active sessions for current user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "device_name": "Chrome on Windows",
      "device_id": "abc123",
      "ip_address": "192.168.1.1",
      "is_current": true,
      "created_at": "2024-01-20T10:00:00Z",
      "expires_at": "2024-01-27T10:00:00Z",
      "last_activity_at": "2024-01-20T14:22:30Z"
    }
  ],
  "total": 1
}
```

#### DELETE /api/v1/auth/sessions/{session_id}
Revoke a specific session (logout from specific device).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "Session revoked successfully"
}
```

#### DELETE /api/v1/auth/logout-all
Logout from all devices (revoke all sessions).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "Logged out from all devices successfully",
  "revoked_sessions": 3
}
```

## Security Features

### Password Security
- **Algorithm:** Argon2id (memory-hard, GPU-resistant)
- **Parameters:**
  - Time Cost: 2 iterations
  - Memory Cost: 65 MB
  - Parallelism: 4 threads
- **Requirements:**
  - Minimum 12 characters
  - Uppercase, lowercase, digit, special character
  - Not in common passwords list
  - Constant-time comparison

### Rate Limiting
- **Limit:** 5 failed login attempts
- **Window:** 15 minutes
- **Action:** Account locked for 30 minutes after limit exceeded
- **Tracked by:** Email + IP address combination

### Token Security
- **Access Token:** 15 minutes expiry
- **Refresh Token:** 7 days expiry with rotation
- **Revocation:** Tokens blacklisted in Redis on logout
- **Type Validation:** All tokens include type field
- **JTI Tracking:** Unique token ID for revocation

### Multi-Session Management
- **Device Tracking:** Device ID, IP, User Agent
- **Suspicious Detection:** New location, new device, rapid login
- **Per-Device Revocation:** Can logout from specific device
- **Session Expiry:** Tied to refresh token expiry

### Audit Trail
- All login attempts logged
- Failed login reasons recorded
- Device/IP information stored
- Password changes audited
- Session events recorded

## Error Handling

All errors return appropriate HTTP status codes with descriptive messages:

```json
{
  "error": "invalid_credentials",
  "message": "Invalid email or password",
  "details": null,
  "timestamp": "2024-01-20T14:22:30Z"
}
```

**Common Errors:**
- `400` - Invalid request/input
- `401` - Unauthorized/Invalid credentials
- `403` - Access forbidden (email not verified)
- `404` - Not found
- `409` - Conflict (email/username exists)
- `429` - Too many requests (rate limited)
- `500` - Internal server error

## Testing

Run tests with pytest:

```bash
# All tests
pytest

# Specific test file
pytest tests/unit/test_auth_service.py

# With coverage
pytest --cov=app.modules.auth tests/

# Watch mode
pytest-watch

# Verbose output
pytest -vv
```

## Database Schema

### Users Table
- `id` (UUID) - Primary key
- `email` (String, unique) - Email address
- `username` (String, unique) - Username
- `password_hash` (String) - Argon2 hash
- `first_name`, `last_name` - Name fields
- `is_active` (Boolean) - Account status
- `is_verified` (Boolean) - Email verification
- `failed_login_attempts` (Integer) - Failed attempt counter
- `locked_until` (DateTime) - Account lock timestamp
- `last_login_at` (DateTime) - Last login timestamp
- Indexes on: email, username, is_active, status

### Sessions Table
- `id` (UUID) - Primary key
- `user_id` (UUID, FK) - Foreign key to users
- `device_id` (String) - Device identifier
- `device_name` (String) - Device display name
- `ip_address` (String) - Client IP
- `user_agent` (String) - User agent string
- `refresh_token_jti` (String, unique) - Token ID
- `expires_at` (DateTime) - Session expiry
- `is_active` (Boolean) - Session status
- Indexes on: user_id, device_id, refresh_token_jti

### PasswordHistory Table
- `id` (UUID) - Primary key
- `user_id` (UUID, FK) - Foreign key to users
- `password_hash` (String) - Previous password hash
- `created_at` (DateTime) - When password was set
- Indexes on: user_id

### LoginAttempts Table
- `id` (UUID) - Primary key
- `user_id` (UUID, FK) - Foreign key (nullable)
- `email` (String) - Email attempted
- `ip_address` (String) - Source IP
- `user_agent` (String) - User agent
- `success` (Boolean) - Login result
- `failure_reason` (String) - Reason for failure
- `created_at` (DateTime) - Attempt timestamp
- Indexes on: email, user_id, ip_address, created_at

## Deployment

### Production Checklist
- [ ] Set strong JWT secret key (min 32 characters)
- [ ] Configure Redis with password
- [ ] Enable HTTPS only
- [ ] Set CORS properly
- [ ] Enable rate limiting
- [ ] Configure email service
- [ ] Set secure cookie flags
- [ ] Enable logging and monitoring
- [ ] Configure backup strategy
- [ ] Set up alerts for security events

### Docker Deployment
```bash
docker-compose up -d
```

### Kubernetes Deployment
See `deployment/` directory for K8s manifests.

## Performance Considerations

- **Argon2 hashing:** ~200ms per hash (configurable)
- **JWT validation:** < 1ms per token
- **Database queries:** Optimized with indexes
- **Redis caching:** Sub-millisecond lookups
- **Connection pooling:** Configured for production

## Contributing

1. Follow PEP8 style guide
2. Add tests for new features
3. Document changes in docstrings
4. Run linting before commit

```bash
# Format code
black app/

# Lint
flake8 app/

# Type check
mypy app/
```

## License

CloudGuest - Commercial Multi-Tenant SaaS Platform

---

**Next Module:** Module 004 (Tenant Management & Multi-Tenancy)
