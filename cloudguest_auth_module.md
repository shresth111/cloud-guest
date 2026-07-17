# CloudGuest Authentication & Identity Module - Architecture Overview

## Module 003: Complete Authentication System

### Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                     │
│                    Routes & Endpoints                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Middleware & Dependencies                      │
│  ├─ JWT Auth Middleware                                    │
│  ├─ Current User Dependency                                │
│  ├─ Permission Dependency                                  │
│  └─ Optional Auth Dependency                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   Service Layer (DDD)                      │
│  ├─ AuthService                                            │
│  ├─ UserService                                            │
│  ├─ TokenService                                           │
│  ├─ PasswordService                                        │
│  ├─ SessionService                                         │
│  └─ SecurityService                                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│               Repository Layer (Data Access)               │
│  ├─ UserRepository                                         │
│  ├─ SessionRepository                                      │
│  ├─ PasswordHistoryRepository                              │
│  └─ LoginAttemptRepository                                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│          Data Layer (Database & Cache)                     │
│  ├─ PostgreSQL (Persistent)                                │
│  │  ├─ Users Table                                         │
│  │  ├─ Sessions Table                                      │
│  │  ├─ Password History Table                              │
│  │  └─ Login Attempts Table                                │
│  │                                                         │
│  └─ Redis (Cache & Tokens)                                 │
│     ├─ Refresh Tokens                                      │
│     ├─ Email Verification Tokens                           │
│     ├─ Password Reset Tokens                               │
│     ├─ Rate Limit Counters                                 │
│     └─ Session Cache                                       │
└─────────────────────────────────────────────────────────────┘
```

### Security Flow

```
┌─────────────────────────────────────────────────────────────┐
│  User Login Request                                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │ Validate Input        │
         │ Check Rate Limit      │
         └────────┬──────────────┘
                  │
                  ▼
         ┌───────────────────────┐
         │ Check Account Lock    │
         │ Check if Active       │
         └────────┬──────────────┘
                  │
                  ▼
         ┌───────────────────────┐
         │ Verify Password       │
         │ Argon2 Compare        │
         └────────┬──────────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
    Success             Failure
         │                 │
         ▼                 ▼
    ┌─────────┐      ┌──────────────┐
    │ Reset   │      │ Increment    │
    │ Attempts│      │ Failed Count │
    └────┬────┘      │ Lock Account │
         │           └──────┬───────┘
         ▼                  ▼
    ┌──────────────────────────────┐
    │ Generate JWT Tokens          │
    │ - Access Token (15 min)      │
    │ - Refresh Token (7 days)     │
    └────────┬─────────────────────┘
             │
             ▼
    ┌──────────────────────────────┐
    │ Create Session               │
    │ Track Device/IP/User Agent   │
    └────────┬─────────────────────┘
             │
             ▼
    ┌──────────────────────────────┐
    │ Store in Redis & DB          │
    │ Update Last Login            │
    └────────┬─────────────────────┘
             │
             ▼
    ┌──────────────────────────────┐
    │ Return Tokens & Session Info │
    └──────────────────────────────┘
```

### Token Management Strategy

**Access Token (JWT)**
- Duration: 15 minutes
- Contains: user_id, email, permissions, iat, exp
- Stored: Client-side (localStorage/sessionStorage)
- Validation: Signature + Expiry

**Refresh Token (JWT)**
- Duration: 7 days
- Contains: user_id, jti, iat, exp
- Stored: Redis + Database
- Validation: Signature + Redis Lookup
- Rotation: New refresh token issued on every refresh

**Session Record**
- Duration: Tied to refresh token expiry
- Tracks: Device ID, IP Address, User Agent
- Stored: PostgreSQL + Redis Cache
- Revocation: Immediate via Redis

### Multi-Session Architecture

```
User (shresth@verbaflo.ai)
├─ Session 1 (Desktop - Chrome - Delhi)
│  ├─ device_id: uuid-xxx
│  ├─ ip_address: 192.168.1.1
│  ├─ user_agent: Chrome/128.0
│  ├─ created_at: 2024-01-01 10:00
│  └─ expires_at: 2024-01-08 10:00
│
├─ Session 2 (Mobile - Safari - Mumbai)
│  ├─ device_id: uuid-yyy
│  ├─ ip_address: 203.0.113.1
│  ├─ user_agent: Safari/17.0
│  ├─ created_at: 2024-01-02 14:30
│  └─ expires_at: 2024-01-09 14:30
│
└─ Session 3 (Tablet - Firefox - Bangalore)
   ├─ device_id: uuid-zzz
   ├─ ip_address: 198.51.100.1
   ├─ user_agent: Firefox/121.0
   ├─ created_at: 2024-01-03 08:15
   └─ expires_at: 2024-01-10 08:15
```

### Rate Limiting Strategy

```
Login Attempts (per IP/Email):
├─ Attempts 1-5: No action
├─ Attempts 6-10: Progressive delays
├─ Attempts 11+: Account lock (30 minutes)

Failed Attempts Storage (Redis):
├─ Key: f"login_attempt:{email}:{ip}"
├─ Value: {"count": 5, "first_attempt": timestamp}
├─ Expiry: 1 hour
```

### Password Security Pipeline

```
User Input Password
        │
        ▼
┌───────────────────────────────────┐
│ Validate Password Strength        │
│ ├─ Min 12 characters             │
│ ├─ Mix of cases                  │
│ ├─ Numbers & Special chars       │
│ └─ Not in common passwords db    │
└────────┬────────────────────────────┘
         │
         ▼
┌───────────────────────────────────┐
│ Hash with Argon2                  │
│ ├─ Time Cost: 2                   │
│ ├─ Memory Cost: 65536 KB          │
│ ├─ Parallelism: 4                 │
│ └─ Hash Length: 32                │
└────────┬────────────────────────────┘
         │
         ▼
┌───────────────────────────────────┐
│ Store Hash in Database            │
│ Store in Password History         │
│ Never allow password reuse (5)    │
└───────────────────────────────────┘
```

### Error Handling Strategy

| Error | HTTP Code | Response | Logging |
|-------|-----------|----------|---------|
| Invalid Credentials | 401 | Generic message | High |
| Account Locked | 429 | Retry after | Medium |
| Email Not Verified | 403 | Verification link | Low |
| Token Expired | 401 | Refresh endpoint | Low |
| Token Invalid | 401 | Generic message | High |
| Rate Limited | 429 | Retry after | Medium |
| Account Inactive | 403 | Contact admin | High |

### Audit Trail

All security events logged:
- Login attempts (success/failure)
- Password changes
- Email verifications
- Session creations/revocations
- Account lockouts
- Failed authentication attempts
- Suspicious activity patterns

---

**Next: Folder Structure & Database Models**
