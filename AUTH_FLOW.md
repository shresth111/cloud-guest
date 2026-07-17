# CloudGuest Authentication Flow Documentation

Detailed walkthrough of all authentication flows with sequence diagrams and code examples.

## Table of Contents
1. Registration Flow
2. Email Verification Flow
3. Login Flow
4. Token Refresh Flow
5. Password Reset Flow
6. Password Change Flow
7. Logout Flow
8. Multi-Session Management

---

## 1. Registration Flow

### Process Overview
```
User Signup Input
        │
        ▼
Validate Input (Email, Username, Password Strength)
        │
        ▼
Check Email/Username Uniqueness
        │
        ▼
Hash Password with Argon2
        │
        ▼
Create User in Database
        │
        ▼
Generate Verification Token
        │
        ▼
Store Token in Redis (24h expiry)
        │
        ▼
Send Verification Email
        │
        ▼
Return User Info (Not Verified)
```

### Sequence Diagram
```
User                API              Database            Redis             Email
 │                   │                  │                  │               │
 ├──POST /register──>│                  │                  │               │
 │                   ├──Validate───────>│                  │               │
 │                   │<─────OK─────────┤                  │               │
 │                   │                  │                  │               │
 │                   ├─Hash Password (Argon2)             │               │
 │                   │                  │                  │               │
 │                   ├──CREATE User───>│                  │               │
 │                   │<───User(id)─────┤                  │               │
 │                   │                  │                  │               │
 │                   ├─Generate Token──────────SET────────>│               │
 │                   │                  │         (24h)    │               │
 │                   │                  │                  │               │
 │                   ├──────────────────────────────────────────Send─────>│
 │                   │                  │                  │     Email     │
 │                   │                  │                  │               │
 │<──201 Created────┤                  │                  │               │
 │ (user, token)    │                  │                  │               │
```

### Code Example
```python
# Request
POST /api/v1/auth/register
{
  "first_name": "Shresth",
  "last_name": "Pathak",
  "email": "shresth@example.com",
  "username": "shresth_p",
  "password": "SecurePass123!@#",
  "timezone": "Asia/Kolkata"
}

# Response (201)
{
  "message": "User registered successfully",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "shresth@example.com",
    "is_verified": false
  },
  "verification_email_sent": true
}
```

### Security Measures
- Password strength validation (12+ chars, uppercase, lowercase, digit, special)
- Email address validation
- Username uniqueness check
- Argon2 password hashing (not reversible)
- Verification token single-use
- Token expiry after 24 hours

---

## 2. Email Verification Flow

### Process Overview
```
User Receives Email with Verification Link
        │
        ▼
User Clicks Link (GET request with token)
        │
        ▼
API Validates Token
        │
        ├─ If Invalid/Expired
        │   └─> 401 Error
        │
        ▼
Lookup User by Token
        │
        ▼
Mark Email as Verified
        │
        ▼
Delete Token from Redis
        │
        ▼
Return Success
```

### Sequence Diagram
```
User        Email Link           API        Database        Redis
 │              │                 │            │             │
 ├─Click Link──>│                 │            │             │
 │              ├──GET /verify───>│            │             │
 │              │                 ├─GET Token──────────────>│
 │              │                 │<───Token ID (or null)───┤
 │              │                 │                         │
 │              │                 ├─Lookup User─────────────>│
 │              │                 │<───User (if exists)─────┤
 │              │                 │                         │
 │              │                 ├─UPDATE is_verified───────>│
 │              │                 │<───OK──────────────────┤
 │              │                 │                         │
 │              │                 ├─DELETE Token─────────────>│
 │              │                 │                         │
 │              │<──200 OK────────┤                         │
 │              │   (verified)    │                         │
 │<─Redirect────┤                 │                         │
```

### Code Example
```python
# Verification Link in Email
https://app.cloudguest.io/verify?token=550e8400-e29b-41d4-a716-446655440000

# API Request
POST /api/v1/auth/verify-email
{
  "token": "550e8400-e29b-41d4-a716-446655440000"
}

# Response (200)
{
  "message": "Email verified successfully"
}
```

### Error Scenarios
| Scenario | Status | Message |
|----------|--------|---------|
| Token not found | 400 | Invalid or expired token |
| Token expired (>24h) | 400 | Verification link has expired |
| User already verified | 200 | Already verified (idempotent) |
| Database error | 500 | Internal server error |

---

## 3. Login Flow

### Process Overview
```
User Submits Credentials (Email + Password + Device Info)
        │
        ▼
Validate Input Format
        │
        ▼
Check Rate Limiting (by email + IP)
        ├─ If Rate Limited (>5 attempts in 15 min)
        │   └─> 429 Too Many Requests
        │
        ▼
Query User by Email
        ├─ If Not Found
        │   ├─> Log Failed Attempt
        │   └─> Return 401 (generic message)
        │
        ▼
Check Account Active Status
        ├─ If Inactive
        │   └─> 401 Account Inactive
        │
        ▼
Check Account Lock Status
        ├─ If Locked Until > Now
        │   └─> 429 Account Locked
        │
        ▼
Verify Password (Argon2 comparison)
        ├─ If Mismatch
        │   ├─> Increment Failed Attempts Counter
        │   ├─> If Failed Attempts >= 5
        │   │   └─> Lock Account for 30 minutes
        │   ├─> Log Failed Attempt
        │   └─> Return 401 (generic message)
        │
        ▼
Check Email Verified
        ├─ If Not Verified
        │   └─> 403 Email Not Verified
        │
        ▼
Reset Failed Attempts to 0
        │
        ▼
Generate JWT Tokens (Access + Refresh)
        │
        ├─> Access Token: 15 min expiry
        │   └─ Contains: user_id, email, iat, exp
        │
        ├─> Refresh Token: 7 day expiry
        │   └─ Contains: user_id, jti (unique ID), iat, exp
        │
        ▼
Create Session in Database
        ├─ Store: user_id, device_id, ip_address, user_agent
        ├─ Store: refresh_token_jti
        ├─ Set expires_at: now + 7 days
        │
        ▼
Cache Refresh Token in Redis (7 day expiry)
        │
        ├─ Key: f"refresh_token:{jti}"
        ├─ Value: user_id
        │
        ▼
Update User Last Login
        │
        ▼
Log Successful Login
        │
        ▼
Return Tokens + Session Info (200)
```

### Sequence Diagram
```
User          Device          API        Redis         Database         Email
 │              │              │           │              │             │
 ├─POST Login──>│              │           │              │             │
 │ (credentials) │              │           │              │             │
 │              │              │           │              │             │
 │              │              ├─Check Rate Limit────────>│             │
 │              │              │<─OK──────────────────────┤             │
 │              │              │                          │             │
 │              │              ├─GET User by Email────────────────────>│
 │              │              │<─User───────────────────────────────┤
 │              │              │                          │             │
 │              │              ├─Check Active/Lock────────┤             │
 │              │              ├─Verify Password (Argon2) │             │
 │              │              │                          │             │
 │              │              ├─Generate Access Token    │             │
 │              │              ├─Generate Refresh Token   │             │
 │              │              │                          │             │
 │              │              ├─CREATE Session───────────────────────>│
 │              │              │<─Session(id)──────────────────────────┤
 │              │              │                          │             │
 │              │              ├─SET Refresh Token (7d)───>             │
 │              │              │<─OK───────────────────────┤             │
 │              │              │                          │             │
 │              │              ├─UPDATE Last Login───────────────────>│
 │              │              │<─OK───────────────────────────────┤
 │              │              │                          │             │
 │              │<──200 OK─────┤                          │             │
 │              │ (tokens)     │                          │             │
 │<─Redirect────┤              │                          │             │
```

### Code Example
```python
# Request
POST /api/v1/auth/login
{
  "email": "shresth@example.com",
  "password": "SecurePass123!@#",
  "device_name": "Chrome on Windows 10"
}

# Headers (automatically captured)
User-Agent: Mozilla/5.0...
X-Forwarded-For: 203.0.113.1  (or from connection)

# Response (200)
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "shresth@example.com",
    "username": "shresth_p",
    "is_verified": true,
    "last_login_at": "2024-01-20T14:22:30Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6InNocmVzdGhAZXhhbXBsZS5jb20iLCJqdGkiOiJhYmMxMjMiLCJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNzA1NzU3MzUwLCJleHAiOjE3MDU3NTgyNTB9.SIGNATURE",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJqdGkiOiJ4eXoxMjMiLCJ0eXBlIjoicmVmcmVzaCIsImlhdCI6MTcwNTc1NzM1MCwiZXhwIjoxNzA2MzYyMTUwfQ.SIGNATURE",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_expires_in": 604800
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

### Error Handling
```python
# 401 Invalid Credentials
{
  "error": "invalid_credentials",
  "message": "Invalid email or password",
  "timestamp": "2024-01-20T14:22:30Z"
}

# 429 Account Locked
{
  "error": "account_locked",
  "message": "Account is locked after 5 failed attempts. Try again in 30 minutes.",
  "locked_until": "2024-01-20T14:52:30Z",
  "timestamp": "2024-01-20T14:22:30Z"
}

# 403 Email Not Verified
{
  "error": "email_not_verified",
  "message": "Email not verified. Please check your email for verification link.",
  "timestamp": "2024-01-20T14:22:30Z"
}
```

### Security: Account Lockout Mechanism
```
Failed Attempts Timeline:
├─ Attempt 1: Failed (0 sec after first attempt)
├─ Attempt 2: Failed (5 sec after first)
├─ Attempt 3: Failed (10 sec after first)
├─ Attempt 4: Failed (15 sec after first)
├─ Attempt 5: Failed (20 sec after first)
│             └─> ACCOUNT LOCKED for 30 minutes
│
├─ Attempt 6: Locked (25 sec after first)
│   └─> 429 Rate Limited
│
└─ Attempt 7+ (within 15 min window): Rate Limited
    └─> Window expires after 15 minutes
    └─> Counter resets on successful login

Unlock Mechanism:
- Automatic unlock after 30 minutes
- No manual unlock endpoint (security)
- Force password reset available
```

---

## 4. Token Refresh Flow

### Process Overview
```
Client Has Expired Access Token + Valid Refresh Token
        │
        ▼
Send Refresh Request with Refresh Token
        │
        ▼
Validate Refresh Token Signature
        ├─ If Invalid Signature
        │   └─> 401 Invalid Token
        │
        ▼
Check Token Type (must be 'refresh')
        ├─ If Type != 'refresh'
        │   └─> 401 Wrong Token Type
        │
        ▼
Lookup Token JTI in Redis (Blacklist Check)
        ├─ If Not Found (revoked/expired)
        │   └─> 401 Token Expired/Revoked
        │
        ▼
Get User by Token Subject
        ├─ If User Deleted/Inactive
        │   └─> 401 User Not Active
        │
        ▼
Revoke Old Refresh Token (Remove from Redis)
        │
        ▼
Generate NEW Access Token
        ├─> Same user_id, email, iat, exp
        │
        ▼
Generate NEW Refresh Token (Token Rotation)
        ├─> New JTI (unique ID)
        ├─> New iat, exp
        │
        ▼
Cache NEW Refresh Token in Redis (7 day expiry)
        │
        ▼
Update Session with NEW Refresh Token JTI
        │
        ▼
Return New Token Pair (200)
```

### Sequence Diagram
```
Client          API           Redis         Database
  │              │              │             │
  ├─Refresh─────>│              │             │
  │ (old token)  │              │             │
  │              │              │             │
  │              ├─Validate Token─────────────>│
  │              │              │             │
  │              ├─Check JTI────────────────>│
  │              │<─Found (valid)────────────┤
  │              │              │             │
  │              ├─Revoke Old JTI────────────>│
  │              │<─OK────────────────────────┤
  │              │              │             │
  │              ├─Generate New Tokens        │
  │              │              │             │
  │              ├─Store New JTI──────────────>│
  │              │<─OK────────────────────────┤
  │              │              │             │
  │              ├─UPDATE Session──────────────>│
  │              │<─OK────────────────────────┤
  │              │              │             │
  │<─200 OK─────┤              │             │
  │ (new tokens) │              │             │
```

### Code Example
```python
# Client Implementation (JavaScript)
async function refreshAccessToken() {
  const response = await fetch('/api/v1/auth/refresh', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      refresh_token: localStorage.getItem('refresh_token')
    })
  });
  
  const data = await response.json();
  
  if (response.ok) {
    // Store new tokens
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    
    return data;
  } else {
    // Tokens invalid - redirect to login
    window.location.href = '/login';
  }
}

// Use in API interceptor
api.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      await refreshAccessToken();
      // Retry original request
      return api(error.config);
    }
    return Promise.reject(error);
  }
);
```

### Token Rotation Benefits
- **Security:** Old tokens become invalid immediately
- **Breach Mitigation:** Attacker needs both access + refresh tokens
- **Audit Trail:** Each token has unique JTI for tracking
- **Session Control:** Server-side revocation possible anytime

---

## 5. Password Reset Flow

### Process Overview
```
User Forgets Password
        │
        ▼
POST /forgot-password (email)
        │
        ├─ Check if User Exists
        │ │ (Note: Response same regardless)
        │ │
        │ ├─ If Exists
        │ │   ├─ Generate Reset Token (UUID)
        │ │   ├─ Store in Redis (1 hour expiry)
        │ │   └─ Send Reset Email
        │ │
        │ └─ If Not Exists
        │     └─ Log for security monitoring
        │
        ▼
Return Success Message (always)
        │ (Security: Never reveal if email exists)
        │
        ├─────────── User Receives Email ───────────
        │
        ▼
User Clicks Reset Link
        │
        ▼
POST /reset-password (token + new_password)
        │
        ▼
Validate Reset Token in Redis
        ├─ If Not Found/Expired
        │   └─> 400 Invalid Token
        │
        ▼
Validate New Password Strength
        ├─ If Weak
        │   └─> 400 Password Too Weak
        │
        ▼
Lookup User by Token
        │
        ▼
Hash New Password (Argon2)
        │
        ▼
Update Password Hash in Database
        │
        ▼
Store in Password History (prevent reuse)
        │
        ▼
Revoke ALL Sessions (Force re-login everywhere)
        │
        ▼
Delete Reset Token from Redis
        │
        ▼
Return Success
```

### Sequence Diagram (Forgot Password)
```
User          Email           API          Database        Redis
 │             │              │             │              │
 ├─Forgot Pwd─>│              │             │              │
 │ (email)     │              │             │              │
 │             │              │             │              │
 │             │              ├─GET User────────────────>│
 │             │              │<─User──────────────────┤
 │             │              │                        │
 │             │              ├─Generate Token         │
 │             │              │                        │
 │             │              ├─SET Token (1h)─────────>
 │             │              │<─OK────────────────────┤
 │             │              │                        │
 │             │              ├──────────SEND Email────>
 │             │<──────────────────────────────────────┤
 │             │   Reset Link with Token               │
 │             │                                       │
 │<─200 OK────┤             │             │
```

### Code Example
```python
# Step 1: Forgot Password
POST /api/v1/auth/forgot-password
{
  "email": "shresth@example.com"
}

# Response (200) - Same regardless if user exists
{
  "message": "If an account exists with that email, a password reset link has been sent."
}

# Email Contains Link
https://app.cloudguest.io/reset-password?token=550e8400-e29b-41d4-a716-446655440000

# Step 2: Reset Password
POST /api/v1/auth/reset-password
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "new_password": "NewSecurePass123!@#"
}

# Response (200)
{
  "message": "Password reset successfully. Please login with new password."
}
```

### Security Measures
- **Token Single-Use:** Deleted after first use
- **Token Expiry:** Only valid for 1 hour
- **Email Verification:** Confirms identity
- **Generic Response:** Doesn't reveal if email exists
- **Session Revocation:** All sessions invalidated
- **Password History:** Can't reuse old passwords

---

## 6. Password Change Flow

### Process Overview
```
User Authenticated (Has Valid Access Token)
        │
        ▼
POST /change-password (current_pwd + new_pwd)
        │
        ▼
Verify Current Password
        ├─ If Mismatch
        │   └─> 401 Wrong Current Password
        │
        ▼
Validate New Password Strength
        ├─ If Weak
        │   └─> 400 Password Too Weak
        │
        ▼
Check Password History (last 5)
        ├─ If Same as Any Previous 5
        │   └─> 400 Cannot Reuse Recent Password
        │
        ▼
Check if Same as Current
        ├─ If Same
        │   └─> 400 New Password Same as Current
        │
        ▼
Hash New Password
        │
        ▼
Update Password in Database
        │
        ▼
Store in Password History
        │
        ▼
Cleanup Old History (keep last 5)
        │
        ▼
Revoke ALL Sessions (Force re-login on all devices)
        │
        ▼
Return Success
```

### Code Example
```python
# Request
POST /api/v1/auth/change-password
Headers:
  Authorization: Bearer <access_token>

{
  "current_password": "OldPass123!@#",
  "new_password": "NewPass123!@#"
}

# Response (200)
{
  "message": "Password changed successfully. Please login again."
}

# Error Cases
# 401 - Wrong current password
{
  "error": "invalid_credentials",
  "message": "Current password is incorrect"
}

# 400 - Password history violation
{
  "error": "password_error",
  "message": "Password was used recently. Choose different password."
}
```

### Password History Logic
```
User's Password Timeline:
├─ 2024-01-01: pass_v1 ✓ Hashed and stored
├─ 2024-01-05: pass_v2 ✓ Hashed and stored
├─ 2024-01-10: pass_v3 ✓ Hashed and stored
├─ 2024-01-15: pass_v4 ✓ Hashed and stored
├─ 2024-01-20: pass_v5 ✓ Hashed and stored (current)
└─ 2024-01-25: Cannot be pass_v1, v2, v3, v4, or v5

Cleanup:
When new password set, keep only latest 5
├─ If 6th password added
│   └─> Delete pass_v1 (oldest)
│
└─ Only last 5 prevented from reuse
```

---

## 7. Logout Flow

### Process Overview
```
User Clicks Logout (Has Access Token + Refresh Token)
        │
        ▼
POST /logout (refresh_token in body)
        │
        ▼
Validate Access Token (from Authorization header)
        │
        ▼
Lookup and Revoke Session by ID
        │
        ├─ Mark is_active = false in DB
        │
        ▼
Revoke Refresh Token (Remove from Redis)
        │
        ├─ Delete from cache
        │ └─ Any use will fail immediately
        │
        ▼
Delete Session Cache
        │
        ▼
Return Success
        │
        ▼
Client Clears Local Storage
        │
        ├─ Delete access_token
        ├─ Delete refresh_token
        ├─ Delete session_id
        │
        ▼
Redirect to Login Page
```

### Code Example
```python
# Frontend Logout
async function logout() {
  const refreshToken = localStorage.getItem('refresh_token');
  
  await fetch('/api/v1/auth/logout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      refresh_token: refreshToken
    })
  });
  
  // Clear storage
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('session_id');
  
  // Redirect
  window.location.href = '/login';
}

# Backend Logout
POST /api/v1/auth/logout
Headers:
  Authorization: Bearer <access_token>

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# Response (200)
{
  "message": "Logged out successfully"
}
```

---

## 8. Multi-Session Management

### List Sessions
```
User Requests Session List
        │
        ▼
GET /sessions
        │
        ▼
Query All Active Sessions for User
        │
        ├─ Check expires_at > now
        ├─ Filter is_active = true
        │
        ▼
For Each Session:
        ├─ Identify if current session (by JWT)
        ├─ Include device, IP, user agent info
        │
        ▼
Return Session List
```

### Revoke Specific Session
```
User Selects Device to Logout From
        │
        ▼
DELETE /sessions/{session_id}
        │
        ▼
Verify User Owns Session
        ├─ If Not Owner
        │   └─> 403 Forbidden
        │
        ▼
Mark Session as Inactive (is_active = false)
        │
        ▼
Revoke Refresh Token for That Session
        │
        ├─ Delete from Redis
        │
        ▼
Clear Session Cache
        │
        ▼
Return Success
        │
        ├─ Other sessions unaffected
        ├─ User logged in on other devices
```

### Logout All Devices
```
User Chooses "Logout All Devices"
        │
        ▼
DELETE /logout-all
        │
        ▼
Query All Active Sessions for User
        │
        ▼
For Each Session:
        ├─ Mark is_active = false
        ├─ Revoke refresh_token_jti
        │   └─ Delete from Redis
        │
        ▼
Return Count of Revoked Sessions
        │
        ├─ e.g., "3 sessions logged out"
        │
        ▼
Client Clears Tokens
        │
        ▼
Redirect to Login
```

### Code Example
```python
# List Sessions
GET /api/v1/auth/sessions
Headers:
  Authorization: Bearer <access_token>

# Response
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "device_name": "Chrome on Windows",
      "device_id": "a1b2c3d4",
      "ip_address": "203.0.113.1",
      "location": "Delhi, India",
      "browser": "Chrome 120.0",
      "os": "Windows 11",
      "device_type": "desktop",
      "is_current": true,
      "created_at": "2024-01-20T10:00:00Z",
      "expires_at": "2024-01-27T10:00:00Z",
      "last_activity_at": "2024-01-20T14:22:30Z",
      "is_active": true
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "device_name": "Safari on iPhone",
      "device_id": "x9y8z7w6",
      "ip_address": "198.51.100.2",
      "location": "Mumbai, India",
      "browser": "Safari 17.1",
      "os": "iOS 17.2",
      "device_type": "mobile",
      "is_current": false,
      "created_at": "2024-01-18T09:30:00Z",
      "expires_at": "2024-01-25T09:30:00Z",
      "last_activity_at": "2024-01-19T08:15:00Z",
      "is_active": true
    }
  ],
  "total": 2
}

# Revoke Specific Session
DELETE /api/v1/auth/sessions/550e8400-e29b-41d4-a716-446655440001
Headers:
  Authorization: Bearer <access_token>

# Response
{
  "message": "Session revoked successfully"
}

# Logout All Devices
DELETE /api/v1/auth/logout-all
Headers:
  Authorization: Bearer <access_token>

# Response
{
  "message": "Logged out from all devices successfully",
  "revoked_sessions": 2
}
```

---

## Token Structure

### Access Token Payload
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "jti": "abc-123-def",
  "type": "access",
  "iat": 1705757350,
  "exp": 1705758250
}
```

### Refresh Token Payload
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "jti": "xyz-789-uvw",
  "type": "refresh",
  "iat": 1705757350,
  "exp": 1706362150
}
```

---

## Security Considerations

### Rate Limiting
- **5 failed login attempts** per email + IP per 15 minutes
- **Account locked** for 30 minutes after limit
- **Counter resets** on successful login

### Token Security
- **Access tokens** short-lived (15 minutes)
- **Refresh tokens** longer-lived (7 days) with rotation
- **JTI tracking** for revocation
- **Type validation** (access vs refresh)
- **Redis blacklist** for revoked tokens

### Password Security
- **Argon2id** hashing (memory-hard, GPU-resistant)
- **12+ characters** required
- **Character diversity** (uppercase, lowercase, digit, special)
- **Password history** (prevent reuse of last 5)
- **Constant-time comparison** (resistant to timing attacks)

### Session Security
- **Per-device sessions** with unique tracking
- **Device fingerprinting** via IP + user agent
- **Suspicious activity detection** (new location, new device)
- **Session expiry** tied to refresh token
- **Per-device revocation** possible

---

**Next Steps:** See API.md for detailed endpoint specifications
