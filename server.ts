import express, { Request, Response, NextFunction } from "express";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodePath from "path";

// In-memory Database State
const JWT_SECRET = "cloudguest-secret-key-123456";

interface CustomRequest extends Request {
  userId?: string;
  requestId?: string;
}

// Preseeded Data
const users = [
  {
    id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
    first_name: "John",
    last_name: "Doe",
    email: "john.doe@example.com",
    username: "johndoe",
    passwordHash: bcrypt.hashSync("password123", 10),
    phone: "+15551234567",
    designation: "Network Administrator",
    department: "IT Infrastructure",
    timezone: "UTC",
    language: "en",
    status: "active",
    is_active: true,
    is_verified: true,
    email_verified_at: new Date().toISOString(),
    last_login_at: new Date().toISOString(),
    created_at: new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  }
];

const organizations = [
  {
    id: "0a112233-4455-6677-8899-aabbccddeeff",
    name: "Acme Global Networks",
    slug: "acme-global",
    legal_name: "Acme Global Networks LLC",
    org_type: "MSP",
    status: "active",
    parent_organization_id: null,
    contact_email: "noc@acme-global.com",
    contact_phone: "+15559876543",
    timezone: "America/New_York",
    default_locale: "en_US",
    settings: { auto_upgrade_firmware: true, alerting_channel: "slack" },
    subscription_tier: "enterprise",
    created_at: new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "1b223344-5566-7788-99aa-bbccddeeff00",
    name: "Northstar Retail Inc",
    slug: "northstar-retail",
    legal_name: "Northstar Retail Group",
    org_type: "Tenant",
    status: "active",
    parent_organization_id: "0a112233-4455-6677-8899-aabbccddeeff",
    contact_email: "support@northstar-retail.com",
    contact_phone: "+15553216540",
    timezone: "America/Los_Angeles",
    default_locale: "en_US",
    settings: { auto_upgrade_firmware: false },
    subscription_tier: "pro",
    created_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "2c334455-6677-8899-aaee-bbccddeeff11",
    name: "Westside Clinics",
    slug: "westside-clinics",
    legal_name: "Westside Medical Alliance",
    org_type: "Tenant",
    status: "suspended",
    parent_organization_id: "0a112233-4455-6677-8899-aabbccddeeff",
    contact_email: "it@westsideclinics.org",
    contact_phone: "+15557778888",
    timezone: "America/Denver",
    default_locale: "en_US",
    settings: { HIPAA_compliance_mode: true },
    subscription_tier: "pro",
    created_at: new Date(Date.now() - 20 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  }
];

const locations = [
  {
    id: "loc-0a112233-4455-6677-8899-aabbccddee11",
    organization_id: "0a112233-4455-6677-8899-aabbccddeeff",
    name: "New York HQ",
    slug: "ny-hq",
    address_line1: "120 Broadway",
    address_line2: "Suite 3400",
    city: "New York",
    state: "NY",
    postal_code: "10271",
    country: "USA",
    timezone: "America/New_York",
    latitude: 40.7081,
    longitude: -74.0113,
    created_at: new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "loc-1b223344-5566-7788-99aa-bbccddeeff22",
    organization_id: "1b223344-5566-7788-99aa-bbccddeeff00",
    name: "Seattle Flagship Store",
    slug: "seattle-flagship",
    address_line1: "500 Pine Street",
    address_line2: "",
    city: "Seattle",
    state: "WA",
    postal_code: "98101",
    country: "USA",
    timezone: "America/Los_Angeles",
    latitude: 47.6119,
    longitude: -122.3371,
    created_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  }
];

const routers = [
  {
    id: "rtr-0a112233-4455-6677-8899-aabbccddee01",
    organization_id: "0a112233-4455-6677-8899-aabbccddeeff",
    location_id: "loc-0a112233-4455-6677-8899-aabbccddee11",
    name: "Acme Core Router",
    serial_number: "7E2A08B01C2F",
    mac_address: "18:FD:74:2A:08:B0",
    ip_address: "192.168.88.1",
    model: "MikroTik RB4011iGS+5HacQ2HnD-IN",
    ros_version: "7.15.2",
    status: "online",
    last_seen_at: new Date().toISOString(),
    created_at: new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "rtr-1b223344-5566-7788-99aa-bbccddeeff02",
    organization_id: "1b223344-5566-7788-99aa-bbccddeeff00",
    location_id: "loc-1b223344-5566-7788-99aa-bbccddeeff22",
    name: "Seattle Gate hAP",
    serial_number: "AB8E19F5C124",
    mac_address: "E8:28:C1:8E:19:F5",
    ip_address: "192.168.1.1",
    model: "MikroTik hAP ac³ (RBD53iG-5HacD2HnD)",
    ros_version: "7.14.3",
    status: "online",
    last_seen_at: new Date().toISOString(),
    created_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "rtr-2c334455-6677-8899-aaee-bbccddeeff03",
    organization_id: "2c334455-6677-8899-aaee-bbccddeeff11",
    location_id: null,
    name: "Clinic West Edge CCR",
    serial_number: "CC04A8B9C10D",
    mac_address: "00:0C:42:A8:B9:C1",
    ip_address: "10.10.20.1",
    model: "MikroTik CCR2004-1G-12S+2XS",
    ros_version: "7.12.1",
    status: "offline",
    last_seen_at: new Date(Date.now() - 12 * 3600 * 1000).toISOString(),
    created_at: new Date(Date.now() - 20 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  }
];

const sessions: Array<{
  id: string;
  user_id: string;
  device_id: string;
  device_name: string;
  ip_address: string;
  user_agent: string;
  location?: string;
  is_active: boolean;
  created_at: string;
  expires_at: string;
  last_activity_at: string;
}> = [
  {
    id: "sess-9f32373c-74f4-41bd-8c43-c649987dc34b",
    user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
    device_id: "dev-macbook-chrome",
    device_name: "MacBook Pro - Google Chrome",
    ip_address: "127.0.0.1",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    location: "New York, USA",
    is_active: true,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
    last_activity_at: new Date().toISOString(),
  }
];

const organizationMembers = [
  {
    id: "mem-0a112233-4455-6677-8899-aabbccddeeff",
    organization_id: "0a112233-4455-6677-8899-aabbccddeeff",
    user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
    status: "active",
    invited_by_user_id: null,
    invited_at: null,
    joined_at: new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString(),
    is_primary_contact: true,
    created_at: new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "mem-1b223344-5566-7788-99aa-bbccddeeff00",
    organization_id: "1b223344-5566-7788-99aa-bbccddeeff00",
    user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
    status: "active",
    invited_by_user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
    invited_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    joined_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    is_primary_contact: false,
    created_at: new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString(),
    updated_at: new Date().toISOString(),
  }
];

// Helper to generate a standardized envelope (ApiResponse)
function buildResponse(success: boolean, message: string, data: any, requestId: string) {
  return {
    success,
    message,
    data,
    request_id: requestId,
  };
}

// Security & Request Context Middlewares
const requestContextMiddleware = (req: CustomRequest, res: Response, next: NextFunction) => {
  req.requestId = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11);
  next();
};

const authMiddleware = (req: CustomRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json(buildResponse(false, "Authentication required", null, req.requestId || ""));
  }
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    req.userId = payload.userId;
    next();
  } catch (error) {
    return res.status(401).json(buildResponse(false, "Invalid or expired access token", null, req.requestId || ""));
  }
};

async function startServer() {
  const app = express();
  app.use(express.json());
  app.use(requestContextMiddleware as any);

  // Security Headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    next();
  });

  // CORS (Simulated FastAPI middleware)
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID");
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  });

  const apiPrefix = "/api/v1";

  // ==========================================
  // 1. HEALTH ENDPOINTS
  // ==========================================
  app.get(`${apiPrefix}/health/live`, (req: CustomRequest, res: Response) => {
    res.json(buildResponse(true, "Service is live", {
      service: "cloud-guest",
      environment: "development",
      uptime_seconds: Math.round(process.uptime() * 1000) / 1000,
    }, req.requestId || ""));
  });

  app.get(`${apiPrefix}/health/ready`, (req: CustomRequest, res: Response) => {
    // Return mock healthy states for DB and Redis
    res.json(buildResponse(true, "Service is ready", {
      service: "cloud-guest",
      database: { status: "ok", latency_ms: 1.25 },
      redis: { status: "ok", latency_ms: 0.85 }
    }, req.requestId || ""));
  });

  // ==========================================
  // 2. AUTHENTICATION ENDPOINTS
  // ==========================================
  app.post(`${apiPrefix}/auth/register`, (req: CustomRequest, res: Response) => {
    const { first_name, last_name, email, username, password, phone, timezone, language } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json(buildResponse(false, "Email, password and username are required", null, req.requestId || ""));
    }

    if (users.find(u => u.email === email)) {
      return res.status(409).json(buildResponse(false, "User with this email already exists", null, req.requestId || ""));
    }

    const newUser = {
      id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11),
      first_name: first_name || "",
      last_name: last_name || "",
      email,
      username,
      passwordHash: bcrypt.hashSync(password, 10),
      phone: phone || "",
      designation: "",
      department: "",
      timezone: timezone || "UTC",
      language: language || "en",
      status: "active",
      is_active: true,
      is_verified: true,
      email_verified_at: new Date().toISOString(),
      last_login_at: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    users.push(newUser as any);

    const { passwordHash, ...userClean } = newUser;
    res.status(201).json(buildResponse(true, "User registered successfully", {
      message: "User registered successfully.",
      user: userClean,
      verification_email_sent: false,
    }, req.requestId || ""));
  });

  app.post(`${apiPrefix}/auth/login`, (req: CustomRequest, res: Response) => {
    const { email, password, device_name } = req.body;
    if (!email || !password) {
      return res.status(400).json(buildResponse(false, "Email and password are required", null, req.requestId || ""));
    }

    const user = users.find(u => u.email === email);
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json(buildResponse(false, "Incorrect email or password", null, req.requestId || ""));
    }

    // Generate JWT and Session
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ userId: user.id, type: "refresh" }, JWT_SECRET, { expiresIn: "7d" });

    const sessionId = "sess-" + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11));
    sessions.push({
      id: sessionId,
      user_id: user.id,
      device_id: "browser-dev",
      device_name: device_name || "Admin Web Console",
      ip_address: req.ip || "127.0.0.1",
      user_agent: req.headers["user-agent"] || "Unknown UI",
      is_active: true,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
      last_activity_at: new Date().toISOString(),
    });

    user.last_login_at = new Date().toISOString();

    const { passwordHash, ...userClean } = user;
    res.json(buildResponse(true, "Login successful", {
      user: userClean,
      tokens: {
        access_token: token,
        refresh_token: refreshToken,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_expires_in: 604800,
      },
      session_id: sessionId,
    }, req.requestId || ""));
  });

  app.get(`${apiPrefix}/auth/me`, authMiddleware as any, (req: CustomRequest, res: Response) => {
    const user = users.find(u => u.id === req.userId);
    if (!user) {
      return res.status(404).json(buildResponse(false, "User not found", null, req.requestId || ""));
    }
    const { passwordHash, ...userClean } = user;
    res.json(buildResponse(true, "Current user", userClean, req.requestId || ""));
  });

  app.get(`${apiPrefix}/auth/sessions`, authMiddleware as any, (req: CustomRequest, res: Response) => {
    const userSessions = sessions.filter(s => s.user_id === req.userId);
    res.json(buildResponse(true, "Active sessions", {
      sessions: userSessions.map(s => ({
        ...s,
        is_current: true, // simplified
      })),
      total: userSessions.length
    }, req.requestId || ""));
  });

  app.delete(`${apiPrefix}/auth/sessions/:session_id`, authMiddleware as any, (req: CustomRequest, res: Response) => {
    const index = sessions.findIndex(s => s.id === req.params.session_id && s.user_id === req.userId);
    if (index === -1) {
      return res.status(404).json(buildResponse(false, "Session not found", null, req.requestId || ""));
    }
    sessions.splice(index, 1);
    res.json(buildResponse(true, "Session revoked", { message: "Session revoked" }, req.requestId || ""));
  });

  app.post(`${apiPrefix}/auth/logout`, (req: CustomRequest, res: Response) => {
    // Revoke token / logout
    res.json(buildResponse(true, "Logged out successfully", { message: "Logged out successfully" }, req.requestId || ""));
  });

  // ==========================================
  // 3. ORGANIZATIONS ENDPOINTS
  // ==========================================
  app.get(`${apiPrefix}/organizations`, (req: CustomRequest, res: Response) => {
    const search = req.query.search as string;
    let filtered = [...organizations];
    if (search) {
      filtered = filtered.filter(org =>
        org.name.toLowerCase().includes(search.toLowerCase()) ||
        org.slug.toLowerCase().includes(search.toLowerCase())
      );
    }

    res.json(buildResponse(true, "Organizations retrieved", {
      items: filtered,
      page: 1,
      page_size: 25,
      total_items: filtered.length,
      total_pages: 1,
      has_next: false,
      has_previous: false,
    }, req.requestId || ""));
  });

  app.post(`${apiPrefix}/organizations`, (req: CustomRequest, res: Response) => {
    const { name, slug, legal_name, org_type, status, contact_email, contact_phone, timezone, default_locale, settings, subscription_tier } = req.body;
    if (!name || !slug || !contact_email) {
      return res.status(400).json(buildResponse(false, "Name, slug and contact email are required", null, req.requestId || ""));
    }

    const newOrg = {
      id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11),
      name,
      slug,
      legal_name: legal_name || name,
      org_type: org_type || "Tenant",
      status: status || "active",
      parent_organization_id: null,
      contact_email,
      contact_phone: contact_phone || "",
      timezone: timezone || "UTC",
      default_locale: default_locale || "en_US",
      settings: settings || {},
      subscription_tier: subscription_tier || "free",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    organizations.push(newOrg);
    res.status(201).json(buildResponse(true, "Organization created", newOrg, req.requestId || ""));
  });

  app.get(`${apiPrefix}/organizations/:id`, (req: CustomRequest, res: Response) => {
    const org = organizations.find(o => o.id === req.params.id);
    if (!org) {
      return res.status(404).json(buildResponse(false, "Organization not found", null, req.requestId || ""));
    }
    res.json(buildResponse(true, "Organization retrieved", org, req.requestId || ""));
  });

  app.put(`${apiPrefix}/organizations/:id`, (req: CustomRequest, res: Response) => {
    const org = organizations.find(o => o.id === req.params.id);
    if (!org) {
      return res.status(404).json(buildResponse(false, "Organization not found", null, req.requestId || ""));
    }

    Object.assign(org, req.body, { updated_at: new Date().toISOString() });
    res.json(buildResponse(true, "Organization updated", org, req.requestId || ""));
  });

  app.delete(`${apiPrefix}/organizations/:id`, (req: CustomRequest, res: Response) => {
    const index = organizations.findIndex(o => o.id === req.params.id);
    if (index === -1) {
      return res.status(404).json(buildResponse(false, "Organization not found", null, req.requestId || ""));
    }
    organizations.splice(index, 1);
    res.json(buildResponse(true, "Organization archived", { message: "Organization archived" }, req.requestId || ""));
  });

  app.get(`${apiPrefix}/organizations/:id/members`, (req: CustomRequest, res: Response) => {
    const members = organizationMembers.filter(m => m.organization_id === req.params.id);
    res.json(buildResponse(true, "Organization members retrieved", members, req.requestId || ""));
  });

  app.post(`${apiPrefix}/organizations/:id/members`, (req: CustomRequest, res: Response) => {
    const { user_id, is_primary_contact } = req.body;
    const orgId = req.params.id;
    const newMember = {
      id: "mem-" + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11)),
      organization_id: orgId,
      user_id: user_id || "9f32373c-74f4-41bd-8c43-c649987dc34a",
      status: "active",
      invited_by_user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a",
      invited_at: new Date().toISOString(),
      joined_at: new Date().toISOString(),
      is_primary_contact: is_primary_contact || false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    organizationMembers.push(newMember);
    res.status(201).json(buildResponse(true, "Member invited", newMember, req.requestId || ""));
  });

  app.delete(`${apiPrefix}/organizations/:id/members/:member_id`, (req: CustomRequest, res: Response) => {
    const index = organizationMembers.findIndex(m => m.id === req.params.member_id && m.organization_id === req.params.id);
    if (index === -1) {
      return res.status(404).json(buildResponse(false, "Member not found", null, req.requestId || ""));
    }
    organizationMembers.splice(index, 1);
    res.json(buildResponse(true, "Member removed", { message: "Member removed" }, req.requestId || ""));
  });

  // ==========================================
  // 4. LOCATIONS ENDPOINTS
  // ==========================================
  app.get(`${apiPrefix}/locations`, (req: CustomRequest, res: Response) => {
    res.json(buildResponse(true, "Locations retrieved", locations, req.requestId || ""));
  });

  app.post(`${apiPrefix}/locations`, (req: CustomRequest, res: Response) => {
    const { organization_id, name, slug, address_line1, address_line2, city, state, postal_code, country, timezone, latitude, longitude } = req.body;
    if (!name || !organization_id) {
      return res.status(400).json(buildResponse(false, "Name and organization_id are required", null, req.requestId || ""));
    }

    const newLoc = {
      id: "loc-" + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11)),
      organization_id,
      name,
      slug: slug || name.toLowerCase().replace(/ /g, "-"),
      address_line1,
      address_line2,
      city,
      state,
      postal_code,
      country: country || "USA",
      timezone: timezone || "UTC",
      latitude: latitude || 0,
      longitude: longitude || 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    locations.push(newLoc);
    res.status(201).json(buildResponse(true, "Location created", newLoc, req.requestId || ""));
  });

  app.get(`${apiPrefix}/locations/:id`, (req: CustomRequest, res: Response) => {
    const loc = locations.find(l => l.id === req.params.id);
    if (!loc) {
      return res.status(404).json(buildResponse(false, "Location not found", null, req.requestId || ""));
    }
    res.json(buildResponse(true, "Location retrieved", loc, req.requestId || ""));
  });

  app.put(`${apiPrefix}/locations/:id`, (req: CustomRequest, res: Response) => {
    const loc = locations.find(l => l.id === req.params.id);
    if (!loc) {
      return res.status(404).json(buildResponse(false, "Location not found", null, req.requestId || ""));
    }
    Object.assign(loc, req.body, { updated_at: new Date().toISOString() });
    res.json(buildResponse(true, "Location updated", loc, req.requestId || ""));
  });

  app.delete(`${apiPrefix}/locations/:id`, (req: CustomRequest, res: Response) => {
    const index = locations.findIndex(l => l.id === req.params.id);
    if (index === -1) {
      return res.status(404).json(buildResponse(false, "Location not found", null, req.requestId || ""));
    }
    locations.splice(index, 1);
    res.json(buildResponse(true, "Location deleted", { message: "Location deleted" }, req.requestId || ""));
  });

  // ==========================================
  // 5. ROUTERS ENDPOINTS
  // ==========================================
  app.get(`${apiPrefix}/routers`, (req: CustomRequest, res: Response) => {
    res.json(buildResponse(true, "Routers retrieved", routers, req.requestId || ""));
  });

  app.post(`${apiPrefix}/routers`, (req: CustomRequest, res: Response) => {
    const { organization_id, location_id, name, serial_number, mac_address, ip_address, model, ros_version } = req.body;
    if (!name || !organization_id || !serial_number || !mac_address) {
      return res.status(400).json(buildResponse(false, "Name, organization_id, serial_number and mac_address are required", null, req.requestId || ""));
    }

    const newRouter = {
      id: "rtr-" + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 11)),
      organization_id,
      location_id: location_id || null,
      name,
      serial_number,
      mac_address,
      ip_address: ip_address || "192.168.88.1",
      model: model || "MikroTik hAP ac³",
      ros_version: ros_version || "7.15",
      status: "online" as const,
      last_seen_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    routers.push(newRouter);
    res.status(201).json(buildResponse(true, "Router registered", newRouter, req.requestId || ""));
  });

  app.get(`${apiPrefix}/routers/:id`, (req: CustomRequest, res: Response) => {
    const router = routers.find(r => r.id === req.params.id);
    if (!router) {
      return res.status(404).json(buildResponse(false, "Router not found", null, req.requestId || ""));
    }
    res.json(buildResponse(true, "Router retrieved", router, req.requestId || ""));
  });

  app.put(`${apiPrefix}/routers/:id`, (req: CustomRequest, res: Response) => {
    const rtr = routers.find(r => r.id === req.params.id);
    if (!rtr) {
      return res.status(404).json(buildResponse(false, "Router not found", null, req.requestId || ""));
    }
    Object.assign(rtr, req.body, { updated_at: new Date().toISOString() });
    res.json(buildResponse(true, "Router updated", rtr, req.requestId || ""));
  });

  app.delete(`${apiPrefix}/routers/:id`, (req: CustomRequest, res: Response) => {
    const index = routers.findIndex(r => r.id === req.params.id);
    if (index === -1) {
      return res.status(404).json(buildResponse(false, "Router not found", null, req.requestId || ""));
    }
    routers.splice(index, 1);
    res.json(buildResponse(true, "Router deleted", { message: "Router deleted" }, req.requestId || ""));
  });

  // Fallback for non-supported routing or subpaths
  app.get(`${apiPrefix}/rbac*`, (req, res) => {
    res.status(501).json({ error: "RBAC domain is not yet fully migrated, but roles can be tested" });
  });

  app.get(`${apiPrefix}/users*`, (req, res) => {
    res.json(buildResponse(true, "Users list", { items: users.map(({ passwordHash, ...u }) => u) }, "req-users"));
  });

  // Vite Integration for Asset Serving
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = nodePath.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(nodePath.join(distPath, "index.html"));
    });
  }

  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server", err);
});
