import { useState, useEffect } from "react";
import {
  Activity,
  Server,
  Network,
  MapPin,
  Users,
  Wifi,
  Settings,
  LogOut,
  User as UserIcon,
  Lock,
  Plus,
  Shield,
  Key,
  Database,
  Chrome,
  Smartphone,
  Laptop,
  CheckCircle,
  XCircle,
  RefreshCw,
  LayoutDashboard
} from "lucide-react";
import { User, Session, Organization, Location, RouterDevice } from "./types";
import { Dashboard } from "./components/Dashboard";
import { OrganizationsTab } from "./components/OrganizationsTab";
import { RoutersTab } from "./components/RoutersTab";
import { ApiPlayground } from "./components/ApiPlayground";

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("cloudguest_token"));
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [locations, setLocations] = useState<Location[]>([]);
  const [routers, setRouters] = useState<RouterDevice[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);

  // Navigation & UI state
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [loading, setLoading] = useState<boolean>(true);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states for Authentication
  const [email, setEmail] = useState("john.doe@example.com");
  const [password, setPassword] = useState("password123");
  const [username, setUsername] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");

  // Base fetch wrapper
  const apiFetch = async (url: string, options: any = {}) => {
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const mergedOptions = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(url, mergedOptions);
      if (response.status === 401) {
        // Automatically logout on token expiration/invalid
        handleLogout();
        throw new Error("Session expired. Please sign in again.");
      }
      return await response.json();
    } catch (err: any) {
      console.error("API Fetch error:", err);
      throw err;
    }
  };

  // Log in
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const res = await apiFetch("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          device_name: "Web Admin Dashboard",
        }),
      });

      if (res && res.success) {
        const { access_token } = res.data.tokens;
        localStorage.setItem("cloudguest_token", access_token);
        setToken(access_token);
        setCurrentUser(res.data.user);
        setSuccessMsg("Successfully signed in.");
      } else {
        setErrorMsg(res?.message || "Invalid email or password.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to connect to the authentication service.");
    }
  };

  // Log out
  const handleLogout = () => {
    localStorage.removeItem("cloudguest_token");
    setToken(null);
    setCurrentUser(null);
    setOrganizations([]);
    setLocations([]);
    setRouters([]);
    setSessions([]);
    setActiveTab("dashboard");
  };

  // Sign up
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const res = await apiFetch("/api/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          username,
          first_name: firstName,
          last_name: lastName,
          timezone: "UTC",
          language: "en",
        }),
      });

      if (res && res.success) {
        setSuccessMsg("Account registered successfully! Please sign in.");
        setAuthMode("login");
      } else {
        setErrorMsg(res?.message || "Registration failed.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Registration failed. Please check backend health.");
    }
  };

  // Load backend data
  const loadData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      // 1. Fetch current user
      const userRes = await apiFetch("/api/v1/auth/me");
      if (userRes && userRes.success) {
        setCurrentUser(userRes.data);
      } else {
        handleLogout();
        return;
      }

      // 2. Fetch Organizations
      const orgsRes = await apiFetch("/api/v1/organizations");
      if (orgsRes && orgsRes.success) {
        setOrganizations(orgsRes.data.items || []);
      }

      // 3. Fetch Locations
      const locsRes = await apiFetch("/api/v1/locations");
      if (locsRes && locsRes.success) {
        setLocations(locsRes.data || []);
      }

      // 4. Fetch Routers
      const routersRes = await apiFetch("/api/v1/routers");
      if (routersRes && routersRes.success) {
        setRouters(routersRes.data || []);
      }

      // 5. Fetch Sessions
      const sessionsRes = await apiFetch("/api/v1/auth/sessions");
      if (sessionsRes && sessionsRes.success) {
        setSessions(sessionsRes.data.sessions || []);
      }

    } catch (err: any) {
      console.error("Error loading application states", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      loadData();
    } else {
      setLoading(false);
    }
  }, [token]);

  // Organization Operations
  const handleCreateOrg = async (orgData: Partial<Organization>) => {
    try {
      const res = await apiFetch("/api/v1/organizations", {
        method: "POST",
        body: JSON.stringify(orgData),
      });
      if (res && res.success) {
        setOrganizations((prev) => [...prev, res.data]);
        setSuccessMsg(`Organization "${orgData.name}" created.`);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to create organization.");
    }
  };

  const handleUpdateOrg = async (id: string, orgData: Partial<Organization>) => {
    try {
      const res = await apiFetch(`/api/v1/organizations/${id}`, {
        method: "PUT",
        body: JSON.stringify(orgData),
      });
      if (res && res.success) {
        setOrganizations((prev) => prev.map((org) => (org.id === id ? res.data : org)));
        setSuccessMsg("Organization updated successfully.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to update organization.");
    }
  };

  const handleDeleteOrg = async (id: string) => {
    if (!window.confirm("Are you sure you want to archive/delete this organization?")) return;
    try {
      const res = await apiFetch(`/api/v1/organizations/${id}`, {
        method: "DELETE",
      });
      if (res && res.success) {
        setOrganizations((prev) => prev.filter((org) => org.id !== id));
        setSuccessMsg("Organization archived.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to archive organization.");
    }
  };

  // Router Operations
  const handleRegisterRouter = async (routerData: Partial<RouterDevice>) => {
    try {
      const res = await apiFetch("/api/v1/routers", {
        method: "POST",
        body: JSON.stringify(routerData),
      });
      if (res && res.success) {
        setRouters((prev) => [...prev, res.data]);
        setSuccessMsg(`Router "${routerData.name}" provisioned successfully.`);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to register router.");
    }
  };

  const handleUpdateRouter = async (id: string, routerData: Partial<RouterDevice>) => {
    try {
      const res = await apiFetch(`/api/v1/routers/${id}`, {
        method: "PUT",
        body: JSON.stringify(routerData),
      });
      if (res && res.success) {
        setRouters((prev) => prev.map((r) => (r.id === id ? res.data : r)));
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to update router.");
    }
  };

  const handleDeleteRouter = async (id: string) => {
    if (!window.confirm("Are you sure you want to deregister this device?")) return;
    try {
      const res = await apiFetch(`/api/v1/routers/${id}`, {
        method: "DELETE",
      });
      if (res && res.success) {
        setRouters((prev) => prev.filter((r) => r.id !== id));
        setSuccessMsg("Router deregistered successfully.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to deregister router.");
    }
  };

  // Location Operations
  const handleCreateLocation = async (locData: Partial<Location>) => {
    try {
      const res = await apiFetch("/api/v1/locations", {
        method: "POST",
        body: JSON.stringify(locData),
      });
      if (res && res.success) {
        setLocations((prev) => [...prev, res.data]);
        setSuccessMsg(`Location "${locData.name}" created.`);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to create location.");
    }
  };

  const handleDeleteLocation = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this location?")) return;
    try {
      const res = await apiFetch(`/api/v1/locations/${id}`, {
        method: "DELETE",
      });
      if (res && res.success) {
        setLocations((prev) => prev.filter((l) => l.id !== id));
        setSuccessMsg("Location deleted successfully.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to delete location.");
    }
  };

  // Terminate active session
  const handleRevokeSession = async (sessionId: string) => {
    try {
      const res = await apiFetch(`/api/v1/auth/sessions/${sessionId}`, {
        method: "DELETE",
      });
      if (res && res.success) {
        setSessions((prev) => prev.filter((s) => s.id !== sessionId));
        setSuccessMsg("Session revoked successfully.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to revoke session.");
    }
  };

  // Helper for Session OS icons
  const getDeviceIcon = (agent: string) => {
    const ua = agent.toLowerCase();
    if (ua.includes("macintosh") || ua.includes("mac os")) return <Laptop size={16} className="text-indigo-600" />;
    if (ua.includes("iphone") || ua.includes("android")) return <Smartphone size={16} className="text-indigo-600" />;
    return <Chrome size={16} className="text-indigo-600" />;
  };

  // Auth Guard
  if (!token) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col justify-between py-12 px-4 sm:px-6 lg:px-8 font-sans selection:bg-indigo-600 selection:text-white">
        <div className="absolute top-0 left-0 w-full h-1.5 bg-gradient-to-r from-indigo-500 via-purple-500 to-sky-500"></div>

        <div className="sm:mx-auto sm:w-full sm:max-w-md my-auto space-y-6">
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-lg shadow-indigo-150 mb-4 ring-4 ring-indigo-50">
              <Network size={24} />
            </div>
            <h2 className="text-center text-3xl font-bold font-display tracking-tight text-slate-900">
              CloudGuest Console
            </h2>
            <p className="mt-2 text-center text-xs text-slate-500 font-medium">
              MikroTik Multi-Tenant Network Administration Service
            </p>
          </div>

          <div className="bg-white py-8 px-6 shadow-xl rounded-2xl border border-slate-200/80 space-y-6">
            {/* Mode selection tab */}
            <div className="flex border-b border-slate-100">
              <button
                onClick={() => { setAuthMode("login"); setErrorMsg(null); }}
                className={`w-1/2 pb-3 text-xs font-semibold uppercase tracking-wider text-center border-b-2 transition-all ${
                  authMode === "login" ? "border-indigo-600 text-indigo-600" : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Sign In
              </button>
              <button
                onClick={() => { setAuthMode("register"); setErrorMsg(null); }}
                className={`w-1/2 pb-3 text-xs font-semibold uppercase tracking-wider text-center border-b-2 transition-all ${
                  authMode === "register" ? "border-indigo-600 text-indigo-600" : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Create Account
              </button>
            </div>

            {errorMsg && (
              <div className="p-3 bg-rose-50 text-rose-800 rounded-lg text-xs font-medium border border-rose-100 flex items-start gap-2">
                <XCircle size={16} className="shrink-0 text-rose-500 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            {successMsg && (
              <div className="p-3 bg-emerald-50 text-emerald-800 rounded-lg text-xs font-medium border border-emerald-100 flex items-start gap-2">
                <CheckCircle size={16} className="shrink-0 text-emerald-500 mt-0.5" />
                <span>{successMsg}</span>
              </div>
            )}

            {authMode === "login" ? (
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Email Address</label>
                  <div className="relative">
                    <UserIcon className="absolute left-3 top-2.5 text-slate-400" size={16} />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-9 pr-4 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                      placeholder="john.doe@example.com"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Password</label>
                  </div>
                  <div className="relative">
                    <Lock className="absolute left-3 top-2.5 text-slate-400" size={16} />
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-9 pr-4 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                      placeholder="••••••••"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full py-2 px-4 border border-transparent rounded-lg shadow-sm text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors cursor-pointer"
                >
                  Authenticate Console
                </button>

                <div className="bg-slate-50 border border-slate-200/60 rounded-xl p-3 text-xs text-slate-600 space-y-1.5">
                  <div className="font-semibold text-slate-700 flex items-center gap-1">
                    <Shield size={12} className="text-indigo-600" /> Preseeded Credentials:
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    Account: <code className="font-mono bg-slate-200/60 px-1 py-0.2 rounded text-slate-800">john.doe@example.com</code><br/>
                    Password: <code className="font-mono bg-slate-200/60 px-1 py-0.2 rounded text-slate-800">password123</code>
                  </p>
                </div>
              </form>
            ) : (
              <form onSubmit={handleRegister} className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">First Name</label>
                    <input
                      type="text"
                      value={firstName}
                      onChange={(e) => setFirstName(e.target.value)}
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all"
                      placeholder="Sarah"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Last Name</label>
                    <input
                      type="text"
                      value={lastName}
                      onChange={(e) => setLastName(e.target.value)}
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all"
                      placeholder="Connor"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Username</label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                    placeholder="sarahc"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Email Address</label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                    placeholder="sarah.connor@example.com"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Password</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                    placeholder="••••••••"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full py-2 px-4 border border-transparent rounded-lg shadow-sm text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors cursor-pointer"
                >
                  Register Admin Account
                </button>
              </form>
            )}
          </div>
        </div>

        <div className="text-center text-[10px] text-slate-400">
          CloudGuest • Secure Cloud-Managed MikroTik Network OS Suite • Powered by Express
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col font-sans">
      {/* Top Banner Accent */}
      <div className="h-1 bg-indigo-600 w-full shrink-0"></div>

      {/* Main Layout Header */}
      <header className="bg-white border-b border-slate-200/80 sticky top-0 z-30 shadow-sm shrink-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600 text-white rounded-lg shadow">
              <Network size={18} />
            </div>
            <div>
              <span className="font-bold text-slate-900 tracking-tight font-display text-sm sm:text-base">
                CloudGuest Admin
              </span>
              <span className="ml-2 bg-indigo-50 border border-indigo-100 text-indigo-700 text-[10px] font-extrabold px-2 py-0.5 rounded-full uppercase tracking-wider">
                SaaS Panel
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {currentUser && (
              <div className="hidden sm:flex items-center gap-2.5 text-right">
                <div>
                  <div className="text-xs font-semibold text-slate-800">
                    {currentUser.first_name} {currentUser.last_name}
                  </div>
                  <div className="text-[10px] text-slate-400 font-medium">
                    {currentUser.designation || "Administrator"}
                  </div>
                </div>
                <div className="w-9 h-9 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center font-bold text-indigo-600 text-xs shadow-inner">
                  {currentUser.first_name?.[0]}{currentUser.last_name?.[0]}
                </div>
              </div>
            )}

            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 py-1.5 px-3 bg-slate-50 border border-slate-200 hover:bg-slate-100 text-slate-600 hover:text-slate-900 rounded-lg text-xs font-semibold transition-all shadow-sm"
              title="Sign Out"
            >
              <LogOut size={13} />
              <span className="hidden sm:inline">Sign Out</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 grow flex flex-col md:flex-row gap-6">
        {/* Navigation Sidebar */}
        <aside className="w-full md:w-56 shrink-0 space-y-2">
          <div className="bg-white rounded-xl border border-slate-200/80 p-3 shadow-sm space-y-1">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "dashboard"
                  ? "bg-indigo-50 text-indigo-700 font-bold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <LayoutDashboard size={15} />
              Dashboard
            </button>

            <button
              onClick={() => setActiveTab("organizations")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "organizations"
                  ? "bg-indigo-50 text-indigo-700 font-bold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <Users size={15} />
              Tenant Orgs
            </button>

            <button
              onClick={() => setActiveTab("routers")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "routers"
                  ? "bg-indigo-50 text-indigo-700 font-bold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <Wifi size={15} />
              Routers & Locations
            </button>

            <button
              onClick={() => setActiveTab("playground")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "playground"
                  ? "bg-indigo-50 text-indigo-700 font-bold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <Settings size={15} />
              API Playground
            </button>

            <button
              onClick={() => setActiveTab("sessions")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "sessions"
                  ? "bg-indigo-50 text-indigo-700 font-bold"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <Lock size={15} />
              Console Sessions
            </button>
          </div>

          {/* Quick Stats sidebar widget */}
          <div className="bg-gradient-to-br from-indigo-50 to-slate-50 border border-slate-200/80 rounded-xl p-4 shadow-sm space-y-3.5 hidden md:block text-xs">
            <h5 className="font-bold text-slate-800 flex items-center gap-1.5 uppercase tracking-wider text-[9px] text-slate-400">
              <Database size={11} className="text-indigo-600" /> Sandbox Health
            </h5>
            <div className="space-y-2">
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-500">Live Services:</span>
                <span className="font-semibold text-slate-700">Express + Vite</span>
              </div>
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-500">Data State:</span>
                <span className="font-semibold text-indigo-600">Active InMemory</span>
              </div>
            </div>
            <button
              onClick={loadData}
              className="w-full flex items-center justify-center gap-1.5 py-1 px-2.5 bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 font-semibold rounded-md shadow-sm transition-all"
            >
              <RefreshCw size={11} /> Refresh Console
            </button>
          </div>
        </aside>

        {/* Dynamic Panel Content */}
        <main className="grow min-w-0">
          {errorMsg && (
            <div className="mb-4 p-3.5 bg-rose-50 text-rose-800 rounded-xl text-xs font-semibold border border-rose-100 flex items-start justify-between gap-3 shadow-sm">
              <div className="flex items-start gap-2">
                <XCircle size={16} className="shrink-0 text-rose-500 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
              <button onClick={() => setErrorMsg(null)} className="text-[10px] text-rose-400 hover:text-rose-600 font-bold">Dismiss</button>
            </div>
          )}

          {successMsg && (
            <div className="mb-4 p-3.5 bg-emerald-50 text-emerald-800 rounded-xl text-xs font-semibold border border-emerald-100 flex items-start justify-between gap-3 shadow-sm">
              <div className="flex items-start gap-2">
                <CheckCircle size={16} className="shrink-0 text-emerald-500 mt-0.5" />
                <span>{successMsg}</span>
              </div>
              <button onClick={() => setSuccessMsg(null)} className="text-[10px] text-emerald-400 hover:text-emerald-600 font-bold">Dismiss</button>
            </div>
          )}

          {loading ? (
            <div className="bg-white rounded-xl border border-slate-200/80 shadow-sm p-16 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
              <div className="text-xs text-slate-500 font-medium">Loading network control datasets...</div>
            </div>
          ) : (
            <>
              {activeTab === "dashboard" && (
                <Dashboard
                  organizations={organizations}
                  routers={routers}
                  locations={locations}
                  onNavigate={setActiveTab}
                />
              )}

              {activeTab === "organizations" && (
                <OrganizationsTab
                  organizations={organizations}
                  onCreateOrg={handleCreateOrg}
                  onUpdateOrg={handleUpdateOrg}
                  onDeleteOrg={handleDeleteOrg}
                  apiFetch={apiFetch}
                />
              )}

              {activeTab === "routers" && (
                <RoutersTab
                  routers={routers}
                  locations={locations}
                  organizations={organizations}
                  onRegisterRouter={handleRegisterRouter}
                  onUpdateRouter={handleUpdateRouter}
                  onDeleteRouter={handleDeleteRouter}
                  onCreateLocation={handleCreateLocation}
                  onDeleteLocation={handleDeleteLocation}
                />
              )}

              {activeTab === "playground" && (
                <ApiPlayground
                  token={token}
                  apiFetch={apiFetch}
                />
              )}

              {activeTab === "sessions" && (
                <div className="bg-white rounded-xl border border-slate-200/80 p-6 shadow-sm space-y-6">
                  <div className="space-y-1">
                    <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                      <Lock size={16} className="text-indigo-600" /> Authorized Admin Sessions
                    </h3>
                    <p className="text-xs text-slate-500 leading-normal">
                      Monitor and revoke active logins and device access keys to secure the CloudGuest network gateway control layer.
                    </p>
                  </div>

                  <div className="divide-y divide-slate-100 pt-2">
                    {sessions.map((sess) => (
                      <div key={sess.id} className="py-4 flex justify-between items-center gap-4 text-xs">
                        <div className="flex gap-3 items-start min-w-0">
                          <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 shrink-0">
                            {getDeviceIcon(sess.user_agent)}
                          </div>
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-800 truncate">{sess.device_name}</span>
                              {sess.is_current && (
                                <span className="px-1.5 py-0.2 bg-indigo-50 border border-indigo-200 text-indigo-700 rounded font-semibold text-[9px] uppercase">
                                  Current Session
                                </span>
                              )}
                            </div>
                            <p className="text-slate-400 text-[10px] flex items-center gap-2 flex-wrap">
                              <span>IP Address: <code className="font-mono text-slate-600">{sess.ip_address}</code></span>
                              <span>•</span>
                              <span>Location: <span className="text-slate-500">{sess.location || "Unknown"}</span></span>
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 uppercase">
                            Active
                          </span>
                          {!sess.is_current && (
                            <button
                              onClick={() => handleRevokeSession(sess.id)}
                              className="text-xs font-semibold text-rose-600 hover:text-rose-700 px-2.5 py-1 hover:bg-rose-50 rounded-lg border border-transparent hover:border-rose-200 transition-colors cursor-pointer"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </main>
      </div>

      <footer className="bg-white border-t border-slate-200/80 py-4 shrink-0 text-center text-xs text-slate-400">
        © {new Date().getFullYear()} CloudGuest Multi-Tenant Control Core • MikroTik Network OS Integrator. All rights reserved.
      </footer>
    </div>
  );
}
