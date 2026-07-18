import React, { useState } from "react";
import { Terminal, Send, CheckCircle2, Play, Code, Clock } from "lucide-react";

interface ApiPlaygroundProps {
  token: string | null;
  apiFetch: (url: string, options?: any) => Promise<any>;
}

interface Endpoint {
  name: string;
  method: "GET" | "POST" | "DELETE" | "PUT";
  path: string;
  description: string;
  requiresAuth: boolean;
  defaultBody?: any;
}

const ENDPOINTS: Endpoint[] = [
  {
    name: "Liveness Check",
    method: "GET",
    path: "/api/v1/health/live",
    description: "Verify that the CloudGuest API is online and responding.",
    requiresAuth: false,
  },
  {
    name: "Readiness Check",
    method: "GET",
    path: "/api/v1/health/ready",
    description: "Verify that the backend has active connections to DB and Redis.",
    requiresAuth: false,
  },
  {
    name: "User Login",
    method: "POST",
    path: "/api/v1/auth/login",
    description: "Authenticate a user and return an Access/Refresh JWT pair.",
    requiresAuth: false,
    defaultBody: {
      email: "john.doe@example.com",
      password: "password123",
      device_name: "Web API Playground",
    },
  },
  {
    name: "Register User",
    method: "POST",
    path: "/api/v1/auth/register",
    description: "Register a new user account in-memory.",
    requiresAuth: false,
    defaultBody: {
      first_name: "Sarah",
      last_name: "Connor",
      email: "sarah.connor@example.com",
      username: "sarahc",
      password: "password123",
      phone: "+15550009999",
      timezone: "America/Los_Angeles",
      language: "en",
    },
  },
  {
    name: "Get User Profile (Me)",
    method: "GET",
    path: "/api/v1/auth/me",
    description: "Retrieve profile info of the currently authenticated bearer token user.",
    requiresAuth: true,
  },
  {
    name: "List Sessions",
    method: "GET",
    path: "/api/v1/auth/sessions",
    description: "List active browser/device sessions for the current user.",
    requiresAuth: true,
  },
  {
    name: "List Organizations",
    method: "GET",
    path: "/api/v1/organizations",
    description: "Retrieve a paginated list of multi-tenant organizations.",
    requiresAuth: false,
  },
  {
    name: "Create Organization",
    method: "POST",
    path: "/api/v1/organizations",
    description: "Configure and register a new MSP or Tenant Organization.",
    requiresAuth: false,
    defaultBody: {
      name: "Solaris Telecom",
      slug: "solaris-telecom",
      legal_name: "Solaris Telecom Group Inc",
      org_type: "MSP",
      status: "active",
      contact_email: "noc@solaris.net",
      contact_phone: "+15551112222",
      timezone: "America/Chicago",
      default_locale: "en_US",
      settings: { ddos_protection: true },
      subscription_tier: "enterprise",
    },
  },
  {
    name: "List Physical Locations",
    method: "GET",
    path: "/api/v1/locations",
    description: "List all geographical sites where gateways are deployed.",
    requiresAuth: false,
  },
  {
    name: "List MikroTik Gateways",
    method: "GET",
    path: "/api/v1/routers",
    description: "Retrieve a complete list of cloud-managed routers.",
    requiresAuth: false,
  },
];

export const ApiPlayground: React.FC<ApiPlaygroundProps> = ({ token, apiFetch }) => {
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint>(ENDPOINTS[0]);
  const [requestBody, setRequestBody] = useState<string>("");
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseHeaders, setResponseHeaders] = useState<Record<string, string>>({});
  const [responseBody, setResponseBody] = useState<string>("");
  const [executing, setExecuting] = useState(false);
  const [latency, setLatency] = useState<number | null>(null);

  // Set default body when endpoint changes
  React.useEffect(() => {
    if (selectedEndpoint.defaultBody) {
      setRequestBody(JSON.stringify(selectedEndpoint.defaultBody, null, 2));
    } else {
      setRequestBody("");
    }
    // Clear previous outputs
    setResponseStatus(null);
    setResponseBody("");
    setLatency(null);
  }, [selectedEndpoint]);

  const handleSendRequest = async () => {
    setExecuting(true);
    setResponseBody("");
    setResponseStatus(null);
    setLatency(null);

    const start = performance.now();
    const options: any = {
      method: selectedEndpoint.method,
      headers: {
        "Content-Type": "application/json",
      },
    };

    if (selectedEndpoint.requiresAuth && token) {
      options.headers["Authorization"] = `Bearer ${token}`;
    }

    if (selectedEndpoint.method !== "GET" && requestBody) {
      try {
        options.body = requestBody;
      } catch (err) {
        setResponseBody(JSON.stringify({ error: "Invalid JSON request body payload." }, null, 2));
        setExecuting(false);
        return;
      }
    }

    try {
      const res = await fetch(selectedEndpoint.path, options);
      const end = performance.now();
      setLatency(Math.round(end - start));
      setResponseStatus(res.status);

      // Extract custom headers if any
      const headersObj: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        headersObj[key] = val;
      });
      setResponseHeaders(headersObj);

      const json = await res.json();
      setResponseBody(JSON.stringify(json, null, 2));
    } catch (err: any) {
      const end = performance.now();
      setLatency(Math.round(end - start));
      setResponseStatus(500);
      setResponseBody(JSON.stringify({
        success: false,
        error: err.message || "Network request failed. Is the dev server offline?",
      }, null, 2));
    }
    setExecuting(false);
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 text-slate-300 flex items-center justify-between">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Terminal size={16} className="text-emerald-400" /> Live API Execution Sandbox
          </h3>
          <p className="text-xs text-slate-400 leading-normal">
            Interact directly with the Express backend using raw HTTP requests. Modify payloads and inspect responses.
          </p>
        </div>
        {token ? (
          <span className="px-2.5 py-1 text-[10px] font-semibold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1">
            <CheckCircle2 size={12} /> Bearer Token Active
          </span>
        ) : (
          <span className="px-2.5 py-1 text-[10px] font-semibold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full">
            No Auth Token Attached
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Endpoint Selector Panel */}
        <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200/80 shadow-sm overflow-hidden divide-y divide-slate-100">
          <div className="p-4 bg-slate-50 font-semibold text-slate-900 text-xs uppercase tracking-wider">
            API Endpoints (v1)
          </div>
          <div className="max-h-[500px] overflow-y-auto divide-y divide-slate-100">
            {ENDPOINTS.map((ep, idx) => {
              const isSelected = selectedEndpoint.path === ep.path && selectedEndpoint.method === ep.method;
              return (
                <button
                  key={idx}
                  onClick={() => setSelectedEndpoint(ep)}
                  className={`w-full text-left p-3.5 space-y-1 transition-all flex flex-col hover:bg-slate-50 ${
                    isSelected ? "bg-indigo-50/50 border-l-4 border-indigo-600 pl-2.5" : "pl-3.5"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[9px] font-extrabold px-1.5 py-0.5 rounded uppercase font-mono ${
                        ep.method === "GET"
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : ep.method === "POST"
                          ? "bg-indigo-50 text-indigo-700 border border-indigo-200"
                          : "bg-rose-50 text-rose-700 border border-rose-200"
                      }`}
                    >
                      {ep.method}
                    </span>
                    <span className="text-xs font-semibold text-slate-800">{ep.name}</span>
                  </div>
                  <code className="text-[10px] font-mono text-slate-500 truncate w-full">{ep.path}</code>
                </button>
              );
            })}
          </div>
        </div>

        {/* Console / Interaction Panel */}
        <div className="lg:col-span-8 space-y-5">
          {/* Active Endpoint Spec */}
          <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-4">
            <div className="flex justify-between items-start gap-4 flex-wrap">
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <span className="text-xs font-bold text-slate-900">{selectedEndpoint.name}</span>
                  {selectedEndpoint.requiresAuth && (
                    <span className="bg-amber-50 text-amber-800 text-[9px] font-bold px-1.5 py-0.5 rounded border border-amber-200 uppercase">
                      Requires Auth Bearer
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 leading-normal">{selectedEndpoint.description}</p>
              </div>

              <button
                onClick={handleSendRequest}
                disabled={executing}
                className="flex items-center gap-1.5 px-4 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-400 text-white font-semibold rounded-lg shadow cursor-pointer transition-all shrink-0"
              >
                {executing ? (
                  <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                ) : (
                  <Play size={13} fill="currentColor" />
                )}
                {executing ? "Executing..." : "Send HTTP Request"}
              </button>
            </div>

            {/* Request block */}
            <div className="space-y-2 pt-2 border-t border-slate-100">
              <div className="flex items-center gap-2 font-mono text-xs bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-slate-700">
                <span className="font-bold text-indigo-600">{selectedEndpoint.method}</span>
                <span className="text-slate-400">|</span>
                <span className="text-slate-800 truncate">{selectedEndpoint.path}</span>
              </div>

              {selectedEndpoint.method !== "GET" && (
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-bold text-slate-400 tracking-wider flex items-center gap-1">
                    <Code size={12} /> HTTP Request Body (JSON)
                  </label>
                  <textarea
                    rows={6}
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    className="w-full px-3.5 py-2.5 text-xs font-mono rounded-lg border border-slate-200 bg-slate-950 text-emerald-400 focus:outline-none focus:ring-1 focus:ring-indigo-500 shadow-inner"
                    placeholder="{}"
                  />
                </div>
              )}
            </div>
          </div>

          {/* Response Panel */}
          <div className="bg-slate-950 p-5 rounded-xl border border-slate-900 text-slate-300 space-y-4 shadow-xl">
            <div className="flex justify-between items-center text-xs pb-3 border-b border-slate-900">
              <span className="text-slate-400 font-semibold uppercase tracking-wider">HTTP Execution Output</span>

              {latency !== null && (
                <div className="flex items-center gap-4">
                  <span className="text-[11px] text-slate-500 flex items-center gap-1">
                    <Clock size={12} /> {latency}ms
                  </span>
                  <span className={`font-mono font-bold px-2 py-0.5 rounded text-[11px] uppercase ${
                    responseStatus === 200 || responseStatus === 201
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : responseStatus === 401 || responseStatus === 409
                      ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                      : "bg-slate-800 text-slate-300"
                  }`}>
                    {responseStatus} Status
                  </span>
                </div>
              )}
            </div>

            {responseBody ? (
              <pre className="text-xs font-mono text-emerald-400 overflow-x-auto max-h-[350px] whitespace-pre p-2 leading-relaxed bg-slate-950/80 rounded-lg shadow-inner">
                {responseBody}
              </pre>
            ) : (
              <div className="text-center py-16 text-xs text-slate-600 font-medium">
                No active response output. Choose an endpoint above and click &quot;Send HTTP Request&quot;.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
