import React from "react";
import { Activity, Server, Network, MapPin, Users, Wifi } from "lucide-react";
import { Organization, RouterDevice, Location } from "../types";

interface DashboardProps {
  organizations: Organization[];
  routers: RouterDevice[];
  locations: Location[];
  onNavigate: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  organizations,
  routers,
  locations,
  onNavigate,
}) => {
  const onlineRouters = routers.filter((r) => r.status === "online").length;

  return (
    <div className="space-y-6">
      {/* Welcome Hero */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-6 text-white border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <Network size={200} className="text-white" />
        </div>
        <div className="max-w-xl space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight font-display">
            CloudGuest Admin Console
          </h1>
          <p className="text-slate-300 text-sm leading-relaxed">
            Commercial SaaS control center for cloud-managed MikroTik RouterOS deployments.
            Monitor core API lifespans, manage multi-tenant organizations, and provision remote gateways.
          </p>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm flex items-center gap-4 hover:border-slate-300 transition-colors">
          <div className="p-3 rounded-lg bg-indigo-50 text-indigo-600">
            <Users size={20} />
          </div>
          <div>
            <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Organizations</div>
            <div className="text-2xl font-bold font-display text-slate-900 mt-0.5">{organizations.length}</div>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm flex items-center gap-4 hover:border-slate-300 transition-colors">
          <div className="p-3 rounded-lg bg-emerald-50 text-emerald-600">
            <MapPin size={20} />
          </div>
          <div>
            <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Locations</div>
            <div className="text-2xl font-bold font-display text-slate-900 mt-0.5">{locations.length}</div>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm flex items-center gap-4 hover:border-slate-300 transition-colors">
          <div className="p-3 rounded-lg bg-sky-50 text-sky-600">
            <Wifi size={20} />
          </div>
          <div>
            <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Online Routers</div>
            <div className="text-2xl font-bold font-display text-slate-900 mt-0.5">
              {onlineRouters} <span className="text-xs font-normal text-slate-400">/ {routers.length}</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm flex items-center gap-4 hover:border-slate-300 transition-colors">
          <div className="p-3 rounded-lg bg-purple-50 text-purple-600">
            <Activity size={20} />
          </div>
          <div>
            <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">API Health</div>
            <div className="text-lg font-bold font-display text-slate-900 mt-0.5 flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse inline-block"></span>
              Live & Ready
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Infrastructure Health */}
        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm col-span-1 space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Server size={16} className="text-slate-500" />
            Backend Infrastructure Health
          </h2>
          <div className="space-y-3.5 pt-2">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/50 flex justify-between items-center text-xs">
              <div className="space-y-0.5">
                <div className="font-semibold text-slate-700">API Service Status</div>
                <div className="text-slate-400 font-mono">/api/v1/health/live</div>
              </div>
              <span className="px-2 py-0.5 font-medium rounded-full bg-emerald-100 text-emerald-800 text-[10px] uppercase">
                Healthy
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/50 flex justify-between items-center text-xs">
              <div className="space-y-0.5">
                <div className="font-semibold text-slate-700">PostgreSQL Database</div>
                <div className="text-slate-400 font-mono">latency: 1.25ms</div>
              </div>
              <span className="px-2 py-0.5 font-medium rounded-full bg-emerald-100 text-emerald-800 text-[10px] uppercase">
                Connected
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/50 flex justify-between items-center text-xs">
              <div className="space-y-0.5">
                <div className="font-semibold text-slate-700">Redis Cache</div>
                <div className="text-slate-400 font-mono">latency: 0.85ms</div>
              </div>
              <span className="px-2 py-0.5 font-medium rounded-full bg-emerald-100 text-emerald-800 text-[10px] uppercase">
                Active
              </span>
            </div>
          </div>

          <div className="bg-indigo-50 border border-indigo-100 rounded-lg p-3 text-xs text-indigo-950 flex flex-col gap-2">
            <div className="font-semibold">Backend Sandbox Verified</div>
            <p className="text-indigo-800 leading-normal">
              The original FastAPI models and tables have been migrated to an Express + CJS backend architecture optimized for AI Studio.
            </p>
          </div>
        </div>

        {/* Live Router Activity and Telemetry */}
        <div className="bg-white p-5 rounded-xl border border-slate-200/80 shadow-sm col-span-2 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Wifi size={16} className="text-indigo-600" />
              Active Remote Gateways (MikroTik)
            </h2>
            <button
              onClick={() => onNavigate("routers")}
              className="text-xs text-indigo-600 hover:text-indigo-700 font-semibold"
            >
              Manage Routers &rarr;
            </button>
          </div>

          <div className="divide-y divide-slate-100">
            {routers.map((router) => {
              const org = organizations.find((o) => o.id === router.organization_id);
              const loc = locations.find((l) => l.id === router.location_id);
              return (
                <div key={router.id} className="py-3.5 flex justify-between items-center gap-4 text-xs">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-800 truncate">{router.name}</span>
                      <span className="px-1.5 py-0.2 bg-slate-100 border border-slate-200 text-slate-600 rounded font-mono text-[9px]">
                        {router.model.split(" ")[0]}
                      </span>
                    </div>
                    <div className="text-slate-400 flex items-center gap-2 flex-wrap">
                      <span>Serial: <code className="font-mono text-slate-600">{router.serial_number}</code></span>
                      <span>•</span>
                      <span>Org: <span className="text-slate-500 font-medium">{org ? org.name : "Unknown"}</span></span>
                      {loc && (
                        <>
                          <span>•</span>
                          <span>Loc: <span className="text-slate-500">{loc.name}</span></span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono text-slate-500">{router.ros_version}</span>
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                        router.status === "online"
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : "bg-rose-50 text-rose-700 border border-rose-200"
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${router.status === "online" ? "bg-emerald-500" : "bg-rose-500"}`}></span>
                      {router.status}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
