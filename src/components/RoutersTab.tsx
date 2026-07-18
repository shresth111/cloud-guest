import React, { useState } from "react";
import { Plus, Trash2, Edit2, MapPin, Wifi, Cpu, Settings, Tag, ShieldAlert } from "lucide-react";
import { RouterDevice, Location, Organization } from "../types";

interface RoutersTabProps {
  routers: RouterDevice[];
  locations: Location[];
  organizations: Organization[];
  onRegisterRouter: (router: Partial<RouterDevice>) => void;
  onUpdateRouter: (id: string, router: Partial<RouterDevice>) => void;
  onDeleteRouter: (id: string) => void;
  onCreateLocation: (location: Partial<Location>) => void;
  onDeleteLocation: (id: string) => void;
}

export const RoutersTab: React.FC<RoutersTabProps> = ({
  routers,
  locations,
  organizations,
  onRegisterRouter,
  onUpdateRouter,
  onDeleteRouter,
  onCreateLocation,
  onDeleteLocation,
}) => {
  const [subTab, setSubTab] = useState<"routers" | "locations">("routers");
  const [isCreatingRouter, setIsCreatingRouter] = useState(false);
  const [isCreatingLocation, setIsCreatingLocation] = useState(false);
  const [editingRouter, setEditingRouter] = useState<RouterDevice | null>(null);

  // Router Form States
  const [routerName, setRouterName] = useState("");
  const [serialNumber, setSerialNumber] = useState("");
  const [macAddress, setMacAddress] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [model, setModel] = useState("MikroTik hAP ac³");
  const [rosVersion, setRosVersion] = useState("7.15.2");
  const [routerOrgId, setRouterOrgId] = useState("");
  const [routerLocId, setRouterLocId] = useState("");

  // Location Form States
  const [locationName, setLocationName] = useState("");
  const [locationOrgId, setLocationOrgId] = useState("");
  const [address, setAddress] = useState("");
  const [city, setCity] = useState("");
  const [state, setState] = useState("");
  const [postalCode, setPostalCode] = useState("");
  const [country, setCountry] = useState("USA");

  const resetRouterForm = () => {
    setRouterName("");
    setSerialNumber("");
    setMacAddress("");
    setIpAddress("");
    setModel("MikroTik hAP ac³");
    setRosVersion("7.15.2");
    setRouterOrgId(organizations[0]?.id || "");
    setRouterLocId("");
  };

  const resetLocationForm = () => {
    setLocationName("");
    setLocationOrgId(organizations[0]?.id || "");
    setAddress("");
    setCity("");
    setState("");
    setPostalCode("");
    setCountry("USA");
  };

  const handleRegisterRouterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!routerName || !serialNumber || !macAddress || !routerOrgId) return;

    onRegisterRouter({
      name: routerName,
      serial_number: serialNumber.toUpperCase(),
      mac_address: macAddress.toUpperCase(),
      ip_address: ipAddress || "192.168.88.1",
      model,
      ros_version: rosVersion,
      organization_id: routerOrgId,
      location_id: routerLocId || null,
    });
    setIsCreatingRouter(false);
    resetRouterForm();
  };

  const startEditRouter = (router: RouterDevice) => {
    setEditingRouter(router);
    setRouterName(router.name);
    setSerialNumber(router.serial_number);
    setMacAddress(router.mac_address);
    setIpAddress(router.ip_address || "");
    setModel(router.model);
    setRosVersion(router.ros_version);
    setRouterOrgId(router.organization_id);
    setRouterLocId(router.location_id || "");
  };

  const handleUpdateRouterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRouter) return;

    onUpdateRouter(editingRouter.id, {
      name: routerName,
      serial_number: serialNumber.toUpperCase(),
      mac_address: macAddress.toUpperCase(),
      ip_address: ipAddress,
      model,
      ros_version: rosVersion,
      organization_id: routerOrgId,
      location_id: routerLocId || null,
    });
    setEditingRouter(null);
    resetRouterForm();
  };

  const handleCreateLocationSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!locationName || !locationOrgId) return;

    onCreateLocation({
      name: locationName,
      organization_id: locationOrgId,
      address_line1: address,
      city,
      state,
      postal_code: postalCode,
      country,
      timezone: "America/New_York",
    });
    setIsCreatingLocation(false);
    resetLocationForm();
  };

  const toggleRouterStatus = (router: RouterDevice) => {
    onUpdateRouter(router.id, {
      status: router.status === "online" ? "offline" : "online",
      last_seen_at: new Date().toISOString(),
    });
  };

  return (
    <div className="space-y-6">
      {/* Sub Tabs Toggle */}
      <div className="flex border-b border-slate-200">
        <button
          onClick={() => setSubTab("routers")}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-colors ${
            subTab === "routers"
              ? "border-indigo-600 text-indigo-600"
              : "border-transparent text-slate-500 hover:text-slate-900"
          }`}
        >
          MikroTik Gateways ({routers.length})
        </button>
        <button
          onClick={() => setSubTab("locations")}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-colors ${
            subTab === "locations"
              ? "border-indigo-600 text-indigo-600"
              : "border-transparent text-slate-500 hover:text-slate-900"
          }`}
        >
          Network Locations ({locations.length})
        </button>
      </div>

      {subTab === "routers" && (
        <div className="space-y-6">
          {/* Action Bar */}
          {!isCreatingRouter && !editingRouter && (
            <div className="flex justify-end">
              <button
                onClick={() => {
                  resetRouterForm();
                  setIsCreatingRouter(true);
                }}
                className="flex items-center gap-1.5 px-3.5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-sm"
              >
                <Plus size={14} /> Provision Router (MikroTik)
              </button>
            </div>
          )}

          {/* Router Registration/Edit Form */}
          {(isCreatingRouter || editingRouter) && (
            <form
              onSubmit={isCreatingRouter ? handleRegisterRouterSubmit : handleUpdateRouterSubmit}
              className="bg-white p-6 rounded-xl border border-slate-200/85 shadow-sm space-y-4"
            >
              <div className="flex justify-between items-center pb-2 border-b border-slate-100">
                <h3 className="text-sm font-semibold text-slate-900">
                  {isCreatingRouter ? "Register MikroTik RouterOS Device" : `Edit Router ${routerName}`}
                </h3>
                <button
                  type="button"
                  onClick={() => {
                    setIsCreatingRouter(false);
                    setEditingRouter(null);
                  }}
                  className="text-xs text-slate-500 hover:text-slate-800"
                >
                  Cancel
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Device Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Lobby Gateway"
                    value={routerName}
                    onChange={(e) => setRouterName(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Serial Number (12 char)</label>
                  <input
                    type="text"
                    required
                    maxLength={12}
                    placeholder="e.g. 7E2A08B01C2F"
                    value={serialNumber}
                    onChange={(e) => setSerialNumber(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">MAC Address</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 18:FD:74:2A:08:B0"
                    value={macAddress}
                    onChange={(e) => setMacAddress(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Model / Hardware</label>
                  <input
                    type="text"
                    placeholder="e.g. MikroTik hAP ac³"
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">RouterOS Version</label>
                  <input
                    type="text"
                    placeholder="e.g. 7.15.2"
                    value={rosVersion}
                    onChange={(e) => setRosVersion(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">IPv4 Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.88.1"
                    value={ipAddress}
                    onChange={(e) => setIpAddress(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Tenant Organization</label>
                  <select
                    required
                    value={routerOrgId}
                    onChange={(e) => setRouterOrgId(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="" disabled>Select tenant</option>
                    {organizations.map((o) => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Physical Location</label>
                  <select
                    value={routerLocId}
                    onChange={(e) => setRouterLocId(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="">No physical location assigned</option>
                    {locations.map((l) => (
                      <option key={l.id} value={l.id}>{l.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsCreatingRouter(false);
                    setEditingRouter(null);
                  }}
                  className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow"
                >
                  {isCreatingRouter ? "Provision Device" : "Update Settings"}
                </button>
              </div>
            </form>
          )}

          {/* Routers List */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {routers.map((router) => {
              const org = organizations.find((o) => o.id === router.organization_id);
              const loc = locations.find((l) => l.id === router.location_id);
              return (
                <div key={router.id} className="bg-white rounded-xl border border-slate-200/80 p-5 shadow-sm space-y-4 hover:shadow-md transition-all">
                  <div className="flex justify-between items-start gap-3">
                    <div className="space-y-1">
                      <h4 className="font-semibold text-slate-900 flex items-center gap-2">
                        {router.name}
                        <span className="px-1.5 py-0.2 bg-slate-100 text-slate-600 rounded font-mono text-[9px]">
                          ROS {router.ros_version}
                        </span>
                      </h4>
                      <p className="text-[10px] font-mono text-slate-400">MAC: {router.mac_address}</p>
                    </div>

                    <button
                      onClick={() => toggleRouterStatus(router)}
                      className={`px-2.5 py-0.5 rounded-full text-[9px] font-semibold uppercase tracking-wider flex items-center gap-1 cursor-pointer transition-colors ${
                        router.status === "online"
                          ? "bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-200"
                          : "bg-rose-50 text-rose-700 hover:bg-rose-100 border border-rose-200"
                      }`}
                      title="Click to toggle Router State"
                    >
                      <span className={`w-1 h-1 rounded-full ${router.status === "online" ? "bg-emerald-500" : "bg-rose-500"}`}></span>
                      {router.status}
                    </button>
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-600 pt-2 border-t border-slate-100">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Hardware</span>
                      <span className="font-medium">{router.model}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">IP Address</span>
                      <span className="font-mono text-slate-700">{router.ip_address || "192.168.88.1"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Tenant Org</span>
                      <span className="font-semibold text-indigo-600 truncate max-w-[150px]" title={org?.name}>
                        {org ? org.name : "Unknown"}
                      </span>
                    </div>
                    {loc && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">Location</span>
                        <span className="font-medium text-slate-700">{loc.name}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex justify-between items-center pt-3 border-t border-slate-50 text-[10px] text-slate-400">
                    <span>Seen: {router.last_seen_at ? new Date(router.last_seen_at).toLocaleTimeString() : "Never"}</span>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => startEditRouter(router)}
                        className="p-1 text-slate-400 hover:text-slate-700 rounded"
                        title="Edit Router Configuration"
                      >
                        <Edit2 size={12} />
                      </button>
                      <button
                        onClick={() => onDeleteRouter(router.id)}
                        className="p-1 text-slate-400 hover:text-rose-600 rounded"
                        title="Deregister Device"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {subTab === "locations" && (
        <div className="space-y-6">
          {/* Action Bar */}
          {!isCreatingLocation && (
            <div className="flex justify-end">
              <button
                onClick={() => {
                  resetLocationForm();
                  setIsCreatingLocation(true);
                }}
                className="flex items-center gap-1.5 px-3.5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-sm"
              >
                <Plus size={14} /> Create New Location
              </button>
            </div>
          )}

          {/* Location Creation Form */}
          {isCreatingLocation && (
            <form
              onSubmit={handleCreateLocationSubmit}
              className="bg-white p-6 rounded-xl border border-slate-200/85 shadow-sm space-y-4"
            >
              <div className="flex justify-between items-center pb-2 border-b border-slate-100">
                <h3 className="text-sm font-semibold text-slate-900">Configure Physical Location</h3>
                <button
                  type="button"
                  onClick={() => setIsCreatingLocation(false)}
                  className="text-xs text-slate-500 hover:text-slate-800"
                >
                  Cancel
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-1.5 col-span-2">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Location Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Seattle Flagship Store"
                    value={locationName}
                    onChange={(e) => setLocationName(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Tenant Org</label>
                  <select
                    required
                    value={locationOrgId}
                    onChange={(e) => setLocationOrgId(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="" disabled>Select tenant</option>
                    {organizations.map((o) => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5 col-span-3">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Street Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 500 Pine Street"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">City</label>
                  <input
                    type="text"
                    placeholder="e.g. Seattle"
                    value={city}
                    onChange={(e) => setCity(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">State / Province</label>
                  <input
                    type="text"
                    placeholder="e.g. WA"
                    value={state}
                    onChange={(e) => setState(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Postal Code</label>
                  <input
                    type="text"
                    placeholder="e.g. 98101"
                    value={postalCode}
                    onChange={(e) => setPostalCode(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsCreatingLocation(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow"
                >
                  Save Location
                </button>
              </div>
            </form>
          )}

          {/* Locations Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {locations.map((loc) => {
              const org = organizations.find((o) => o.id === loc.organization_id);
              const routerCount = routers.filter((r) => r.location_id === loc.id).length;
              return (
                <div key={loc.id} className="bg-white rounded-xl border border-slate-200/80 p-5 shadow-sm space-y-4 hover:shadow-md transition-all">
                  <div className="flex justify-between items-start gap-3">
                    <div className="space-y-1">
                      <h4 className="font-semibold text-slate-900 flex items-center gap-2">
                        <MapPin size={14} className="text-rose-500" />
                        {loc.name}
                      </h4>
                      <p className="text-[10px] font-mono text-slate-400">Organization: {org ? org.name : "Unknown"}</p>
                    </div>

                    <button
                      onClick={() => onDeleteLocation(loc.id)}
                      className="p-1.5 hover:bg-rose-50 text-slate-400 hover:text-rose-600 rounded-lg transition-colors"
                      title="Delete Location"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>

                  <div className="text-xs text-slate-500 space-y-1">
                    <p>{loc.address_line1 || "No address configured"}</p>
                    <p>
                      {loc.city ? `${loc.city}, ` : ""}
                      {loc.state ? `${loc.state} ` : ""}
                      {loc.postal_code || ""}
                    </p>
                    <p className="font-medium text-slate-400 uppercase text-[9px] tracking-wider">{loc.country}</p>
                  </div>

                  <div className="pt-3 border-t border-slate-100 flex justify-between items-center text-xs font-medium">
                    <span className="text-slate-400">Active Gateways</span>
                    <span className="bg-indigo-50 text-indigo-700 px-2.5 py-0.5 rounded-full text-[10px] font-semibold border border-indigo-100">
                      {routerCount} Assigned
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
