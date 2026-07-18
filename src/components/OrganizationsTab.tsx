import React, { useState } from "react";
import { Plus, Search, Trash2, Edit2, Users, Sliders, Globe, Mail, Phone, Calendar, ArrowLeft } from "lucide-react";
import { Organization } from "../types";

interface OrganizationsTabProps {
  organizations: Organization[];
  onCreateOrg: (org: Partial<Organization>) => void;
  onUpdateOrg: (id: string, org: Partial<Organization>) => void;
  onDeleteOrg: (id: string) => void;
  apiFetch: (url: string, options?: any) => Promise<any>;
}

export const OrganizationsTab: React.FC<OrganizationsTabProps> = ({
  organizations,
  onCreateOrg,
  onUpdateOrg,
  onDeleteOrg,
  apiFetch,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [editingOrg, setEditingOrg] = useState<Organization | null>(null);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);

  // Form states
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [legalName, setLegalName] = useState("");
  const [orgType, setOrgType] = useState("Tenant");
  const [status, setStatus] = useState("active");
  const [contactEmail, setContactEmail] = useState("");
  const [contactPhone, setContactPhone] = useState("");
  const [timezone, setTimezone] = useState("America/New_York");
  const [locale, setLocale] = useState("en_US");
  const [subTier, setSubTier] = useState("pro");

  // Member management states
  const [members, setMembers] = useState<any[]>([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [isPrimaryContact, setIsPrimaryContact] = useState(false);
  const [loadingMembers, setLoadingMembers] = useState(false);

  const loadMembers = async (orgId: string) => {
    setLoadingMembers(true);
    try {
      const res = await apiFetch(`/api/v1/organizations/${orgId}/members`);
      if (res && res.success) {
        setMembers(res.data);
      } else {
        setMembers([]);
      }
    } catch {
      setMembers([]);
    }
    setLoadingMembers(false);
  };

  const handleSelectOrg = (org: Organization) => {
    setSelectedOrg(org);
    loadMembers(org.id);
  };

  const resetForm = () => {
    setName("");
    setSlug("");
    setLegalName("");
    setOrgType("Tenant");
    setStatus("active");
    setContactEmail("");
    setContactPhone("");
    setTimezone("America/New_York");
    setLocale("en_US");
    setSubTier("pro");
  };

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !slug || !contactEmail) return;
    onCreateOrg({
      name,
      slug,
      legal_name: legalName || name,
      org_type: orgType,
      status,
      contact_email: contactEmail,
      contact_phone: contactPhone,
      timezone,
      default_locale: locale,
      subscription_tier: subTier,
    });
    setIsCreating(false);
    resetForm();
  };

  const startEdit = (org: Organization, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingOrg(org);
    setName(org.name);
    setSlug(org.slug);
    setLegalName(org.legal_name || "");
    setOrgType(org.org_type);
    setStatus(org.status);
    setContactEmail(org.contact_email);
    setContactPhone(org.contact_phone || "");
    setTimezone(org.timezone);
    setLocale(org.default_locale);
    setSubTier(org.subscription_tier);
  };

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingOrg) return;
    onUpdateOrg(editingOrg.id, {
      name,
      slug,
      legal_name: legalName || name,
      org_type: orgType,
      status,
      contact_email: contactEmail,
      contact_phone: contactPhone,
      timezone,
      default_locale: locale,
      subscription_tier: subTier,
    });
    setEditingOrg(null);
    resetForm();
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrg) return;
    try {
      const res = await apiFetch(`/api/v1/organizations/${selectedOrg.id}/members`, {
        method: "POST",
        body: JSON.stringify({
          user_id: "9f32373c-74f4-41bd-8c43-c649987dc34a", // Mocked registered user ID
          is_primary_contact: isPrimaryContact,
        }),
      });
      if (res && res.success) {
        setInviteEmail("");
        setIsPrimaryContact(false);
        loadMembers(selectedOrg.id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!selectedOrg) return;
    try {
      const res = await apiFetch(`/api/v1/organizations/${selectedOrg.id}/members/${memberId}`, {
        method: "DELETE",
      });
      if (res && res.success) {
        loadMembers(selectedOrg.id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const filteredOrgs = organizations.filter(
    (org) =>
      org.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      org.slug.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (selectedOrg) {
    return (
      <div className="space-y-6">
        <button
          onClick={() => setSelectedOrg(null)}
          className="flex items-center gap-2 text-slate-600 hover:text-slate-950 font-medium text-xs bg-white py-1.5 px-3 rounded-lg border border-slate-200 shadow-sm"
        >
          <ArrowLeft size={14} /> Back to Organizations
        </button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Org Info */}
          <div className="bg-white rounded-xl border border-slate-200/85 p-6 shadow-sm space-y-6 lg:col-span-1">
            <div className="space-y-2">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                selectedOrg.status === "active"
                  ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                  : "bg-rose-50 text-rose-700 border border-rose-200"
              }`}>
                {selectedOrg.status}
              </span>
              <h2 className="text-xl font-bold font-display text-slate-900">{selectedOrg.name}</h2>
              <p className="text-xs font-mono text-slate-400">ID: {selectedOrg.id}</p>
            </div>

            <div className="space-y-4 text-xs divide-y divide-slate-100">
              <div className="pt-0 flex justify-between py-2">
                <span className="text-slate-400">Legal Name</span>
                <span className="font-medium text-slate-800">{selectedOrg.legal_name || selectedOrg.name}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Type</span>
                <span className="font-medium text-indigo-600">{selectedOrg.org_type}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Slug</span>
                <span className="font-mono text-slate-700">{selectedOrg.slug}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Subscription</span>
                <span className="font-medium uppercase text-indigo-600">{selectedOrg.subscription_tier}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Email</span>
                <span className="font-medium text-slate-800">{selectedOrg.contact_email}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Phone</span>
                <span className="font-medium text-slate-800">{selectedOrg.contact_phone || "Not Set"}</span>
              </div>
              <div className="pt-2 flex justify-between py-2">
                <span className="text-slate-400">Timezone</span>
                <span className="font-medium text-slate-800">{selectedOrg.timezone}</span>
              </div>
            </div>
          </div>

          {/* Members Panel */}
          <div className="bg-white rounded-xl border border-slate-200/85 p-6 shadow-sm lg:col-span-2 space-y-6">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Users size={16} className="text-slate-400" /> Organization Memberships
            </h3>

            {/* Invite Form */}
            <form onSubmit={handleInviteMember} className="bg-slate-50 rounded-lg p-4 border border-slate-200/60 flex items-end gap-4 flex-wrap">
              <div className="space-y-1.5 grow min-w-[200px]">
                <label className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Invite User ID</label>
                <input
                  type="text"
                  placeholder="e.g. 9f32373c-74f4-41bd-8c43-c649987dc34a"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                />
              </div>

              <div className="flex items-center gap-2 h-9 mb-0.5">
                <input
                  type="checkbox"
                  id="primaryContact"
                  checked={isPrimaryContact}
                  onChange={(e) => setIsPrimaryContact(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-indigo-500"
                />
                <label htmlFor="primaryContact" className="text-xs text-slate-600 font-medium select-none">
                  Primary Contact
                </label>
              </div>

              <button
                type="submit"
                className="px-4 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow transition-colors"
              >
                Add Member
              </button>
            </form>

            {/* Members List */}
            <div className="space-y-3">
              {loadingMembers ? (
                <div className="text-center py-6 text-xs text-slate-400 animate-pulse">Loading members...</div>
              ) : members.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-400 border border-dashed border-slate-200 rounded-lg">
                  No members assigned to this organization.
                </div>
              ) : (
                <div className="divide-y divide-slate-100">
                  {members.map((member) => (
                    <div key={member.id} className="py-3 flex justify-between items-center text-xs">
                      <div className="space-y-1">
                        <div className="font-semibold text-slate-800 flex items-center gap-2">
                          <span>User ID: <code className="font-mono text-indigo-600">{member.user_id}</code></span>
                          {member.is_primary_contact && (
                            <span className="bg-amber-100 text-amber-800 text-[9px] px-1.5 py-0.1 rounded font-medium uppercase">
                              Primary Contact
                            </span>
                          )}
                        </div>
                        <div className="text-slate-400 text-[10px]">
                          Joined: {new Date(member.joined_at).toLocaleString()}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] uppercase font-semibold">
                          {member.status}
                        </span>
                        <button
                          onClick={() => handleRemoveMember(member.id)}
                          className="p-1.5 hover:bg-rose-50 text-slate-400 hover:text-rose-600 rounded-lg transition-colors"
                          title="Remove Member"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Search / Action Bar */}
      <div className="flex justify-between items-center gap-4 flex-wrap bg-white p-4 rounded-xl border border-slate-200/80 shadow-sm">
        <div className="relative grow max-w-sm">
          <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
          <input
            type="text"
            placeholder="Search organizations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all"
          />
        </div>

        {!isCreating && !editingOrg && (
          <button
            onClick={() => { resetForm(); setIsCreating(true); }}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-sm transition-colors"
          >
            <Plus size={14} /> Create Tenant Org
          </button>
        )}
      </div>

      {/* Dynamic forms */}
      {(isCreating || editingOrg) && (
        <form
          onSubmit={isCreating ? handleCreateSubmit : handleEditSubmit}
          className="bg-white p-6 rounded-xl border border-slate-200/85 shadow-sm space-y-4"
        >
          <div className="flex justify-between items-center pb-2 border-b border-slate-100">
            <h3 className="text-sm font-semibold text-slate-900">
              {isCreating ? "Create New Multi-Tenant Organization" : `Edit ${name}`}
            </h3>
            <button
              type="button"
              onClick={() => { setIsCreating(false); setEditingOrg(null); resetForm(); }}
              className="text-xs text-slate-500 hover:text-slate-800 font-medium"
            >
              Cancel
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Org Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (isCreating) {
                    setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, ""));
                  }
                }}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Slug Identifier</label>
              <input
                type="text"
                required
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Legal Name</label>
              <input
                type="text"
                value={legalName}
                onChange={(e) => setLegalName(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Tenant Type</label>
              <select
                value={orgType}
                onChange={(e) => setOrgType(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
              >
                <option value="Tenant">Tenant (Customer)</option>
                <option value="MSP">MSP (Parent Operator)</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
              >
                <option value="active">Active</option>
                <option value="suspended">Suspended</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Subscription Tier</label>
              <select
                value={subTier}
                onChange={(e) => setSubTier(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
              >
                <option value="free">Free Starter</option>
                <option value="pro">Pro Operations</option>
                <option value="enterprise">Enterprise Core</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Contact Email</label>
              <input
                type="email"
                required
                value={contactEmail}
                onChange={(e) => setContactEmail(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Contact Phone</label>
              <input
                type="text"
                value={contactPhone}
                onChange={(e) => setContactPhone(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Timezone</label>
              <input
                type="text"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => { setIsCreating(false); setEditingOrg(null); resetForm(); }}
              className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow"
            >
              Save Organization
            </button>
          </div>
        </form>
      )}

      {/* Organizations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredOrgs.map((org) => (
          <div
            key={org.id}
            onClick={() => handleSelectOrg(org)}
            className="bg-white rounded-xl border border-slate-200/80 hover:border-slate-300 p-5 shadow-sm space-y-4 hover:shadow-md transition-all cursor-pointer relative group"
          >
            <div className="flex justify-between items-start gap-3">
              <div className="space-y-1 min-w-0">
                <h4 className="font-semibold text-slate-900 group-hover:text-indigo-600 transition-colors truncate">
                  {org.name}
                </h4>
                <p className="text-[10px] font-mono text-slate-400 truncate">slug: {org.slug}</p>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-[9px] font-semibold uppercase ${
                org.status === "active" ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
              }`}>
                {org.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 pt-2 text-[11px] border-t border-slate-100">
              <div className="text-slate-400">Type: <span className="text-slate-700 font-medium">{org.org_type}</span></div>
              <div className="text-slate-400">Tier: <span className="text-indigo-600 font-medium uppercase">{org.subscription_tier}</span></div>
            </div>

            <div className="flex justify-between items-center pt-2">
              <span className="text-[10px] text-slate-400 flex items-center gap-1">
                <Mail size={12} /> {org.contact_email}
              </span>

              <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                <button
                  onClick={(e) => startEdit(org, e)}
                  className="p-1.5 hover:bg-slate-100 text-slate-500 hover:text-slate-900 rounded-lg"
                  title="Edit Settings"
                >
                  <Edit2 size={13} />
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteOrg(org.id);
                  }}
                  className="p-1.5 hover:bg-rose-50 text-slate-400 hover:text-rose-600 rounded-lg"
                  title="Archive Org"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
