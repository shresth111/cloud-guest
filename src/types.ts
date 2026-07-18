export interface User {
  id: string;
  first_name: string;
  last_name: string;
  email: string;
  username: string;
  phone?: string;
  profile_photo?: string;
  designation?: string;
  department?: string;
  timezone?: string;
  language?: string;
  status: string;
  is_active: boolean;
  is_verified: boolean;
  email_verified_at?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Session {
  id: string;
  device_id: string;
  device_name: string;
  ip_address: string;
  user_agent: string;
  location?: string;
  is_current: boolean;
  created_at: string;
  expires_at: string;
  last_activity_at: string;
  is_active: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  legal_name?: string;
  org_type: string;
  status: string;
  parent_organization_id?: string | null;
  contact_email: string;
  contact_phone?: string;
  timezone: string;
  default_locale: string;
  settings?: Record<string, any>;
  subscription_tier: string;
  created_at: string;
  updated_at: string;
}

export interface Location {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  address_line1?: string;
  address_line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country: string;
  timezone: string;
  latitude?: number;
  longitude?: number;
  created_at: string;
  updated_at: string;
}

export interface RouterDevice {
  id: string;
  organization_id: string;
  location_id?: string | null;
  name: string;
  serial_number: string;
  mac_address: string;
  ip_address?: string;
  model: string;
  ros_version: string;
  status: "online" | "offline" | "connecting" | "error";
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data: T;
  request_id: string;
}
