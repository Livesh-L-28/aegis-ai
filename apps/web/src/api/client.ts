// API Client with organization header, correlation IDs, and unified error handling

const envBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');
export const API_BASE = envBaseUrl ? `${envBaseUrl}/api/v1` : '/api/v1';

export const DEFAULT_ORG_ID = '088adce9-4d52-4a3d-9ceb-bccba54b3d2f';
let currentActiveOrgId = DEFAULT_ORG_ID;

export function getActiveOrgId(): string {
  return currentActiveOrgId;
}

export function setActiveOrgId(orgId: string): void {
  currentActiveOrgId = orgId;
}

export interface ApiOptions extends RequestInit {
  orgId?: string;
}

export async function apiRequest<T>(endpoint: string, options: ApiOptions = {}): Promise<T> {
  const { orgId = currentActiveOrgId, headers = {}, ...rest } = options;
  
  const requestHeaders = new Headers(headers);
  requestHeaders.set('Content-Type', 'application/json');
  requestHeaders.set('X-Organization-ID', orgId);
  requestHeaders.set('X-User-ID', 'usr_dev_000000000001');
  requestHeaders.set('X-User-Roles', 'OWNER,OPERATOR');
  
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: requestHeaders,
    ...rest,
  });

  if (!res.ok) {
    let errMessage = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const errData = await res.json();
      if (errData.detail) errMessage = errData.detail;
      else if (errData.error?.message) errMessage = errData.error.message;
    } catch {
      // ignore json parse error
    }
    throw new Error(errMessage);
  }

  // Handle empty responses
  if (res.status === 204) {
    return {} as T;
  }

  return res.json();
}
