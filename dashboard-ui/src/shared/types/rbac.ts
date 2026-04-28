export type RbacEntity = {
  id: string;
  name: string;
  /** Present for service-wide RBAC (global admin) so names are unique per tenant. */
  tenant_id?: string;
};

export type RbacMappingRow = {
  role_id: string;
  role_name: string;
  permission_id: string;
  permission_name: string;
  tenant_id?: string;
};

export type RbacResponse = {
  roles: RbacEntity[];
  permissions: RbacEntity[];
  role_permissions: RbacMappingRow[];
};
