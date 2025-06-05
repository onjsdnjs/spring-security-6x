package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.entity.Role;

import java.util.List;

public interface RoleService {
    Role getRole(long id);
    List<Role> getRoles();
    List<Role> getRolesWithoutExpression();
    Role createRole(Role role, List<Long> permissionIds);
    Role updateRole(Role role, List<Long> permissionIds);
    void deleteRole(long id);
}
