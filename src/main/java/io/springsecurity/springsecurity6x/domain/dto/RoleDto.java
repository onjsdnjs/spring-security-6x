package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleDto{
    private String id;
    private String roleName;
    private String roleDesc;
    private String isExpression;
    private List<Long> permissionIds;
}
