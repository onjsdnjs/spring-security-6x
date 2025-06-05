package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleHierarchyRelationshipDto {
    private Long id;
    private Long higherRoleId;   // 상위 역할 ID
    private String higherRoleName; // UI 표시용
    private Long lowerRoleId;    // 하위 역할 ID
    private String lowerRoleName; // UI 표시용
    private String description;
}