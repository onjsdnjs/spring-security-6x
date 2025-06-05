package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleHierarchyDto {
    private Long id;
    private String hierarchyString;
    private String description;
    private Boolean isActive; // 활성화 여부
}