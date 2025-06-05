package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MethodResourceDto {
    private Long id;
    private String methodName;
    private String className;
    private String accessExpression;
    private int orderNum;
    private String httpMethod; // HTTP 메서드

    // UI에서 선택된 역할 및 권한 ID 목록을 받기 위함
    private List<Long> selectedRoleIds;
    private List<Long> selectedPermissionIds;
}