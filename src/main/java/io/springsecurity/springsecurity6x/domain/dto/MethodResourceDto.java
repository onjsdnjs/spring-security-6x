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
    private String httpMethod;
    private List<Long> selectedRoleIds;
    private List<Long> selectedPermissionIds;
}