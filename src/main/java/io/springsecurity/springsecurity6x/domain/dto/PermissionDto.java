package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder // DTO에도 Builder 패턴을 추가하여 생성 편의성 높임
public class PermissionDto {
    private Long id;
    private String name;
    private String description;
    private String targetType;
    private String actionType;
}
