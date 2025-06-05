package io.springsecurity.springsecurity6x.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List; // List import

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResourcesDto {
    private Long id; // Resources 엔티티의 ID 타입과 일치
    private String resourceName;
    private String httpMethod;
    private int orderNum;
    private String resourceType;
    private List<Long> selectedRoleIds;
}
