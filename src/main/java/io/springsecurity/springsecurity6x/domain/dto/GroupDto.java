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
public class GroupDto {
    private Long id;
    private String name;
    private String description;
    private List<Long> selectedRoleIds; // UI에서 선택된 Role ID 목록을 받기 위함
}
