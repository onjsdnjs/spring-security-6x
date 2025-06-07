package io.springsecurity.springsecurity6x.domain.dto;

import io.springsecurity.springsecurity6x.entity.policy.Policy;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PolicyDto {
    private Long id;
    private String name;
    private String description;
    private Policy.Effect effect;
    private int priority;
    private List<String> targets; // 예: "URL:/admin/**", "METHOD:com.example.service.Admin.delete"
    private List<String> conditions; // 예: "hasRole('ADMIN')", "#riskScore < 50"
}