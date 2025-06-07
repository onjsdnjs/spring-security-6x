package io.springsecurity.springsecurity6x.entity.policy;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

/**
 * 정책이 적용될 대상을 정의하는 엔티티.
 */
@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyTarget implements Serializable {
    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Column(nullable = false)
    private String targetType; // 예: "URL", "METHOD"

    @Column(nullable = false)
    private String targetIdentifier; // 예: "/admin/**", "com.example.service.AdminService.deleteUser"
}