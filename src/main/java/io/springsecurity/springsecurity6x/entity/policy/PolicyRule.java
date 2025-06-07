package io.springsecurity.springsecurity6x.entity.policy;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * 정책 내의 개별 규칙을 정의하는 엔티티.
 * 하나의 규칙은 여러 조건(Condition)을 가질 수 있으며, 모든 조건이 충족되어야 규칙이 참(true)이 됩니다.
 */
@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyRule implements Serializable {
    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    private String description;

    @OneToMany(mappedBy = "rule", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @Builder.Default
    private Set<PolicyCondition> conditions = new HashSet<>();
}
