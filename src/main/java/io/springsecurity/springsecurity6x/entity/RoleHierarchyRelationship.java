package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "ROLE_HIERARCHY_RELATIONSHIP", uniqueConstraints = @UniqueConstraint(columnNames = {"higher_role_id", "lower_role_id"})) // 고유 제약조건
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RoleHierarchyRelationship implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "hierarchy_id")
    private Long id;

    // 상위 역할 (예: ROLE_ADMIN)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "higher_role_id", nullable = false)
    @ToString.Exclude
    private Role higherRole;

    // 하위 역할 (예: ROLE_MANAGER)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "lower_role_id", nullable = false)
    @ToString.Exclude
    private Role lowerRole;

    @Column(name = "description")
    private String description; // 관계에 대한 설명 (예: "관리자는 매니저를 포함")

    // equals와 hashCode는 복합키를 기반으로 구현
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RoleHierarchyRelationship that = (RoleHierarchyRelationship) o;
        return Objects.equals(higherRole, that.higherRole) &&
                Objects.equals(lowerRole, that.lowerRole);
    }

    @Override
    public int hashCode() {
        return Objects.hash(higherRole, lowerRole);
    }
}