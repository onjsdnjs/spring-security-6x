package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "METHOD_RESOURCE_ROLES") // MethodResource와 Role의 조인 테이블
@IdClass(MethodResourceRoleId.class) // 복합 PK를 위한 @IdClass 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MethodResourceRole implements Serializable {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "method_resource_id")
    @ToString.Exclude
    private MethodResource methodResource; // 메서드 자원 엔티티

    @Id
    @ManyToOne(fetch = FetchType.LAZY) // FetchType.LAZY 오타 수정
    @JoinColumn(name = "role_id")
    @ToString.Exclude
    private Role role; // 역할 엔티티

    // 추가 속성
    // @Column(name = "assigned_at")
    // private Instant assignedAt;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MethodResourceRole that = (MethodResourceRole) o;
        return Objects.equals(methodResource, that.methodResource) &&
                Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodResource, role);
    }
}

// 복합 PK를 위한 ID 클래스
@Data
@NoArgsConstructor
@AllArgsConstructor
class MethodResourceRoleId implements Serializable {
    private Long methodResource; // MethodResource 엔티티의 ID 타입과 일치해야 함
    private Long role;           // Role 엔티티의 ID 타입과 일치해야 함
}
