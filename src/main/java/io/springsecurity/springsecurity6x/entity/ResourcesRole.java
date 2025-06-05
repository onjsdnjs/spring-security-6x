package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "RESOURCES_ROLES") // Resources와 Role의 조인 테이블
@IdClass(ResourcesRoleId.class) // 복합 PK를 위한 @IdClass 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResourcesRole implements Serializable {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "resource_id") // DB 컬럼 이름
    @ToString.Exclude
    private Resources resources; // 자원 엔티티 (ManyToOne 관계의 소유자)

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id") // DB 컬럼 이름
    @ToString.Exclude
    private Role role; // 역할 엔티티 (ManyToOne 관계의 소유자)

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResourcesRole that = (ResourcesRole) o;
        return Objects.equals(resources, that.resources) &&
                Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resources, role);
    }
}

// 복합 PK를 위한 ID 클래스 (ResourcesRoleId.java)
@Data // @EqualsAndHashCode, @NoArgsConstructor, @AllArgsConstructor 자동 생성
@NoArgsConstructor
@AllArgsConstructor
class ResourcesRoleId implements Serializable {
    private Long resources; // Resources 엔티티의 ID 타입과 일치해야 함
    private Long role;      // Role 엔티티의 ID 타입과 일치해야 함
}