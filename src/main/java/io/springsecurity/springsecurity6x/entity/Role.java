package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Role implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // IDENTITY 전략으로 통일하는 것이 좋음
    @Column(name = "role_id")
    private Long id;

    @Column(name = "role_name", unique = true, nullable = false) // role_name도 UNIQUE로 설정하는 것이 좋음
    private String roleName;

    @Column(name = "role_desc")
    private String roleDesc;

    @Column(name = "is_expression") // is_expression 필드 유지
    private String isExpression;

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "roleSet", cascade = CascadeType.ALL)
    @OrderBy("orderNum desc")
    private Set<Resources> resourcesSet = new LinkedHashSet<>();

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "userRoles", cascade = CascadeType.ALL)
    private Set<Users> users = new HashSet<>();

    // **새로 추가되는 부분**
    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.MERGE}) // Role 생성 시 Permission도 함께 저장될 수 있도록 MERGE
    @JoinTable(name = "role_permissions", // 새로운 조인 테이블 이름
            joinColumns = { @JoinColumn(name = "role_id") },
            inverseJoinColumns = { @JoinColumn(name = "permission_id") })
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>(); // Role에 할당되는 권한들
}
