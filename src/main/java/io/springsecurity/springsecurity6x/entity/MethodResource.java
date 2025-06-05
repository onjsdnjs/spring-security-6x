package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "METHOD_RESOURCES")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MethodResource implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "method_resource_id")
    private Long id;

    @Column(name = "method_name", nullable = false)
    private String methodName; // 메서드 이름 (예: "updateDocument")

    @Column(name = "class_name", nullable = false)
    private String className; // 메서드가 속한 클래스 이름 (패키지 포함, 예: "com.example.service.DocumentService")

    @Column(name = "access_expression", nullable = false)
    private String accessExpression; // DB에 저장될 SpEL 표현식 (예: "hasPermission(#documentId, 'Document', 'WRITE')")

    @Column(name = "order_num")
    private int orderNum; // 평가 순서

    @Column(name = "http_method") // HTTP 메서드 (선택적, 예: "GET", "POST", "ALL")
    private String httpMethod;

    // **관계:**
    // MethodResource와 Role 간의 조인 엔티티 매핑
    @OneToMany(mappedBy = "methodResource", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<MethodResourceRole> methodResourceRoles = new HashSet<>();

    // MethodResource와 Permission 간의 조인 엔티티 매핑
    @OneToMany(mappedBy = "methodResource", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<MethodResourcePermission> methodResourcePermissions = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MethodResource that = (MethodResource) o;
        return Objects.equals(methodName, that.methodName) &&
                Objects.equals(className, that.className) &&
                Objects.equals(httpMethod, that.httpMethod); // 고유성 판단 기준으로 사용
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodName, className, httpMethod);
    }
}
