package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "RESOURCES")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@EntityListeners(value = { AuditingEntityListener.class })
@Builder
@AllArgsConstructor
public class Resources implements Serializable {
    @Id
    @GeneratedValue
    @Column(name = "resource_id")
    private Long id;

    @Column(name = "resource_name")
    private String resourceName;

    @Column(name = "http_method")
    private String httpMethod;

    @Column(name = "order_num")
    private int orderNum;

    @Column(name = "resource_type")
    private String resourceType;

    @OneToMany(mappedBy = "resources", cascade = CascadeType.ALL, orphanRemoval = true) // ResourcesRole 엔티티의 'resources' 필드에 매핑
    @Builder.Default
    @ToString.Exclude
    private Set<ResourcesRole> resourcesRoles = new HashSet<>(); // 이 자원에 할당된 역할들

}