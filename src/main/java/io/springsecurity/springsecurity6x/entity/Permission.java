package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;
import java.io.Serializable;

@Entity
@Table(name = "PERMISSION")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Permission implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "permission_id")
    private Long id;

    @Column(name = "permission_name", unique = true, nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "target_type")
    private String targetType;

    @Column(name = "action_type")
    private String actionType;

    // ABAC 조건을 위한 SpEL 표현식 필드
    @Column(name = "condition_expression", length = 2048)
    private String conditionExpression;
}