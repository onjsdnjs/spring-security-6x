package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.*;
import java.io.Serializable;

@Entity
@Table(name = "PERMISSION") // 테이블 이름은 PERMISSION
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
    private String name; // 예: DOCUMENT_READ, BOARD_CREATE, FILE_DELETE

    @Column(name = "description")
    private String description;

    @Column(name = "target_type") // 이 권한이 적용되는 대상 도메인 객체 타입 (예: "Document", "Board")
    private String targetType;

    @Column(name = "action_type") // 이 권한이 허용하는 구체적인 행동 (예: "READ", "WRITE", "DELETE", "UPDATE")
    private String actionType; // 'action'은 SQL 키워드일 수 있으므로 'action_type'으로 변경

    // 다른 속성 추가 가능: createdBy, createdAt, updatedBy, updatedAt 등
}
