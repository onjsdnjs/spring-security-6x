package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor; // 기본 생성자 추가

import java.util.List;

@Entity
@Data
@NoArgsConstructor // JPA 엔티티는 기본 생성자가 필요할 수 있음
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username; // 일반적으로 이메일 주소 사용

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String roles; // 예: "ROLE_USER,ROLE_ADMIN"

    // --- MFA 관련 필드 ---
    @Column(nullable = false)
    private boolean mfaEnabled; // 사용자가 MFA를 활성화했는지 여부

    /**
     * 등록된 MFA 수단 (쉼표로 구분된 AuthType 이름 문자열).
     * 예: "OTT,PASSKEY" 또는 "OTT" 등. 비어있으면 등록된 MFA 없음.
     * EnumSet을 직접 저장하는 것보다 문자열로 저장하고 파싱하는 것이 일반적.
     */
    private List<String> registeredMfaFactors;

    public Users(String username, String password, String name, String roles) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.roles = roles;
    }

    // registeredMfaFactors 필드에 대한 getter (MfaWorkflowService 에서 사용)
    public List<String> getMfaFactors() {
        return registeredMfaFactors;
    }

    // 필요시 mfaFactors를 설정하는 setter도 추가 가능
    public void setMfaFactors(String[] factors) {
        this.registeredMfaFactors = List.of(factors);
    }
}
