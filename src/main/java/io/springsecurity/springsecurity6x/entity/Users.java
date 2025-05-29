package io.springsecurity.springsecurity6x.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Data
@NoArgsConstructor
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

    @Column
    private String preferredMfaFactor;

    @Column
    private String lastUsedMfaFactor;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private java.util.Date lastMfaUsedAt;

    public Users(String username, String password, String name, String roles) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.roles = roles;
    }

    private List<String> registeredMfaFactors;

    // registeredMfaFactors 필드에 대한 getter (MfaWorkflowService 에서 사용)
    public List<String> getMfaFactors() {
        return registeredMfaFactors;
    }

    // 필요시 mfaFactors를 설정하는 setter도 추가 가능
    public void setMfaFactors(String[] factors) {
        this.registeredMfaFactors = Arrays.stream(factors)
                .flatMap(s -> Arrays.stream(s.split(",")))
                .map(String::trim)
                .toList();
    }

    /**
     * 선호하는 MFA 팩터 반환
     * 설정되지 않은 경우 마지막 사용 팩터를 반환
     */
    public String getPreferredMfaFactor() {
        if (preferredMfaFactor != null && !preferredMfaFactor.isEmpty()) {
            return preferredMfaFactor;
        }
        // 선호 팩터가 없으면 마지막 사용 팩터 반환
        return lastUsedMfaFactor;
    }

    /**
     * 실제 선호 팩터만 반환 (fallback 없음)
     */
    public String getExplicitPreferredMfaFactor() {
        return preferredMfaFactor;
    }

    /**
     * 선호 팩터 설정 시 유효성 검증
     */
    public void setPreferredMfaFactor(String factor) {
        if (factor != null && registeredMfaFactors != null &&
                !registeredMfaFactors.contains(factor)) {
            throw new IllegalArgumentException(
                    "Preferred factor must be one of registered factors");
        }
        this.preferredMfaFactor = factor;
    }

    /**
     * MFA 사용 기록 업데이트
     */
    public void updateMfaUsage(String factorUsed) {
        this.lastUsedMfaFactor = factorUsed;
        this.lastMfaUsedAt = new java.util.Date();
    }

    /**
     * 등록된 팩터 중 선호 팩터가 있는지 확인
     */
    public boolean hasPreferredFactorRegistered() {
        return preferredMfaFactor != null &&
                registeredMfaFactors != null &&
                registeredMfaFactors.contains(preferredMfaFactor);
    }
}