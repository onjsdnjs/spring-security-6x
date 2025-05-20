package io.springsecurity.springsecurity6x.security.core.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString; // ToString 추가

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Getter
@Setter
@ToString
public class AuthenticationStepConfig {
    private String stepId; // <<-- 고유 식별자 필드 추가
    private String type;   // 예: "form", "ott", "passkey"
    private final Map<String, Object> options = new HashMap<>();
    private int order = 0;

    public AuthenticationStepConfig() {}

    public AuthenticationStepConfig(String type, int order) {
        this.type = type;
        this.order = order;
        // stepId는 이 시점 또는 DSL 빌드 시점에 설정 필요
    }

    // stepId를 위한 생성자 또는 setter (MfaDslConfigurerImpl 등에서 사용)
    public AuthenticationStepConfig(String flowName, String type, int order) {
        this.type = type;
        this.order = order;
        this.stepId = generateId(flowName, type, order); // stepId 자동 생성
    }


    public void addOption(String key, Object value) {
        this.options.put(key, value);
    }

    public <T> T getOption(String key) {
        return (T) this.options.get(key);
    }

    // stepId 자동 생성 헬퍼 (필요시 MfaDslConfigurerImpl 내부로 이동 가능)
    public static String generateId(String flowName, String factorType, int order) {
        return flowName.toLowerCase() + ":" + factorType.toLowerCase() + ":" + order;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationStepConfig that = (AuthenticationStepConfig) o;
        // stepId가 고유하므로, stepId로 비교하거나, 모든 필드 비교 유지
        return order == that.order &&
                Objects.equals(stepId, that.stepId) &&
                Objects.equals(type, that.type) &&
                Objects.equals(options, that.options);
    }

    @Override
    public int hashCode() {
        return Objects.hash(stepId, type, options, order);
    }
}