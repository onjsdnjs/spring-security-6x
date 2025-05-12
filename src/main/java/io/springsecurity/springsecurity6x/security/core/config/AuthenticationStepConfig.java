package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.enums.StepType;

import java.util.Map;
import java.util.HashMap;

/**
 * DSL 단계별 설정 정보
 */
public class AuthenticationStepConfig {
    private String type;
    private final Map<String, Object> options = new HashMap<>();

    public String type() { return type; }
    public void type(String type) { this.type = type; }
    public Map<String, Object> options() { return options; }

    /** 상태 전이 매핑 */
    public MfaState getChallengeState() {
        return StepType.of(type).challengeState();
    }
    public MfaState getSubmittedState() {
        return StepType.of(type).submittedState();
    }
}
