package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

/**
 * 각 인증 플로우에 대한 DSL 설정 결과를 담는 모델
 */
public class AuthenticationFlowConfig {
    private final String type;
    private final List<AuthenticationStepConfig> steps;
    private StateConfig state;
    private final ThrowingConsumer<HttpSecurity> customizer;

    public AuthenticationFlowConfig(
            String type,
            List<AuthenticationStepConfig> steps,
            StateConfig state,
            ThrowingConsumer<HttpSecurity> customizer
    ) {
        this.type = type;
        this.steps = steps;
        this.state = state;
        this.customizer = customizer;
    }

    public String getType() {
        return type;
    }

    public List<AuthenticationStepConfig> getSteps() {
        return steps;
    }

    public StateConfig getState() {
        return state;
    }

    public void setState(StateConfig state) {
        this.state = state;
    }

    public ThrowingConsumer<HttpSecurity> getCustomizer() {
        return customizer;
    }
}

