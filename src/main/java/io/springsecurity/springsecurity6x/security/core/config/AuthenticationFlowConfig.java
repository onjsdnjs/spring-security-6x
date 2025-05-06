package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

/**
 * 각 인증 플로우에 대한 DSL 설정 결과를 담는 모델
 */
public class AuthenticationFlowConfig {
    private final String typeName;
    private final List<AuthenticationStepConfig> stepConfigs;
    private StateConfig stateConfig;
    private final ThrowingConsumer<HttpSecurity> customizer;

    public AuthenticationFlowConfig(
            String typeName,
            List<AuthenticationStepConfig> stepConfigs,
            StateConfig stateConfig,
            ThrowingConsumer<HttpSecurity> customizer) {
        this.typeName = typeName;
        this.stepConfigs = stepConfigs;
        this.stateConfig = stateConfig;
        this.customizer = customizer;
    }

    public String typeName() {
        return typeName;
    }

    public List<AuthenticationStepConfig> stepConfigs() {
        return stepConfigs;
    }

    public StateConfig stateConfig() {
        return stateConfig;
    }

    public void stateConfig(StateConfig stateConfig) {
        this.stateConfig = stateConfig;
    }

    public ThrowingConsumer<HttpSecurity> customizer() {
        return customizer;
    }
}

