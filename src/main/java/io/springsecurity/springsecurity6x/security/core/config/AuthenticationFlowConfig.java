package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

/**
 * 각 인증 플로우에 대한 DSL 설정 결과를 담는 모델
 */
public final class AuthenticationFlowConfig {
    private final String typeName;
    private final List<AuthenticationStepConfig> stepConfigs;
    private final StateConfig stateConfig;
    private final ThrowingConsumer<HttpSecurity> customizer;
    private final int order;

    private AuthenticationFlowConfig(Builder builder) {
        this.typeName     = builder.typeName;
        this.stepConfigs  = List.copyOf(builder.stepConfigs);
        this.stateConfig  = builder.stateConfig;
        this.customizer   = builder.customizer;
        this.order        = builder.order;
    }

    public String typeName() { return typeName; }
    public List<AuthenticationStepConfig> stepConfigs() { return stepConfigs; }
    public StateConfig stateConfig() { return stateConfig; }
    public ThrowingConsumer<HttpSecurity> customizer() { return customizer; }
    public int order() { return order; }

    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private final String typeName;
        private List<AuthenticationStepConfig> stepConfigs = List.of();
        private StateConfig stateConfig;
        private ThrowingConsumer<HttpSecurity> customizer = http -> {};
        private int order = 0;

        public Builder(String typeName) {
            this.typeName = typeName;
        }

        public Builder stepConfigs(List<AuthenticationStepConfig> stepConfigs) {
            this.stepConfigs = stepConfigs;
            return this;
        }

        public Builder stateConfig(StateConfig stateConfig) {
            this.stateConfig = stateConfig;
            return this;
        }

        public Builder customizer(ThrowingConsumer<HttpSecurity> customizer) {
            this.customizer = customizer;
            return this;
        }

        public Builder order(int order) {
            this.order = order;
            return this;
        }

        public AuthenticationFlowConfig build() {
            return new AuthenticationFlowConfig(this);
        }
    }
}


