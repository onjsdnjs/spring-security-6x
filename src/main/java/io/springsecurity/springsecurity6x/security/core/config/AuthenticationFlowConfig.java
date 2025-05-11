package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.dsl.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.RecoveryConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.RetryPolicy;
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
    private RetryPolicy retryPolicy;
    private AdaptiveConfig adaptiveConfig;
    private boolean deviceTrust;
    private RecoveryConfig recoveryConfig;

    private AuthenticationFlowConfig(Builder builder) {
        this.typeName     = builder.typeName;
        this.stepConfigs  = List.copyOf(builder.stepConfigs);
        this.stateConfig  = builder.stateConfig;
        this.customizer   = builder.customizer;
        this.order        = builder.order;
        this.retryPolicy    = builder.retryPolicy;
        this.adaptiveConfig = builder.adaptiveConfig;
        this.deviceTrust    = builder.deviceTrust;
        this.recoveryConfig = builder.recoveryConfig;
    }

    public String typeName() { return typeName; }
    public List<AuthenticationStepConfig> stepConfigs() { return stepConfigs; }
    public StateConfig stateConfig() { return stateConfig; }
    public ThrowingConsumer<HttpSecurity> customizer() { return customizer; }
    public int order() { return order; }

    public RetryPolicy retryPolicy() {
        return retryPolicy;
    }

    public AdaptiveConfig adaptiveConfig() {
        return adaptiveConfig;
    }

    public boolean deviceTrust() {
        return deviceTrust;
    }

    public RecoveryConfig recoveryConfig() {
        return recoveryConfig;
    }

    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private final String typeName;
        private List<AuthenticationStepConfig> stepConfigs = List.of();
        private StateConfig stateConfig;
        private ThrowingConsumer<HttpSecurity> customizer = http -> {};
        private int order = 0;
        private RetryPolicy retryPolicy;
        private AdaptiveConfig adaptiveConfig;
        private boolean deviceTrust;
        private RecoveryConfig recoveryConfig;


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

        public Builder retryPolicy(RetryPolicy retryPolicy) {
            this.retryPolicy = retryPolicy;
            return this;
        }

        public Builder adaptiveConfig(AdaptiveConfig adaptiveConfig) {
            this.adaptiveConfig = adaptiveConfig;
            return this;
        }

        public Builder deviceTrust(boolean deviceTrust) {
            this.deviceTrust = deviceTrust;
            return this;
        }

        public Builder recoveryConfig(RecoveryConfig recoveryConfig) {
            this.recoveryConfig = recoveryConfig;
            return this;
        }

        public AuthenticationFlowConfig build() {
            return new AuthenticationFlowConfig(this);
        }
    }
}


