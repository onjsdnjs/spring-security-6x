package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.Getter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.function.ThrowingConsumer;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public final class AuthenticationFlowConfig {
    private final String typeName;
    private final int order;
    private final StateConfig stateConfig; // 상태 관리 전략 (JWT, Session 등)
    private final ThrowingConsumer<HttpSecurity> rawHttpCustomizer; // HttpSecurity 직접 조작

    // MFA Flow 전용 설정
    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final MfaContinuationHandler mfaContinuationHandler;
    private final MfaFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions;
    private final RetryPolicy defaultRetryPolicy;
    private final AdaptiveConfig defaultAdaptiveConfig;
    private final boolean defaultDeviceTrustEnabled;

    // 단일 인증 플로우용 (기존 stepConfigs 역할)
    private final List<AuthenticationStepConfig> singleAuthSteps;

    private AuthenticationFlowConfig(Builder builder) {
        this.typeName = builder.typeName;
        this.order = builder.order;
        this.stateConfig = builder.stateConfig;
        this.rawHttpCustomizer = builder.rawHttpCustomizer;

        this.primaryAuthenticationOptions = builder.primaryAuthenticationOptions;
        this.mfaPolicyProvider = builder.mfaPolicyProvider;
        this.mfaContinuationHandler = builder.mfaContinuationHandler;
        this.mfaFailureHandler = builder.mfaFailureHandler;
        this.finalSuccessHandler = builder.finalSuccessHandler;
        this.registeredFactorOptions = builder.registeredFactorOptions != null ?
                Collections.unmodifiableMap(new HashMap<>(builder.registeredFactorOptions)) :
                Collections.emptyMap();
        this.defaultRetryPolicy = builder.defaultRetryPolicy;
        this.defaultAdaptiveConfig = builder.defaultAdaptiveConfig;
        this.defaultDeviceTrustEnabled = builder.defaultDeviceTrustEnabled;
        this.singleAuthSteps = builder.singleAuthSteps != null ?
                List.copyOf(builder.singleAuthSteps) :
                Collections.emptyList();
    }

    public String typeName() { return typeName; }
    public int order() { return order; }
    public StateConfig stateConfig() { return stateConfig; }
    public ThrowingConsumer<HttpSecurity> rawHttpCustomizer() { return rawHttpCustomizer; }

    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private final String typeName;
        private int order = 0;
        private StateConfig stateConfig; // AbstractFlowRegistrar에서 설정
        private ThrowingConsumer<HttpSecurity> rawHttpCustomizer = http -> {}; // 기본값 설정

        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private MfaPolicyProvider mfaPolicyProvider;
        private MfaContinuationHandler mfaContinuationHandler;
        private MfaFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions;
        private RetryPolicy defaultRetryPolicy;
        private AdaptiveConfig defaultAdaptiveConfig;
        private boolean defaultDeviceTrustEnabled;
        private List<AuthenticationStepConfig> singleAuthSteps; // 단일 인증 플로우용

        public Builder(String typeName) {
            this.typeName = typeName;
        }

        public Builder order(int order) { this.order = order; return this; }
        public Builder stateConfig(StateConfig stateConfig) { this.stateConfig = stateConfig; return this; }
        public Builder rawHttpCustomizer(ThrowingConsumer<HttpSecurity> customizer) { this.rawHttpCustomizer = customizer; return this; }

        public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions opts) { this.primaryAuthenticationOptions = opts; return this; }
        public Builder mfaPolicyProvider(MfaPolicyProvider provider) { this.mfaPolicyProvider = provider; return this; }
        public Builder mfaContinuationHandler(MfaContinuationHandler handler) { this.mfaContinuationHandler = handler; return this; }
        public Builder mfaFailureHandler(MfaFailureHandler handler) { this.mfaFailureHandler = handler; return this; }
        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) { this.finalSuccessHandler = handler; return this; }
        public Builder registeredFactorOptions(Map<AuthType, FactorAuthenticationOptions> options) { this.registeredFactorOptions = options; return this; }
        public Builder defaultRetryPolicy(RetryPolicy policy) { this.defaultRetryPolicy = policy; return this; }
        public Builder defaultAdaptiveConfig(AdaptiveConfig config) { this.defaultAdaptiveConfig = config; return this; }
        public Builder defaultDeviceTrustEnabled(boolean enabled) { this.defaultDeviceTrustEnabled = enabled; return this; }

        public Builder singleAuthSteps(List<AuthenticationStepConfig> steps) { this.singleAuthSteps = steps; return this; }

        public AuthenticationFlowConfig build() {
            if (AuthType.MFA.name().equalsIgnoreCase(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow named '" + typeName + "'");
                Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider must be set for MFA flow named '" + typeName + "'");
                Assert.notNull(mfaContinuationHandler, "MfaContinuationHandler must be set for MFA flow named '" + typeName + "'");
                Assert.notNull(mfaFailureHandler, "MfaFailureHandler must be set for MFA flow named '" + typeName + "'");
                Assert.notNull(finalSuccessHandler, "FinalSuccessHandler must be set for MFA flow named '" + typeName + "'");
                Assert.notEmpty(registeredFactorOptions, "At least one Factor must be registered for MFA flow named '" + typeName + "'");
            } else {
                // MFA가 아닌 플로우(예: form, rest 단독 사용)의 경우 singleAuthSteps가 필요할 수 있음
                Assert.isTrue(singleAuthSteps != null && !singleAuthSteps.isEmpty(),
                        "singleAuthSteps must be set for non-MFA flow named '" + typeName + "'");
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}


