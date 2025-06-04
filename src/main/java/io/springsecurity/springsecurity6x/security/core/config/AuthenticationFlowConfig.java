package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.MfaAsepAttributes; // 추가
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.Getter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class AuthenticationFlowConfig {

    private final String typeName;
    private final int order;
    private final StateConfig stateConfig;
    private final Customizer<HttpSecurity> rawHttpCustomizer; // SafeHttpCustomizer<HttpSecurity>로 변경 가능

    // MFA 전용 필드들
    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthenticationFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions;
    private final RetryPolicy defaultRetryPolicy;
    private final AdaptiveConfig defaultAdaptiveConfig;
    private final boolean defaultDeviceTrustEnabled;
    private final MfaAsepAttributes mfaAsepAttributes; // <<-- 추가

    private final List<AuthenticationStepConfig> stepConfigs;

    private AuthenticationFlowConfig(Builder builder) {
        this.typeName = builder.typeName;
        this.order = builder.order;
        this.stateConfig = builder.stateConfig;
        this.rawHttpCustomizer = builder.rawHttpCustomizer;
        this.primaryAuthenticationOptions = builder.primaryAuthenticationOptions;
        this.mfaPolicyProvider = builder.mfaPolicyProvider;
        this.mfaFailureHandler = builder.mfaFailureHandler;
        this.finalSuccessHandler = builder.finalSuccessHandler;
        this.registeredFactorOptions = builder.registeredFactorOptions != null ? Map.copyOf(builder.registeredFactorOptions) :
                Collections.emptyMap();
        this.defaultRetryPolicy = builder.defaultRetryPolicy;
        this.defaultAdaptiveConfig = builder.defaultAdaptiveConfig;
        this.defaultDeviceTrustEnabled = builder.defaultDeviceTrustEnabled;
        this.mfaAsepAttributes = builder.mfaAsepAttributes; // <<-- 추가
        this.stepConfigs = builder.stepConfigs != null ?
                Collections.unmodifiableList(new ArrayList<>(builder.stepConfigs)) :
                Collections.emptyList();
    }

    public AuthenticationFlowConfig withStateConfig(StateConfig newStateConfig) {
        Builder builder = new Builder(this.typeName)
                .order(this.order)
                .rawHttpCustomizer(this.rawHttpCustomizer)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .mfaPolicyProvider(this.mfaPolicyProvider)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                .registeredFactorOptions(this.registeredFactorOptions != null ? new HashMap<>(this.registeredFactorOptions) : null)
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .mfaAsepAttributes(this.mfaAsepAttributes) // <<-- 복사 시 추가
                .stepConfigs(this.stepConfigs != null ? new ArrayList<>(this.stepConfigs) : null)
                .stateConfig(newStateConfig);
        return new AuthenticationFlowConfig(builder);
    }

    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private String typeName;
        private int order = 0;
        private StateConfig stateConfig;
        private Customizer<HttpSecurity> rawHttpCustomizer = http -> {};

        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private MfaPolicyProvider mfaPolicyProvider;
        private AuthenticationFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions = new HashMap<>();
        private RetryPolicy defaultRetryPolicy;
        private AdaptiveConfig defaultAdaptiveConfig;
        private boolean defaultDeviceTrustEnabled;
        private MfaAsepAttributes mfaAsepAttributes; // <<-- 추가
        private List<AuthenticationStepConfig> stepConfigs = new ArrayList<>();

        public Builder(String typeName) {
            Assert.hasText(typeName, "typeName cannot be empty");
            this.typeName = typeName;
        }

        public Builder typeName(String typeName) {
            Assert.hasText(typeName, "typeName cannot be empty");
            this.typeName = typeName;
            return this;
        }

        public Builder order(int order) {
            this.order = order;
            return this;
        }
        public Builder stateConfig(StateConfig stateConfig) { this.stateConfig = stateConfig; return this; }
        public Builder rawHttpCustomizer(Customizer<HttpSecurity> customizer) {
            this.rawHttpCustomizer = customizer;
            return this;
        }
        public Builder stepConfigs(List<AuthenticationStepConfig> steps) {
            this.stepConfigs = (steps != null) ? new ArrayList<>(steps) : Collections.emptyList();
            return this;
        }

        public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions opts) { this.primaryAuthenticationOptions = opts; return this; }
        public Builder registeredFactorOptions(Map<AuthType, AuthenticationProcessingOptions> options) {
            this.registeredFactorOptions = (options != null) ? new HashMap<>(options) : new HashMap<>();
            return this;
        }
        public Builder mfaPolicyProvider(MfaPolicyProvider provider) { this.mfaPolicyProvider = provider; return this; }
        public Builder mfaFailureHandler(AuthenticationFailureHandler handler) { this.mfaFailureHandler = handler; return this; }
        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) { this.finalSuccessHandler = handler; return this; }
        public Builder defaultRetryPolicy(RetryPolicy policy) { this.defaultRetryPolicy = policy; return this; }
        public Builder defaultAdaptiveConfig(AdaptiveConfig config) { this.defaultAdaptiveConfig = config; return this; }
        public Builder defaultDeviceTrustEnabled(boolean enabled) { this.defaultDeviceTrustEnabled = enabled; return this; }

        public Builder mfaAsepAttributes(MfaAsepAttributes attributes) { // <<-- 추가
            this.mfaAsepAttributes = attributes;
            return this;
        }

        public AuthenticationFlowConfig build() {
            if (AuthType.MFA.name().equalsIgnoreCase(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow named '" + typeName + "'");
                // Assert.isTrue(registeredFactorOptions != null && !registeredFactorOptions.isEmpty(), "At least one Factor must be registered for MFA flow named '" + typeName + "'"); // 이 조건은 policyProvider가 동적으로 결정할 수 있으므로 완화 가능
                Assert.isTrue(this.stepConfigs != null && this.stepConfigs.size() > 1, "MFA flow must have its primary and at least one secondary factor step configured in stepConfigs field.");
            } else {
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(),
                        "Non-MFA flow named '" + typeName + "' must have at least one step in stepConfigs.");
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}


