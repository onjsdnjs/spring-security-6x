package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

public final class AuthenticationFlowConfig {
    private final String typeName;
    private final int order;
    private final StateConfig stateConfig;
    private final Customizer<HttpSecurity> rawHttpCustomizer; // ThrowingConsumer 대신 Customizer 사용

    // MFA 관련 필드 (MFA 흐름이 아닐 경우 null일 수 있음)
    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final MfaContinuationHandler mfaContinuationHandler;
    private final MfaFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions;
    private final RetryPolicy defaultRetryPolicy;
    private final AdaptiveConfig defaultAdaptiveConfig;
    private final boolean defaultDeviceTrustEnabled;

    // 모든 흐름(단일, MFA)의 스텝을 통합 관리
    private final List<AuthenticationStepConfig> stepConfigs;

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

        this.stepConfigs = builder.stepConfigs != null ?
                Collections.unmodifiableList(new ArrayList<>(builder.stepConfigs)) :
                Collections.emptyList();
    }

    // Getters
    public String getTypeName() { return typeName; }
    public int getOrder() { return order; }
    public StateConfig getStateConfig() { return stateConfig; }
    public Customizer<HttpSecurity> getRawHttpCustomizer() { return rawHttpCustomizer; } // 반환 타입 변경
    public List<AuthenticationStepConfig> getStepConfigs() { return stepConfigs; } // 통합된 스텝 목록 반환

    // MFA 관련 Getter들
    public PrimaryAuthenticationOptions getPrimaryAuthenticationOptions() { return primaryAuthenticationOptions; }
    public MfaPolicyProvider getMfaPolicyProvider() { return mfaPolicyProvider; }
    public MfaContinuationHandler getMfaContinuationHandler() { return mfaContinuationHandler; }
    public MfaFailureHandler getMfaFailureHandler() { return mfaFailureHandler; }
    public AuthenticationSuccessHandler getFinalSuccessHandler() { return finalSuccessHandler; }
    public Map<AuthType, FactorAuthenticationOptions> getRegisteredFactorOptions() { return registeredFactorOptions; }
    public RetryPolicy getDefaultRetryPolicy() { return defaultRetryPolicy; }
    public AdaptiveConfig getDefaultAdaptiveConfig() { return defaultAdaptiveConfig; }
    public boolean isDefaultDeviceTrustEnabled() { return defaultDeviceTrustEnabled; }


    public static Builder builder(String typeName) {
        return new Builder(typeName);
    }

    public static class Builder {
        private String typeName;
        private int order = 0;
        private StateConfig stateConfig;
        private Customizer<HttpSecurity> rawHttpCustomizer = http -> {}; // 타입 및 기본값 변경

        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private MfaPolicyProvider mfaPolicyProvider;
        private MfaContinuationHandler mfaContinuationHandler;
        private MfaFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions = new HashMap<>();
        private RetryPolicy defaultRetryPolicy;
        private AdaptiveConfig defaultAdaptiveConfig;
        private boolean defaultDeviceTrustEnabled;

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

        public Builder order(int order) { this.order = order; return this; }
        public Builder stateConfig(StateConfig stateConfig) { this.stateConfig = stateConfig; return this; }
        public Builder rawHttpCustomizer(Customizer<HttpSecurity> customizer) { // 타입 변경
            this.rawHttpCustomizer = customizer;
            return this;
        }
        public Builder stepConfigs(List<AuthenticationStepConfig> steps) {
            this.stepConfigs = (steps != null) ? new ArrayList<>(steps) : Collections.emptyList();
            return this;
        }

        // MFA 관련 setter
        public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions opts) { this.primaryAuthenticationOptions = opts; return this; }
        public Builder registeredFactorOptions(Map<AuthType, FactorAuthenticationOptions> options) { this.registeredFactorOptions = options; return this; }
        public Builder mfaPolicyProvider(MfaPolicyProvider provider) { this.mfaPolicyProvider = provider; return this; }
        public Builder mfaContinuationHandler(MfaContinuationHandler handler) { this.mfaContinuationHandler = handler; return this; }
        public Builder mfaFailureHandler(MfaFailureHandler handler) { this.mfaFailureHandler = handler; return this; }
        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) { this.finalSuccessHandler = handler; return this; }
        public Builder defaultRetryPolicy(RetryPolicy policy) { this.defaultRetryPolicy = policy; return this; }
        public Builder defaultAdaptiveConfig(AdaptiveConfig config) { this.defaultAdaptiveConfig = config; return this; }
        public Builder defaultDeviceTrustEnabled(boolean enabled) { this.defaultDeviceTrustEnabled = enabled; return this; }


        public AuthenticationFlowConfig build() {
            if (AuthType.MFA.name().equalsIgnoreCase(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow named '" + typeName + "'");
                Assert.isTrue(registeredFactorOptions != null && !registeredFactorOptions.isEmpty(), "At least one Factor must be registered for MFA flow named '" + typeName + "'");

                // MFA 흐름의 stepConfigs 구성 (MfaDslConfigurerImpl 에서 이미 이 작업을 수행하고 builder.stepConfigs()를 호출하도록 변경하는 것이 더 좋음)
                // 여기서는 MfaDslConfigurerImpl이 primary와 factor 옵션들을 설정하고,
                // build() 시점에서 이들을 조합하여 stepConfigs 리스트를 만들어 여기에 설정한다고 가정.
                // 이 build() 메소드에서 직접 stepConfigs를 구성하는 것은 MfaDslConfigurerImpl의 책임과 중복될 수 있음.
                // **따라서 MfaDslConfigurerImpl의 build() 메소드에서 flowConfigBuilder.stepConfigs(...)를 호출하여
                // 완성된 스텝 리스트를 전달하는 것이 더 나은 설계임.**
                // 아래는 MfaDslConfigurerImpl 에서 이 작업을 수행했다고 가정하고, 여기서는 단순히 유효성만 검사.
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(), "MFA flow must have its steps configured in stepConfigs field.");
            } else { // 단일 인증 플로우
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(),
                        "Non-MFA flow named '" + typeName + "' must have at least one step in stepConfigs.");
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}


