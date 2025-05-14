package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.mfa.AdaptiveConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.RetryPolicy;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.function.ThrowingConsumer;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class AuthenticationFlowConfig {
    private final String typeName;
    private final int order;
    private final StateConfig stateConfig;
    private final ThrowingConsumer<HttpSecurity> rawHttpCustomizer;

    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final MfaContinuationHandler mfaContinuationHandler;
    private final MfaFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions;
    private final RetryPolicy defaultRetryPolicy;
    private final AdaptiveConfig defaultAdaptiveConfig;
    private final boolean defaultDeviceTrustEnabled;
    private final List<AuthenticationStepConfig> singleAuthSteps;

    // private 생성자
    private AuthenticationFlowConfig(Builder builder) {
        this.typeName = builder.typeName; // Builder에서 설정된 값 사용
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

    // 모든 Getter 메소드는 public
    public String typeName() { return typeName; }
    public int order() { return order; }
    public StateConfig stateConfig() { return stateConfig; }
    public ThrowingConsumer<HttpSecurity> rawHttpCustomizer() { return rawHttpCustomizer; }
    public PrimaryAuthenticationOptions getPrimaryAuthenticationOptions() { return primaryAuthenticationOptions; }
    public MfaPolicyProvider getMfaPolicyProvider() { return mfaPolicyProvider; }
    public MfaContinuationHandler getMfaContinuationHandler() { return mfaContinuationHandler; }
    public MfaFailureHandler getMfaFailureHandler() { return mfaFailureHandler; }
    public AuthenticationSuccessHandler getFinalSuccessHandler() { return finalSuccessHandler; }
    public Map<AuthType, FactorAuthenticationOptions> getRegisteredFactorOptions() { return registeredFactorOptions; }
    public RetryPolicy getDefaultRetryPolicy() { return defaultRetryPolicy; }
    public AdaptiveConfig getDefaultAdaptiveConfig() { return defaultAdaptiveConfig; }
    public boolean isDefaultDeviceTrustEnabled() { return defaultDeviceTrustEnabled; }
    public List<AuthenticationStepConfig> getSingleAuthSteps() { return singleAuthSteps; }

    public static Builder builder(String typeName) { // typeName을 생성자 인자로 받음
        return new Builder(typeName);
    }

    public static class Builder {
        private String typeName; // 생성자에서 설정됨
        private int order = 0;
        private StateConfig stateConfig;
        private ThrowingConsumer<HttpSecurity> rawHttpCustomizer = http -> {};

        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private MfaPolicyProvider mfaPolicyProvider;
        private MfaContinuationHandler mfaContinuationHandler;
        private MfaFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions = new HashMap<>(); // 초기화
        private RetryPolicy defaultRetryPolicy;
        private AdaptiveConfig defaultAdaptiveConfig;
        private boolean defaultDeviceTrustEnabled;
        private List<AuthenticationStepConfig> singleAuthSteps = Collections.emptyList(); // 초기화

        // 생성자에서 typeName을 받도록 수정
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
                Assert.isTrue(registeredFactorOptions != null && !registeredFactorOptions.isEmpty(), "At least one Factor must be registered for MFA flow named '" + typeName + "'");
            } else if (singleAuthSteps == null || singleAuthSteps.isEmpty()) {
                // 단일 인증 플로우(MFA가 아닌)의 경우 singleAuthSteps가 설정되어야 함
                // 또는 이 조건을 제거하고, MFA가 아닌 경우 stepConfigs 필드를 AuthenticationFlowConfig에 직접 추가하는 방식도 고려 가능
                // 현재는 MFA가 아닌 경우 singleAuthSteps가 필수라고 가정
                // throw new IllegalArgumentException("singleAuthSteps must be set for non-MFA flow named '" + typeName + "'");
                // 단일 인증 흐름에서도 singleAuthSteps가 비어있을 수 있도록 허용 (예: HttpSecurity만 직접 구성)
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}


