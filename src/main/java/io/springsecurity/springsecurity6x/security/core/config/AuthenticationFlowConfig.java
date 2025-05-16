package io.springsecurity.springsecurity6x.security.core.config;

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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class AuthenticationFlowConfig {

    private final String typeName;
    private final int order;
    private final StateConfig stateConfig;
    private final Customizer<HttpSecurity> rawHttpCustomizer;

    private final PrimaryAuthenticationOptions primaryAuthenticationOptions;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final MfaContinuationHandler mfaContinuationHandler;
    private final MfaFailureHandler mfaFailureHandler;
    private final AuthenticationSuccessHandler finalSuccessHandler;
    private final Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions;
    private final RetryPolicy defaultRetryPolicy;
    private final AdaptiveConfig defaultAdaptiveConfig;
    private final boolean defaultDeviceTrustEnabled;
    private final List<AuthenticationStepConfig> stepConfigs;

    // Private 생성자, Builder를 통해서만 생성
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
                Collections.unmodifiableMap(new HashMap<>(builder.registeredFactorOptions)) : // 방어적 복사
                Collections.emptyMap();
        this.defaultRetryPolicy = builder.defaultRetryPolicy;
        this.defaultAdaptiveConfig = builder.defaultAdaptiveConfig;
        this.defaultDeviceTrustEnabled = builder.defaultDeviceTrustEnabled;
        this.stepConfigs = builder.stepConfigs != null ?
                Collections.unmodifiableList(new ArrayList<>(builder.stepConfigs)) : // 방어적 복사
                Collections.emptyList();
    }


    /**
     * 현재 객체의 복사본을 만들되, StateConfig만 새로운 값으로 대체합니다.
     * @param newStateConfig 새로운 StateConfig
     * @return StateConfig가 변경된 새로운 AuthenticationFlowConfig 인스턴스
     */
    public AuthenticationFlowConfig withStateConfig(StateConfig newStateConfig) {
        Builder builder = new Builder(this.typeName)
                .order(this.order)
                .rawHttpCustomizer(this.rawHttpCustomizer)
                .primaryAuthenticationOptions(this.primaryAuthenticationOptions)
                .mfaPolicyProvider(this.mfaPolicyProvider)
                .mfaContinuationHandler(this.mfaContinuationHandler)
                .mfaFailureHandler(this.mfaFailureHandler)
                .finalSuccessHandler(this.finalSuccessHandler)
                // Map과 List는 새로운 컬렉션으로 복사하여 불변성 유지
                .registeredFactorOptions(this.registeredFactorOptions != null ? new HashMap<>(this.registeredFactorOptions) : null)
                .defaultRetryPolicy(this.defaultRetryPolicy)
                .defaultAdaptiveConfig(this.defaultAdaptiveConfig)
                .defaultDeviceTrustEnabled(this.defaultDeviceTrustEnabled)
                .stepConfigs(this.stepConfigs != null ? new ArrayList<>(this.stepConfigs) : null)
                .stateConfig(newStateConfig); // 새 StateConfig 설정
        return new AuthenticationFlowConfig(builder); // private 생성자 호출, build() 재호출 아님
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
        private MfaContinuationHandler mfaContinuationHandler;
        private MfaFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private Map<AuthType, AuthenticationProcessingOptions> registeredFactorOptions = new HashMap<>();
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
        public Builder mfaContinuationHandler(MfaContinuationHandler handler) { this.mfaContinuationHandler = handler; return this; }
        public Builder mfaFailureHandler(MfaFailureHandler handler) { this.mfaFailureHandler = handler; return this; }
        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) { this.finalSuccessHandler = handler; return this; }
        public Builder defaultRetryPolicy(RetryPolicy policy) { this.defaultRetryPolicy = policy; return this; }
        public Builder defaultAdaptiveConfig(AdaptiveConfig config) { this.defaultAdaptiveConfig = config; return this; }
        public Builder defaultDeviceTrustEnabled(boolean enabled) { this.defaultDeviceTrustEnabled = enabled; return this; }

        /**
         * 최종 AuthenticationFlowConfig 객체를 생성합니다.
         * 이 메소드는 각 Flow 설정이 완료된 후 단 한 번만 호출되어야 합니다.
         * @return 구성된 AuthenticationFlowConfig 객체
         */
        public AuthenticationFlowConfig build() {
            // 유효성 검사는 여기에 유지 (최종 빌드 시점에 검증)
            if (AuthType.MFA.name().equalsIgnoreCase(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow named '" + typeName + "'");
                Assert.isTrue(registeredFactorOptions != null && !registeredFactorOptions.isEmpty(), "At least one Factor must be registered for MFA flow named '" + typeName + "'");
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(), "MFA flow must have its steps configured in stepConfigs field.");
            } else { // 단일 인증 플로우
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(),
                        "Non-MFA flow named '" + typeName + "' must have at least one step in stepConfigs.");
            }
            return new AuthenticationFlowConfig(this);
        }
    }
}


