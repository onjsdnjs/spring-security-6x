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

import java.util.*;

@Getter
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
    private final List<AuthenticationStepConfig> stepConfigs;

    // private 생성자
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

        this.stepConfigs = List.copyOf(builder.stepConfigs); // 통합된 stepConfigs 사용
    }

    // 모든 Getter 메소드는 public
    public String typeName() {
        return typeName;
    }

    public int order() {
        return order;
    }

    public StateConfig stateConfig() {
        return stateConfig;
    }

    public ThrowingConsumer<HttpSecurity> rawHttpCustomizer() {
        return rawHttpCustomizer;
    }

    public static Builder builder(String typeName) { // typeName을 생성자 인자로 받음
        return new Builder(typeName);
    }

    public static class Builder {
        private String typeName;
        private int order = 0;
        private StateConfig stateConfig;
        private ThrowingConsumer<HttpSecurity> rawHttpCustomizer = http -> {
        };

        // MFA 관련 필드
        private PrimaryAuthenticationOptions primaryAuthenticationOptions;
        private Map<AuthType, FactorAuthenticationOptions> registeredFactorOptions = new HashMap<>();
        private MfaPolicyProvider mfaPolicyProvider;
        private MfaContinuationHandler mfaContinuationHandler;
        private MfaFailureHandler mfaFailureHandler;
        private AuthenticationSuccessHandler finalSuccessHandler;
        private RetryPolicy defaultRetryPolicy;
        private AdaptiveConfig defaultAdaptiveConfig;
        private boolean defaultDeviceTrustEnabled;
        private List<AuthenticationStepConfig> stepConfigs = new ArrayList<>(); // 이 필드로 통합

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

        public Builder stateConfig(StateConfig stateConfig) {
            this.stateConfig = stateConfig;
            return this;
        }

        public Builder rawHttpCustomizer(ThrowingConsumer<HttpSecurity> customizer) {
            this.rawHttpCustomizer = customizer;
            return this;
        }

        public Builder stepConfigs(List<AuthenticationStepConfig> steps) {
            if (!AuthType.MFA.name().equalsIgnoreCase(this.typeName)) {
                this.stepConfigs = (steps != null) ? new ArrayList<>(steps) : Collections.emptyList();
            }
            // MFA의 경우, 아래 primary 및 factor 옵션 설정 시 stepConfigs가 구성됨
            return this;
        }

        // MFA 용 빌더 메소드들
        public Builder primaryAuthenticationOptions(PrimaryAuthenticationOptions opts) {
            this.primaryAuthenticationOptions = opts;
            return this;
        }

        public Builder registeredFactorOptions(Map<AuthType, FactorAuthenticationOptions> options) {
            this.registeredFactorOptions = options;
            return this;
        }

        // ... (기타 MFA 관련 빌더 메소드들은 동일하게 유지) ...
        public Builder mfaPolicyProvider(MfaPolicyProvider provider) {
            this.mfaPolicyProvider = provider;
            return this;
        }

        public Builder mfaContinuationHandler(MfaContinuationHandler handler) {
            this.mfaContinuationHandler = handler;
            return this;
        }

        public Builder mfaFailureHandler(MfaFailureHandler handler) {
            this.mfaFailureHandler = handler;
            return this;
        }

        public Builder finalSuccessHandler(AuthenticationSuccessHandler handler) {
            this.finalSuccessHandler = handler;
            return this;
        }

        public Builder defaultRetryPolicy(RetryPolicy policy) {
            this.defaultRetryPolicy = policy;
            return this;
        }

        public Builder defaultAdaptiveConfig(AdaptiveConfig config) {
            this.defaultAdaptiveConfig = config;
            return this;
        }

        public Builder defaultDeviceTrustEnabled(boolean enabled) {
            this.defaultDeviceTrustEnabled = enabled;
            return this;
        }


        public AuthenticationFlowConfig build() {
            if (AuthType.MFA.name().equalsIgnoreCase(typeName)) {
                Assert.notNull(primaryAuthenticationOptions, "PrimaryAuthenticationOptions must be set for MFA flow");
                Assert.isTrue(registeredFactorOptions != null && !registeredFactorOptions.isEmpty(), "At least one Factor must be registered for MFA flow");
                // MFA 흐름의 stepConfigs 구성
                this.stepConfigs.clear(); // 기존 내용 비우기 (중복 방지)

                // 1. Primary Authentication Step 추가
                String primaryAuthType = primaryAuthenticationOptions.isFormLogin() ? "form" : "rest";
                AuthenticationStepConfig primaryStep = new AuthenticationStepConfig(primaryAuthType, 0); // order는 0으로 시작
                primaryStep.getOptions().put("_options",
                        primaryAuthenticationOptions.isFormLogin() ?
                                primaryAuthenticationOptions.getFormOptions() :
                                primaryAuthenticationOptions.getRestOptions()
                );
                this.stepConfigs.add(primaryStep);

                // 2. Factor Authentication Steps 추가 (registeredFactorOptions의 순서가 중요하다면 LinkedHashMap 사용 등 고려)
                // 여기서는 FactorAuthenticationOptions에 order 필드가 있다고 가정하고 정렬하거나,
                // DSL 에서 정의한 순서대로 Map에 삽입되었다고 가정.
                // 또는 FactorAuthenticationOptions 자체에 order를 설정할 수 있는 필드가 있어야 함.
                // 임시로 AuthType 이름 순으로 정렬하여 추가 (실제로는 DSL 정의 순서가 중요)
                int factorOrder = 1;
                List<Map.Entry<AuthType, FactorAuthenticationOptions>> sortedFactors = new ArrayList<>(registeredFactorOptions.entrySet());
                // 만약 FactorAuthenticationOptions에 getOrder()와 같은 메소드가 있다면 그것으로 정렬
                // sortedFactors.sort(Comparator.comparingInt(entry -> entry.getValue().getOrder()));

                for (Map.Entry<AuthType, FactorAuthenticationOptions> entry : sortedFactors) {
                    AuthenticationStepConfig factorStep = new AuthenticationStepConfig(entry.getKey().name().toLowerCase(), factorOrder++);
                    factorStep.getOptions().put("_options", entry.getValue());
                    this.stepConfigs.add(factorStep);
                }
                Assert.isTrue(!this.stepConfigs.isEmpty(), "MFA flow must have configured steps.");

            } else { // 단일 인증 플로우
                Assert.isTrue(this.stepConfigs != null && !this.stepConfigs.isEmpty(),
                        "Non-MFA flow named '" + typeName + "' must have at least one step.");
            }
            // rawHttpCustomizer는 null이 아니어야 함 (기본값 Customizer.withDefaults() 또는 http -> {} 사용)
            if (this.rawHttpCustomizer == null) {
                this.rawHttpCustomizer = http -> {
                };
            }

            return new AuthenticationFlowConfig(this);
        }
    }
}


