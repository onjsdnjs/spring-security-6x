package io.springsecurity.springsecurity6x.security.core.feature.auth.mfa;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.DefaultRiskEngine;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.filter.MfaAuthenticationFilter;
import jakarta.servlet.Filter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

public class MfaAuthenticationFeature implements AuthenticationFeature {
    private static final String ID = "mfa";
    private static final String MFA_LOGIN_URL = "/api/auth/mfa";

    private final AuditEventPublisher auditPublisher = new DefaultAuditEventPublisher();
    private final RiskEngine riskEngine = new DefaultRiskEngine();
    private final TrustedDeviceService trustedDeviceService = new DefaultTrustedDeviceService();
    private final RecoveryService recoveryService = new DefaultRecoveryService();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        return 500;
    }

    /**
     * FlowContext 에서 stateConfig 까지 전달받기 때문에,
     * 여기에만 MfaAuthenticationFilter 등록 로직을 넣으면 됩니다.
     */
    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> stepConfigs, StateConfig stateConfig) throws Exception {

        AuthenticationManager authManager =
                http.getSharedObject(AuthenticationManager.class);
        var successHandler =
                http.getSharedObject(org.springframework.security.web.authentication.AuthenticationSuccessHandler.class);
        var failureHandler =
                http.getSharedObject(org.springframework.security.web.authentication.AuthenticationFailureHandler.class);

        // MultiFactorManager 생성
        MultiFactorManager mfaManager = new MultiFactorManager(
                // FeatureRegistry 에서는 이 Feature 자체를 관리하므로 registry.getFlow("mfa") 호출 가능
                http.getSharedObject(FeatureRegistry.class),
                auditPublisher,
                authManager,
                riskEngine,
                trustedDeviceService,
                recoveryService
        );

        // stateConfig 에 따라 적절한 참조 필터 지정
        Class<? extends Filter> referenceFilter = switch (stateConfig.state()) {
            case "session" -> UsernamePasswordAuthenticationFilter.class;
            case "jwt"     -> ExceptionTranslationFilter.class;
            default        -> UsernamePasswordAuthenticationFilter.class;
        };

        // 마지막으로 MfaAuthenticationFilter 등록
        MfaAuthenticationFilter mfaFilter = new MfaAuthenticationFilter(
                MFA_LOGIN_URL,
                mfaManager,
                successHandler,
                failureHandler,
                authManager
        );
        http.addFilterAfter(mfaFilter, referenceFilter);
    }
}
