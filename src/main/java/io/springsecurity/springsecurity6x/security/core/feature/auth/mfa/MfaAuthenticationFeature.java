package io.springsecurity.springsecurity6x.security.core.feature.auth.mfa;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.DefaultRiskEngine;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.filter.MfaAuthenticationFilter;
import jakarta.servlet.Filter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;
import java.util.Objects;

/**
 * MFA 전용 AuthenticationFeature 구현.
 * - AuthenticationManager, Success/FailureHandler 의존을 제거하고
 *   SecurityFilterChain 에 등록된 각 인증 필터를 직접 호출하는
 *   MultiFactorManager 기반으로 작동합니다.
 */
public class MfaAuthenticationFeature implements AuthenticationFeature {
    private static final String ID = "mfa";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        return 500;
    }

    /**
     * HttpSecurity 에 MfaAuthenticationFilter 만 등록합니다.
     * 실제 개별 인증 필터들은 SecurityPlatformInitializer 에서
     * SecurityFilterChain 으로 생성·등록되며, FeatureRegistry 에 보관됩니다.
     */
    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> stepConfigs, StateConfig stateConfig) throws Exception {

        String mfaUrl = stepConfigs.stream()
                .map(step -> (String) step.options().get("_mfa_loginUrl"))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse("/api/auth/mfa");  // 기본값


        FeatureRegistry registry = http.getSharedObject(FeatureRegistry.class);

            RiskEngine riskEngine = new DefaultRiskEngine();
            TrustedDeviceService trustedDeviceService = new DefaultTrustedDeviceService();
            RecoveryService recoveryService = new DefaultRecoveryService();
            AuditEventPublisher auditPublisher = new DefaultAuditEventPublisher();

            // stateConfig 에 따라 참조 필터 결정
            Class<? extends Filter> reference = "jwt".equals(stateConfig.state())
                    ? ExceptionTranslationFilter.class
                    : UsernamePasswordAuthenticationFilter.class;

            // 올바른 생성자 시그니처에 맞춰 인자 6개 모두 전달
            MfaAuthenticationFilter mfaFilter = new MfaAuthenticationFilter(
                    mfaUrl,
                    registry,
                    auditPublisher,
                    riskEngine,
                    trustedDeviceService,
                    recoveryService
            );

            http.addFilterAfter(mfaFilter, reference);
        }

    }
