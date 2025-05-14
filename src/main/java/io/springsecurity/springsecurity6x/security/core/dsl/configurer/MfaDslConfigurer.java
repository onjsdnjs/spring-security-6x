package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface MfaDslConfigurer {

    MfaDslConfigurer order(int order);

    /**
     * 1차 인증(ID/PW)을 담당하는 Configurer 설정.
     * 이 Configurer의 성공 핸들러에서 MfaContinuationHandler가 호출되어야 합니다.
     */
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);

    /**
     * 1차 인증 성공 후 호출될 핸들러를 지정합니다.
     * 이 핸들러는 사용자의 MFA 필요 여부 확인, 등록된 Factor 로드,
     * 자동 시도 Factor 결정, Factor 선택 화면 안내 등의 로직을 수행합니다.
     * MfaPolicyProvider로부터 현재 사용자의 정책을 받아 동적으로 처리합니다.
     */
    MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler);

    /**
     * 사용 가능한 MFA Factor들을 등록하고 각 Factor의 기술적 설정을 정의합니다.
     * 실제 Factor의 활성화 여부나 우선순위는 MfaPolicyProvider가 런타임에 결정합니다.
     *
     * @param factorType 등록할 Factor의 AuthType
     * @param factorConfigurer 해당 Factor 설정을 위한 Customizer
     */
    <C extends FactorDslConfigurer> MfaDslConfigurer registerFactor(AuthType factorType, Customizer<C> factorConfigurer);

    /**
     * 모든 등록된 (그리고 정책에 의해 시도된) MFA Factor 인증이 실패했을 때 호출될 핸들러입니다.
     */
    MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler);

    /**
     * 최종적으로 모든 MFA 요구사항이 충족되었을 때 호출될 성공 핸들러입니다.
     * (일반적으로 토큰 발급 핸들러)
     */
    MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler);

    /**
     * MFA 정책을 동적으로 제공하는 MfaPolicyProvider 구현체를 설정합니다.
     * 이 Provider는 DB, 설정 파일 등에서 운영 정책을 로드하여 반환합니다.
     * (필수)
     */
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);


    MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c);
    MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable); // 기본값, 실제 적용은 policyProvider 판단
    // MfaDslConfigurer defaultRecoveryFlow(Customizer<RecoveryDslConfigurer> c); // RECOVERY_CODE Factor로 통합 권장

    AuthenticationFlowConfig build();
}