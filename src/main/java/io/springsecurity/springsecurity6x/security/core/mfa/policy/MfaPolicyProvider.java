package io.springsecurity.springsecurity6x.security.core.mfa.policy;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;

/**
 * 런타임에 현재 사용자에 적용될 MFA 정책을 제공하는 인터페이스.
 * 구현체는 DB, 설정 파일, 외부 정책 서버 등에서 정책 정보를 조회합니다.
 */
public interface MfaPolicyProvider {
    boolean isMfaRequired(Authentication primaryAuthentication, FactorContext context);

    Set<AuthType> getEnabledFactors(Authentication primaryAuthentication, FactorContext context);

    Optional<AuthType> getAutoAttemptFactor(Authentication primaryAuthentication, FactorContext context);

    String getMfaFactorSelectionUrl(Authentication primaryAuthentication, FactorContext context);

    int getMaxAttemptsForFactor(AuthType factorType, FactorContext context); // RetryPolicy 대신 int

    boolean isDeviceTrustEnabled(Authentication primaryAuthentication, FactorContext context);
}