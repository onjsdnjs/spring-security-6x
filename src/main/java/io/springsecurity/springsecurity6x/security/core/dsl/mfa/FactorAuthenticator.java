package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 각 스텝의 HTTP 요청을 Spring Security용 Authentication 토큰으로 변환하는 전략.
 */
public interface FactorAuthenticator {
    /**
     * @param request  MFA 엔드포인트로 들어온 원본 HTTP 요청
     * @param step     DSL로 설정된 이 스텝의 파라미터(loginUrl, tokenParam 등)
     * @return         UsernamePasswordAuthenticationToken, OneTimeTokenAuthenticationToken, WebAuthnAuthenticationToken 등
     * @throws AuthenticationException 변환 단계에서 곧바로 실패 처리할 경우
     */
    Authentication convert(HttpServletRequest request,
                           AuthenticationStepConfig step)
            throws AuthenticationException;
}