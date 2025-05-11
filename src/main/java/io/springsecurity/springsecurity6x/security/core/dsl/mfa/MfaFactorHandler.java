package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.AuthenticationManager;

/**
 * 각 MFA 스텝별 인증을 담당하는 핸들러.
 * <p>
 * - 기존 Spring Security 의 AuthenticationManager 로 인증을 위임하고,
 * 성공·실패 처리는 AuthenticationException 으로 일관성 있게 처리합니다.
 * - before/after 훅은 default 메서드로 제공해, 필요한 경우만 오버라이드하도록 설계했습니다.
 */
public interface MfaFactorHandler {

    /**
     * 스텝 시작 전 사전 작업(파라미터 검증 등).
     */
    default void beforeAuthentication(FactorContext ctx,
                                      AuthenticationStepConfig config) throws Exception { }

    /**
     * 실제 인증: 반드시 authManager.authenticate() 호출.
     *
     * @return 성공한 Authentication
     * @throws AuthenticationException 실패 시 던집니다.
     */
    Authentication authenticate(FactorContext ctx,
                                AuthenticationStepConfig config,
                                AuthenticationManager authManager) throws AuthenticationException;

    /**
     * 인증 성공 후 후속 작업.
     */
    default void afterSuccess(FactorContext ctx,
                              AuthenticationStepConfig config,
                              Authentication authentication) throws Exception { }

    /**
     * 인증 실패 시 후속 작업.
     */
    default void afterFailure(FactorContext ctx,
                              AuthenticationStepConfig config,
                              AuthenticationException exception) throws Exception { }

    /**
     * 스텝 종료 시 공통 정리 작업.
     */
    default void afterFinally(FactorContext ctx,
                              AuthenticationStepConfig config) throws Exception { }
}



