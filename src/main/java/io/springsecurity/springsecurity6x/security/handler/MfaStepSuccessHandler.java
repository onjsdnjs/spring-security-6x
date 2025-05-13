package io.springsecurity.springsecurity6x.security.handler;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.List;
import java.util.function.Supplier;

/**
 * MFA 흐름의 각 스텝별 SuccessHandler를 제공하는 유틸리티
 */
public class MfaStepSuccessHandler {
    /**
     * 인증 단계 중간(REST, PASSKEY)의 인증 성공 시, 다음 스텝으로 Redirect
     */
    public static AuthenticationSuccessHandler forAuthStep(
            List<AuthenticationStepConfig> steps,
            int currentIndex) {
        String nextUrl = steps.get(currentIndex + 1).loginProcessingUrl();
        return new SimpleRedirectSuccessHandler(nextUrl);
    }

    /**
     * OTT 단계 중간의 OneTimeToken 성공 시, 다음 스텝으로 Redirect
     */
    public static OneTimeTokenGenerationSuccessHandler forOttStep(
            List<AuthenticationStepConfig> steps,
            int currentIndex) {
        String nextUrl = steps.get(currentIndex + 1).loginProcessingUrl();
        return new OneTimeRedirectSuccessHandler(nextUrl);
    }

    /**
     * 최종 단계(Authentication): TokenIssuingSuccessHandler를 사용
     */
    public static AuthenticationSuccessHandler forTokenStep(
            Supplier<TokenService> tokenSupplier,
            AuthenticationSuccessHandler delegate) {
        return new TokenIssuingSuccessHandler(tokenSupplier, delegate);
    }

    /**
     * 최종 단계(OTT): TokenIssuingSuccessHandler를 사용
     */
    public static OneTimeTokenGenerationSuccessHandler forTokenStep(
            Supplier<TokenService> tokenSupplier,
            OneTimeTokenGenerationSuccessHandler delegate) {
        return new TokenIssuingSuccessHandler(tokenSupplier, delegate);
    }
}
