package io.springsecurity.springsecurity6x.security.handler;


import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.List;
import java.util.function.Supplier;

/**
 * MFA 단계별 성공 핸들러를 제공하는 클래스
 * - 중간 단계에서는 다음 단계의 targetUrl로 Redirect
 * - 최종 단계에서는 Token 발급 핸들러 사용
 */
public class MfaStepSuccessHandler {

    /**
     * REST/Form/Passkey 중간 단계: 다음 스텝의 targetUrl로 Redirect
     */
    public static AuthenticationSuccessHandler forAuthStep(List<AuthenticationStepConfig> steps, int currentIndex) {
        AuthenticationStepConfig nextStep = steps.get(currentIndex + 1);
        Object opts = nextStep.getOptions().get("_options");
        String targetUrl = extractTargetUrl(opts);
        return new SimpleRedirectSuccessHandler(targetUrl);
    }

    /**
     * OTT 중간 단계: OneTimeTokenGenerationSuccessHandler로 Redirect
     */
    public static OneTimeTokenGenerationSuccessHandler forOttStep(List<AuthenticationStepConfig> steps, int currentIndex) {
        AuthenticationStepConfig nextStep = steps.get(currentIndex + 1);
        Object opts = nextStep.getOptions().get("_options");
        String targetUrl = extractTargetUrl(opts);
        return new OneTimeRedirectSuccessHandler(targetUrl);
    }

    /**
     * 최종 인증 단계: TokenIssuingSuccessHandler를 통해 토큰 발급
     */
    public static AuthenticationSuccessHandler forTokenStep(Supplier<TokenService> tokenSupplier,
                                                            AuthenticationSuccessHandler delegate) {
        return new CustomTokenIssuingSuccessHandler(tokenSupplier, delegate);
    }

    /**
     * 최종 OTT 단계: TokenIssuingSuccessHandler를 통해 토큰 발급
     */
    public static OneTimeTokenGenerationSuccessHandler forTokenStep(Supplier<TokenService> tokenSupplier,
                                                                    OneTimeTokenGenerationSuccessHandler delegate) {
        return new CustomTokenIssuingSuccessHandler(tokenSupplier, delegate);
    }

    /**
     * Options 객체에서 targetUrl 추출
     */
    private static String extractTargetUrl(Object opts) {
        return "/login/mfa/list";
    }
}

