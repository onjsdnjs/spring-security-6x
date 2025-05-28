package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.AbstractMfaAuthenticationSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationFailureHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

@Slf4j
public class OttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    @Override
    public String getId() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 300; // 다른 인증 방식과의 순서
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler  successHandler, // 이 메소드는 Ott에서는 사용 안 함
                                         PlatformAuthenticationFailureHandler  failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "OttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    @Override
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                            OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                            PlatformAuthenticationSuccessHandler successHandler,// 코드 생성 성공 핸들러
                                            PlatformAuthenticationFailureHandler failureHandler) throws Exception { // 코드 검증 실패 핸들러

        String getRequestUrlForForwardingFilter = opts.getLoginProcessingUrl(); // 예: /login/ott 또는 /login/mfa-ott
        String postProcessingUrlForAuthFilter = opts.getLoginProcessingUrl();   // 이 URL로 자동 POST

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl()) // 사용자가 직접 코드 입력하는 페이지 (선택적)
                    .loginProcessingUrl(postProcessingUrlForAuthFilter) // 코드 "검증"을 처리할 POST URL
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl()) // 코드 "생성/발송"을 처리할 POST URL (GenerateOneTimeTokenFilter가 처리)
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            tokenGenerationSuccessHandler:opts.getTokenGenerationSuccessHandler())
                    .successHandler(successHandler)
                    .failureHandler(failureHandler);
        });
        log.info("OttAuthenticationAdapter: Configured OttForwardingFilter for GET {} and OneTimeTokenLogin for POST {} (Generation at {})",
                getRequestUrlForForwardingFilter, postProcessingUrlForAuthFilter, opts.getTokenGeneratingUrl());
    }
}
