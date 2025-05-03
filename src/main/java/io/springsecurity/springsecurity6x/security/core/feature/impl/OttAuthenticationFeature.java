package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.feature.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.Objects;

/**
 * OTT(One-Time Token) 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 *
 * DSL로 설정된 OttOptions를 읽어서:
 *  - URL 매처(matchers)
 *  - 토큰 제출 페이지 URL(defaultSubmitPageUrl)
 *  - 로그인 처리 URL(loginProcessingUrl)
 *  - 토큰 생성 엔드포인트(tokenGeneratingUrl)
 *  - 토큰 서비스(tokenService)
 *  - 토큰 생성 성공 핸들러(tokenGenerationSuccessHandler)
 * 등을 설정합니다.
 */
public class OttAuthenticationFeature implements AuthenticationFeature {

    private final AuthenticationHandlers defaultHandlers;

    /**
     * @param defaultHandlers 기본 성공 핸들러 제공자
     */
    public OttAuthenticationFeature(AuthenticationHandlers defaultHandlers) {
        this.defaultHandlers = defaultHandlers;
    }

    @Override
    public String getId() {
        return "ott";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // 1) 현재 AuthenticationConfig와 OttOptions 꺼내오기
        AuthenticationConfig config = ctx.getShared(AuthenticationConfig.class);
        OttOptions opts = (OttOptions) config.options();

        // 2) 요청 매처 설정
        if (opts.getMatchers() != null && !opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        }

        // 3) one-time-token 로그인 DSL 적용
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getTokenService());

            // 4) 토큰 생성 성공 핸들러 설정 (없으면 기본 제공)
            OneTimeTokenGenerationSuccessHandler successHandler = (OneTimeTokenGenerationSuccessHandler) Objects.requireNonNullElse(
                    opts.getTokenGenerationSuccessHandler(),
                    defaultHandlers.successHandler()
            );
            ott.tokenGenerationSuccessHandler(successHandler);
        });
    }
}

