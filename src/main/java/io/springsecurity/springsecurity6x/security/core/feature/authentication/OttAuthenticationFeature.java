package io.springsecurity.springsecurity6x.security.core.feature.authentication;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

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

    @Override
    public String getId() {
        return "ott";
    }

    @Override
    public int getOrder() {
        return 300;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }
        AuthenticationStepConfig step = steps.getFirst();
        Object optsObj = step.options().get("_options");
        if (!(optsObj instanceof OttOptions)) {
            throw new IllegalStateException("Expected OttOptions in step options");
        }
        OttOptions opts = (OttOptions) optsObj;

        // URL 매처 설정
        if (opts.getMatchers() != null && !opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        }

        // one-time-token 로그인 DSL 적용
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getTokenService());

            if (opts.getTokenGenerationSuccessHandler() != null) {
                ott.tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler());
            }
        });
    }
}

