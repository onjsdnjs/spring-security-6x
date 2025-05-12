package io.springsecurity.springsecurity6x.security.core.feature.auth.ott;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.TokenIssuingSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;

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
        AuthenticationStepConfig myStep = steps.stream()
                .filter(s -> AuthType.OTT.name().equalsIgnoreCase(s.type()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Form step config missing"));

        OttOptions opts = (OttOptions) myStep.options().get("_options");
        OneTimeTokenGenerationSuccessHandler origSuccess = opts.getTokenGenerationSuccessHandler() != null
                ? opts.getTokenGenerationSuccessHandler()
                : (request, response, oneTimeToken) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            try {
                new ObjectMapper().writeValue(response.getWriter(), "인증에 성공 했습니다." + oneTimeToken.getTokenValue());
            } catch (IOException e) {
                throw new RuntimeException("JSON 응답 실패", e);
            }
        };

        boolean isLastStep = steps.indexOf(myStep) == steps.size() - 1;

        OneTimeTokenGenerationSuccessHandler successHandler;
        if (isLastStep) {
            Supplier<TokenService> tokenSvcSupplier = () ->
                    http.getSharedObject(TokenService.class);

            successHandler = new TokenIssuingSuccessHandler(tokenSvcSupplier, origSuccess);
        } else {
            successHandler = origSuccess;
        }

        // one-time-token 로그인 DSL 적용
        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getTokenService())
                    .tokenGenerationSuccessHandler(successHandler);
        });
    }
}

