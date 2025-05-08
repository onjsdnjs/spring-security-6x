package io.springsecurity.springsecurity6x.security.core.feature.auth.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.TokenIssuingSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * REST 기반 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 *
 * - DSL로 설정된 RestOptions(matchers, loginProcessingUrl, defaultSuccessUrl, failureUrl 등)을
 *   HttpSecurity.with(RestAuthenticationConfigurer) 블록 안에서 구성합니다.
 * - 성공/실패 핸들러와 SecurityContextRepository는 옵션이 없으면 기본 핸들러(provider를 통해 주입된)를 사용합니다.
 */
public class RestAuthenticationFeature implements AuthenticationFeature {

    @Override
    public String getId() {
        return "rest";
    }

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }
        AuthenticationStepConfig myStep = steps.stream()
                .filter(s -> AuthType.REST.name().equalsIgnoreCase(s.type()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Form step config missing"));

        RestOptions opts = (RestOptions) myStep.options().get("_options");
        AuthenticationSuccessHandler origSuccess = opts.getSuccessHandler() != null
                ? opts.getSuccessHandler()
                : (request, response, authentication) -> {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
                    try {
                        new ObjectMapper().writeValue(response.getWriter(), "인증에 성공 했습니다.");
                    } catch (IOException e) {
                        throw new RuntimeException("JSON 응답 실패", e);
                    }
                };

        boolean isLastStep = steps.indexOf(myStep) == steps.size() - 1;

        AuthenticationSuccessHandler successHandler;
        if (isLastStep) {
            Supplier<TokenService> tokenSvcSupplier = () ->
                    http.getSharedObject(TokenService.class);

            successHandler = new TokenIssuingSuccessHandler(tokenSvcSupplier, origSuccess);
        } else {
            successHandler = origSuccess;
        }


        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest
                .loginProcessingUrl(opts.getLoginProcessingUrl());

            rest.successHandler(opts.getSuccessHandler() == null ? successHandler : opts.getSuccessHandler());
            if (opts.getFailureHandler() != null) rest.failureHandler(opts.getFailureHandler());
            if (opts.getSecurityContextRepository() != null) rest.securityContextRepository(opts.getSecurityContextRepository());

        });

        List<Customizer<HttpSecurity>> httpCustomizers = opts.rawHttpCustomizers();
        for (Customizer<HttpSecurity> customizer : httpCustomizers) {
            Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
        }
    }
}

