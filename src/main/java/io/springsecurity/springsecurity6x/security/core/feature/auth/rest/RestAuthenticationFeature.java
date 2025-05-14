package io.springsecurity.springsecurity6x.security.core.feature.auth.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.handler.MfaStepSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.TokenIssuingSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.List;
import java.util.Map;
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
                .filter(s -> AuthType.REST.name().equalsIgnoreCase(s.getType()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Form step config missing"));

        RestOptions opts = (RestOptions) myStep.getOptions().get("_options");
        int idx = steps.indexOf(myStep);
        boolean last = idx == steps.size() - 1;
        Supplier<TokenService> tokenSupplier = () -> http.getSharedObject(TokenService.class);

        // 기존 핸들러
        AuthenticationSuccessHandler orig = opts.getSuccessHandler() != null
                ? opts.getSuccessHandler()
                : (req,res,auth) -> {
            res.setStatus(200);
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(res.getWriter(), Map.of("message","인증 성공"));
        };

        // 단계별 핸들러
        AuthenticationSuccessHandler handler = last
                ? MfaStepSuccessHandler.forTokenStep(tokenSupplier, orig)
                : MfaStepSuccessHandler.forAuthStep(steps, idx);


        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest.loginProcessingUrl(opts.getLoginProcessingUrl())
                .successHandler(handler);
            if (opts.getFailureHandler() != null) rest.failureHandler(opts.getFailureHandler());
            if (opts.getSecurityContextRepository() != null)
                rest.securityContextRepository(opts.getSecurityContextRepository());

        });

        for (Customizer<HttpSecurity> customizer : opts.getRawHttpCustomizers()) {
            Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
        }
    }
}

