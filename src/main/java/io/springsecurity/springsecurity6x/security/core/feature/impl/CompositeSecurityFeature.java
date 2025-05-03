package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.function.Consumer;

/**
 * 여러 AuthenticationFeature 단계를 묶어 하나의 SecurityFilterChain으로 등록하는 구현체
 */
public class CompositeSecurityFeature implements SecurityFeature {

    private final String id;
    private final Consumer<HttpSecurity> globalCustomizer;
    private final StateFeature state;
    private final List<AuthenticationFeature> steps;

    public CompositeSecurityFeature(
            String id,
            Consumer<HttpSecurity> globalCustomizer,
            StateFeature state,
            List<AuthenticationFeature> steps
    ) {
        this.id = id;
        this.globalCustomizer = globalCustomizer;
        this.state = state;
        this.steps = steps;
    }

    @Override
    public void configure(PlatformContext ctx) throws Exception {
        // 1) HttpSecurity 빌더 획득
        HttpSecurity http = ctx.getHttp(id);

        // 2) 글로벌 설정 (예: CSRF, CORS 등)
        if (globalCustomizer != null) {
            globalCustomizer.accept(http);
        }

        // 3) 상태 설정 (session, jwt, oauth2 등)
        state.apply(http, ctx);

        // 4) 각 인증단계(Feature) 적용
        for (AuthenticationFeature feature : steps) {
            feature.apply(http, ctx);
        }

        // 5) 최종 체인 빌드 및 등록
        SecurityFilterChain chain = http.build();
        ctx.registerChain(id, chain);
    }
}

