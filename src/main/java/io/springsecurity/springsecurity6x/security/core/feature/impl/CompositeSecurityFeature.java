package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * 여러 AuthenticationFeature 단계와 StateFeature를 묶어
 * SecurityFilterChain으로 생성 및 등록하는 SecurityFeature 구현체입니다.
 */
public class CompositeSecurityFeature implements SecurityFeature {

    private final String id;
    private final Consumer<HttpSecurity> globalCustomizer;
    private final StateFeature stateFeature;
    private final List<AuthenticationFeature> steps;

    public CompositeSecurityFeature(
            String id,
            Consumer<HttpSecurity> globalCustomizer,
            StateFeature stateFeature,
            List<AuthenticationFeature> steps
    ) {
        this.id = id;
        this.globalCustomizer = globalCustomizer;
        this.stateFeature = stateFeature;
        this.steps = steps;
    }

    @Override
    public void configure(PlatformContext ctx) throws Exception {
        // 1) HttpSecurity 인스턴스 가져오기 (스프링이 주입한 빌더)
        HttpSecurity http = ctx.getHttp();

        // 2) 글로벌 설정 적용
        if (globalCustomizer != null) {
            globalCustomizer.accept(http);
        }

        // 3) 상태 설정 적용 (session, jwt, oauth2 등)
        stateFeature.apply(http, ctx);

        // 4) 각 인증 단계 설정 적용
        List<AuthenticationStepConfig> allSteps = ctx.getAuthConfigs();
        for (AuthenticationFeature feature : steps) {
            // 해당 feature 타입에 맞는 step configs 필터링
            List<AuthenticationStepConfig> configs = allSteps.stream()
                    .filter(c -> feature.getId().equals(c.getType()))
                    .collect(Collectors.toList());
            // DSL에서 공유된 StateConfig 가져오기
            StateConfig stateConfig = ctx.getShared(StateConfig.class);
            feature.apply(http, configs, stateConfig);
        }

        // 5) SecurityFilterChain 생성 및 등록
        SecurityFilterChain chain = http.build();
        ctx.registerChain(id, chain);
    }
}


