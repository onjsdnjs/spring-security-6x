package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.SecurityFeature;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * 여러 AuthenticationFeature 단계와 StateFeature를 묶어
 * SecurityFilterChain으로 생성 및 등록하는 SecurityFeature 구현체입니다.
 */
public class CompositeSecurityFeature implements SecurityFeature {

    private final String id;
    private final Customizer<HttpSecurity> globalCustomizer;
    private final StateFeature stateFeature;
    private final List<AuthenticationFeature> steps;
    private final ThrowingConsumer<HttpSecurity> customizer;

    public CompositeSecurityFeature(
            String id,
            Customizer<HttpSecurity> globalCustomizer,
            StateFeature stateFeature,
            List<AuthenticationFeature> steps,
            ThrowingConsumer<HttpSecurity> customizer) {
        this.id = id;
        this.globalCustomizer = globalCustomizer;
        this.stateFeature = stateFeature;
        this.steps = steps;
        this.customizer = customizer;
    }

    @Override
    public void configure(PlatformContext ctx) throws Exception {
        // 인증 스텝별로 SecurityFilterChain 다중 생성
        List<AuthenticationStepConfig> allSteps = ctx.getAuthConfigs();
        StateConfig stateConfig = ctx.getShared(StateConfig.class);
        for (AuthenticationStepConfig stepConfig : allSteps) {
            // 매 단계마다 HttpSecurity 반환 (matchers 적용)
            HttpSecurity http = ctx.getHttp();
            if (stepConfig.getMatchers() != null) {
                http = http.securityMatcher(stepConfig.getMatchers());
            }

            // 글로벌 설정
            if (globalCustomizer != null) {
                globalCustomizer.customize(http);
            }

            // 상태 설정
            stateFeature.apply(http, ctx);

            // 해당 단계에 해당하는 AuthenticationFeature 찾기
            AuthenticationFeature feature = steps.stream()
                    .filter(f -> f.getId().equals(stepConfig.getType()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "No feature for step type " + stepConfig.getType()));

            // 단계별 설정만 전달
            feature.apply(http, List.of(stepConfig), stateConfig);

            // DSL 흐름 레벨 커스터마이저
            if (customizer != null) {
                customizer.accept(http);
            }

            // 체인 생성 및 단계 ID를 키로 등록
            SecurityFilterChain chain = http.build();
            ctx.registerChain(stepConfig.getType(), chain);
        }
    }

    public String id() {
        return id;
    }
}


