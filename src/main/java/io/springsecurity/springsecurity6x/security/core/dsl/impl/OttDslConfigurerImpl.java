package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

/**
 * OTT(One-Time Token) 로그인 DSL 구현체
 */
public class OttDslConfigurerImpl extends AbstractDslConfigurer<OttDslConfigurerImpl> implements OttDslConfigurer {

    private String[] matchers;
    private String loginProcessingUrl;

    @Override
    public OttDslConfigurer matchers(String... patterns) {
        this.matchers = patterns;
        return this;
    }

    @Override
    public OttDslConfigurer loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> applyCommonWithMatcher(http, matchers);
    }
    /**
     * DSL 설정값을 AuthenticationStepConfig로 변환합니다.
     */
    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("ott");
        if (matchers != null && matchers.length > 0) {
            step.setMatchers(matchers);
        }
        if (loginProcessingUrl != null) {
            step.getOptions().put("loginProcessingUrl", loginProcessingUrl);
        }
        return step;
    }
}
