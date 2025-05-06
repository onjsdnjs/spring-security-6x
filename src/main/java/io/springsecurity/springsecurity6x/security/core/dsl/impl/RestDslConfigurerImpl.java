/*
package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

*/
/**
 * REST 로그인 DSL 구현체
 *//*

public class RestDslConfigurerImpl extends AbstractDslConfigurer<RestDslConfigurerImpl> implements RestDslConfigurer {

    private String[] matchers;
    private String loginProcessingUrl;

    @Override
    public RestDslConfigurer matchers(String... patterns) {
        this.matchers = patterns;
        return this;
    }

    @Override
    public RestDslConfigurer loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> applyCommonWithMatcher(http, matchers);
    }

    */
/**
     * DSL 설정값을 AuthenticationStepConfig로 변환합니다.
     *//*

    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("rest");
        if (matchers != null && matchers.length > 0) {
            step.setMatchers(matchers);
        }
        if (loginProcessingUrl != null) {
            step.getOptions().put("loginProcessingUrl", loginProcessingUrl);
        }
        return step;
    }
}

*/
