package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * REST 로그인 DSL 구현체
 */
public class RestDslConfigurerImpl implements RestDslConfigurer {

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

    /**
     * DSL 설정값을 AuthenticationStepConfig로 변환합니다.
     */
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

