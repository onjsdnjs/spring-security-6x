package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * OTT(One-Time Token) 로그인 DSL 구현체
 */
public class OttDslConfigurerImpl implements OttDslConfigurer {

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
