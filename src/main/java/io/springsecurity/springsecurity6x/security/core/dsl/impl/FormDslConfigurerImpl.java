package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl extends AbstractDslConfigurer<FormDslConfigurerImpl> implements FormDslConfigurer {

    private String[] matchers;
    private String loginPage;
    private String loginProcessingUrl;

    @Override
    public FormDslConfigurer matchers(String... patterns) {
        this.matchers = patterns;
        return this;
    }

    @Override
    public FormDslConfigurer loginPage(String url) {
        this.loginPage = url;
        return this;
    }

    @Override
    public FormDslConfigurer loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    /**
     * 이 플로우를 HttpSecurity에 적용할 ThrowingConsumer를 생성합니다.
     */
    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> {
            applyCommonWithMatcher(http, matchers);
        };
    }

    /**
     * DSL 설정값을 AuthenticationStepConfig로 변환합니다.
     */
    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("form");
        if (matchers != null && matchers.length > 0) {
            step.setMatchers(matchers);
        }
        if (loginPage != null) {
            step.getOptions().put("loginPage", loginPage);
        }
        if (loginProcessingUrl != null) {
            step.getOptions().put("loginProcessingUrl", loginProcessingUrl);
        }
        return step;
    }
}

