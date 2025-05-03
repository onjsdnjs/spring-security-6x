package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.aop.framework.ReflectiveMethodInvocation;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl implements FormDslConfigurer {

    private final List<Customizer<FormLoginConfigurer<HttpSecurity>>> customizers = new ArrayList<>();

    @Override
    public FormDslConfigurer login(Customizer<FormLoginConfigurer<HttpSecurity>> customizer) {
        customizers.add(customizer);
        return this;
    }

    /**
     * DSL 결과를 StepConfig에 담습니다.
     */
    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("form");
        // "_loginCustomizers" 키로 나중에 꺼내 씁니다.
        step.getOptions().put("_loginCustomizers", List.copyOf(customizers));
        return step;
    }
}


