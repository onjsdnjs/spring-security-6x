package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

import java.util.ArrayList;
import java.util.List;

/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl implements FormDslConfigurer {

    private final List<MethodInvocation> invocations = new ArrayList<>();

    @Override
    public FormDslConfigurer formLogin(Customizer<FormLoginConfigurer<HttpSecurity>> customizer) {
        ProxyFactory factory = new ProxyFactory(FormLoginConfigurer.class);
        factory.addAdvice((MethodInterceptor) invocation -> {
            // 메서드 호출 기록
            invocations.add(invocation);
            // 체이닝을 위해 자신(프록시) 반환
            return invocation.getThis();
        });
        FormLoginConfigurer<HttpSecurity> proxy = (FormLoginConfigurer<HttpSecurity>) factory.getProxy();
        // 사용자 정의 호출 실행
        customizer.customize(proxy);
        return this;
    }

    /**
     * DSL 결과를 AuthenticationStepConfig에 저장합니다.
     */
    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("form");
        step.getOptions().put("_invocations", List.copyOf(invocations));
        return step;
    }
}


