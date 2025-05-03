package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * Form 기반 로그인 전략을 적용하는 Feature 구현체
 */
public class FormAuthenticationFeature implements AuthenticationFeature {
    @Override
    public String getId() {
        return "form";
    }

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps.isEmpty()) return;
        // 프록시로 캡처된 메서드 호출 재연
        List<MethodInvocation> invs =
                (List<MethodInvocation>) steps.getFirst().getOptions().get("_invocations");

        http.formLogin(form -> {
            for (MethodInvocation inv : invs) {
                try {
                    inv.proceed();  // MethodInvocation.proceed()가 form 인스턴스에 호출됨
                } catch (Throwable e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }
}

