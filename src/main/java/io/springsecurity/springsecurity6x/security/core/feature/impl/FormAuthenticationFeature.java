package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

import java.util.List;
import java.util.function.Consumer;

/**
 * Form 기반 로그인 전략을 적용하는 Feature 구현체
 */
public class FormAuthenticationFeature implements AuthenticationFeature {

    @Override public String getId()  { return "form"; }
    @Override public int getOrder()  { return 100; }

    @SuppressWarnings("unchecked")
    @Override
    public void apply(HttpSecurity http,
                      List<AuthenticationStepConfig> steps,
                      StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }
        // 첫 번째 StepConfig에서 customizer 리스트를 꺼내고
        var opts = steps.get(0).getOptions();
        List<Customizer<FormLoginConfigurer<HttpSecurity>>> customizers =
                (List<Customizer<FormLoginConfigurer<HttpSecurity>>>) opts.get("_loginCustomizers");

        if (customizers != null && !customizers.isEmpty()) {
            // HttpSecurity.formLogin(...) 블록 안에서 한 번만 실행합니다.
            http.formLogin(form -> {
                for (var c : customizers) {
                    c.customize(form);
                }
            });
        }
    }
}
