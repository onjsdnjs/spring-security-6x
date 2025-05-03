package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * Passkey(WebAuthn) 로그인 DSL 구현체
 */
public class PasskeyDslConfigurerImpl implements PasskeyDslConfigurer {

    private String[] matchers;
    private String rpName;
    private String rpId;
    private String[] allowedOrigins;

    @Override
    public PasskeyDslConfigurer matchers(String... patterns) {
        this.matchers = patterns;
        return this;
    }

    @Override
    public PasskeyDslConfigurer rpName(String name) {
        this.rpName = name;
        return this;
    }

    @Override
    public PasskeyDslConfigurer rpId(String id) {
        this.rpId = id;
        return this;
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        this.allowedOrigins = origins;
        return this;
    }

    /**
     * DSL 설정값을 AuthenticationStepConfig로 변환합니다.
     */
    public AuthenticationStepConfig toConfig() {
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("passkey");
        if (matchers != null && matchers.length > 0) {
            step.setMatchers(matchers);
        }
        if (rpName != null) {
            step.getOptions().put("rpName", rpName);
        }
        if (rpId != null) {
            step.getOptions().put("rpId", rpId);
        }
        if (allowedOrigins != null && allowedOrigins.length > 0) {
            step.getOptions().put("allowedOrigins", allowedOrigins);
        }
        return step;
    }
}
