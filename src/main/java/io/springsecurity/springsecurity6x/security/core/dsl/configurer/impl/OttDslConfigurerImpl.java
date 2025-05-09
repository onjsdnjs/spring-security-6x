/*
package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.option.OttOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

*/
/**
 * OTT(One-Time Token) 로그인 DSL 구현체
 *//*

public class OttDslConfigurerImpl extends AbstractDslConfigurer<OttOptions.Builder, OttDslConfigurer> implements OttDslConfigurer {

    public OttDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, OttOptions.builder());
    }

    @Override
    public OttDslConfigurer matchers(String... patterns) {
        options.matchers(List.of(patterns));
        return this;
    }

    @Override
    public OttDslConfigurer loginProcessingUrl(String url) {
        options.loginProcessingUrl(url);
        return this;
    }

    @Override
    public OttDslConfigurer defaultSubmitPageUrl(String url) {
        options.defaultSubmitPageUrl(url);
        return this;
    }

    @Override
    public OttDslConfigurer tokenGeneratingUrl(String url) {
        options.tokenGeneratingUrl(url);
        return this;
    }

    @Override
    public OttDslConfigurer showDefaultSubmitPage(boolean show) {
        options.showDefaultSubmitPage(show);
        return this;
    }

    @Override
    public OttDslConfigurer tokenService(org.springframework.security.authentication.ott.OneTimeTokenService service) {
        options.tokenService(service);
        return this;
    }

    @Override
    public OttDslConfigurer tokenGenerationSuccessHandler(org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler handler) {
        options.tokenGenerationSuccessHandler(handler);
        return this;
    }

    */
/**
     * AuthenticationStepConfig 생성 및 옵션 저장
     *//*

    public AuthenticationStepConfig toConfig() {
        OttOptions opts = options.build();
        AuthenticationStepConfig step = getStepConfig();
        step.setType("ott");
        if (!opts.getMatchers().isEmpty()) {
            step.setMatchers(opts.getMatchers().toArray(new String[0]));
        }
        step.getOptions().put("_options", opts);
        return step;
    }

    @Override
    public FormDslConfigurer raw(Customizer<FormLoginConfigurer<HttpSecurity>> customizer) {
        return null;
    }
}
*/
