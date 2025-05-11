package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

/**
 * DSL 구현체: OTT 인증 스텝 설정
 */
public class OttDslConfigurerImpl
        extends AbstractDslConfigurer<OttOptions.Builder, OttDslConfigurer>
        implements OttDslConfigurer {

    private int order = 0;

    public OttDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, OttOptions.builder());
    }

    @Override
    public OttDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public int order() {
        return order;
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
    public OttDslConfigurer tokenService(OneTimeTokenService service) {
        options.tokenService(service);
        return this;
    }

    @Override
    public OttDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        options.tokenGenerationSuccessHandler(handler);
        return this;
    }

    /**
     * 원시 HttpSecurity 커스터마이저를 안전하게 적용
     */
    public OttDslConfigurer originRaw(Customizer<HttpSecurity> customizer) {
        options.rawHttp(customizer);
        return this;
    }

    @Override
    public OttDslConfigurer raw(SafeHttpCustomizer safe) {
        return originRaw(wrapSafe(safe));
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                // 내부 예외는 로깅 또는 무시
                System.err.println("OTT raw customizer exception: " + e.getMessage());
            }
        };
    }

    /**
     * DSL 설정을 HttpSecurity에 적용하는 Consumer 반환
     */
    @Override
    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> {
            // 1) 공통 옵션 적용 (securityMatcher 등)
            OttOptions optsBuilt = options.build();
            try {
                optsBuilt.applyCommon(http);
            } catch (Exception e) {
                // 예외는 무시 또는 로깅
            }

            // 2) One-Time Token 로그인 설정
            http.oneTimeTokenLogin(ott -> {
                // rawOneTimeTokenCustomizer 가 설정되어 있으면 적용
                Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> rawOtt = optsBuilt.getRawOttLogin();
                if (rawOtt != null) {
                    try {
                        rawOtt.customize(ott);
                    } catch (Exception ex) {
                        System.err.println("OTT login customizer exception: " + ex.getMessage());
                    }
                }
            });
        };
    }

    /**
     * AuthenticationStepConfig 생성 및 옵션 저장
     */
    public AuthenticationStepConfig toConfig() {
        OttOptions optsBuilt = options.build();
        AuthenticationStepConfig step = stepConfig();
        step.type("form");
        step.options().put("_options", optsBuilt);
        return step;
    }
}

