package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.PasskeyAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Set;

@Slf4j
public final class PasskeyDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyDslConfigurerImpl, PasskeyOptions, PasskeyOptions.Builder, PasskeyDslConfigurer>
        implements PasskeyDslConfigurer {

    public PasskeyDslConfigurerImpl() {
        super(PasskeyOptions.builder());
    }

    @Override
    public PasskeyDslConfigurer order(int order) {
        getOptionsBuilder().order(order); // AuthenticationProcessingOptions.Builder의 order 사용
        return self();
    }

    @Override
    public PasskeyDslConfigurer loginProcessingUrl(String url) {
        super.loginProcessingUrl(url); // AbstractOptionsBuilderConfigurer의 메서드 호출
        return self();
    }

    @Override
    public PasskeyDslConfigurer successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        super.successHandler(successHandler);
        return self();
    }

    @Override
    public PasskeyDslConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        super.failureHandler(failureHandler);
        return self();
    }

    @Override
    public PasskeyDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        super.securityContextRepository(repository);
        return self();
    }

    // --- PasskeyDslConfigurer specific methods ---
    @Override
    public PasskeyDslConfigurer assertionOptionsEndpoint(String url) {
        getOptionsBuilder().assertionOptionsEndpoint(url);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpName(String rpName) {
        getOptionsBuilder().rpName(rpName);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpId(String rpId) {
        getOptionsBuilder().rpId(rpId);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(List<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(Set<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer asep(Customizer<PasskeyAsepAttributes> passkeyAsepAttributesCustomizer){

        PasskeyAsepAttributes attributes = new PasskeyAsepAttributes();
        if (passkeyAsepAttributesCustomizer != null) {
            passkeyAsepAttributesCustomizer.customize(attributes);
        }
        // builder.setSharedObject(PasskeyAsepAttributes.class, attributes); // 제거
        getOptionsBuilder().asepAttributes(attributes); // PasskeyOptions.Builder에 저장
        log.debug("ASEP: PasskeyAsepAttributes configured and will be stored within PasskeyOptions.");
        return self();
    }

    @Override
    protected PasskeyDslConfigurerImpl self() {
        return this;
    }

    // configure(H builder) 메서드는 AbstractOptionsBuilderConfigurer에서 제거되었으므로 여기서도 불필요
}
