package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.RestAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class RestDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        extends AbstractOptionsBuilderConfigurer<RestDslConfigurerImpl<H>, H, RestOptions, RestOptions.Builder, RestDslConfigurer>
        implements RestDslConfigurer {

    public RestDslConfigurerImpl(/* ApplicationContext context */) {
        super(RestOptions.builder());
    }

    @Override
    public RestDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public RestDslConfigurer loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return self();
    }

    @Override
    public RestDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        getOptionsBuilder().successHandler(handler);
        return self();
    }

    @Override
    public RestDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        getOptionsBuilder().failureHandler(handler);
        return self();
    }

    @Override
    public RestDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }
    // --- OptionsBuilderDsl 공통 메소드 구현 (disableCsrf, cors 등) ---
    // 부모 AbstractOptionsBuilderConfigurer에서 이미 구현되어 self()를 통해 RestDslConfigurerImpl<H> 반환
    // 인터페이스는 RestDslConfigurer를 반환하도록 되어 있으므로 호환됨.

    @Override
    public RestDslConfigurer asep(Customizer<RestAsepAttributes> restAsepAttributesCustomizer) throws Exception {
        H builder = getBuilder();
        RestAsepAttributes attributes = builder.getSharedObject(RestAsepAttributes.class);
        if (attributes == null) {
            attributes = new RestAsepAttributes();
        }
        if (restAsepAttributesCustomizer != null) {
            restAsepAttributesCustomizer.customize(attributes);
        }
        builder.setSharedObject(RestAsepAttributes.class, attributes);
        log.debug("ASEP: RestAsepAttributes stored/updated in sharedObjects for builder hash: {}", System.identityHashCode(builder));
        return self();
    }

    @Override
    protected RestDslConfigurerImpl<H> self() {
        return this;
    }

    @Override
    public void configure(H builder) throws Exception {
    }
}

