package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.PasskeyAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Set;

@Slf4j
public final class PasskeyDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        extends AbstractOptionsBuilderConfigurer<PasskeyDslConfigurerImpl<H>, H, PasskeyOptions, PasskeyOptions.Builder, PasskeyDslConfigurer>
        implements PasskeyDslConfigurer {

    public PasskeyDslConfigurerImpl(/* ApplicationContext context */) {
        super(PasskeyOptions.builder());
    }

    @Override
    public PasskeyDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public PasskeyDslConfigurer loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return self();
    }

    @Override
    public PasskeyDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        getOptionsBuilder().successHandler(handler);
        return self();
    }

    @Override
    public PasskeyDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        getOptionsBuilder().failureHandler(handler);
        return self();
    }

    @Override
    public PasskeyDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
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
    public PasskeyDslConfigurer asep(Customizer<PasskeyAsepAttributes> passkeyAsepAttributesCustomizer) throws Exception {
        H builder = getBuilder();
        PasskeyAsepAttributes attributes = builder.getSharedObject(PasskeyAsepAttributes.class);
        if (attributes == null) {
            attributes = new PasskeyAsepAttributes();
        }
        if (passkeyAsepAttributesCustomizer != null) {
            passkeyAsepAttributesCustomizer.customize(attributes);
        }
        builder.setSharedObject(PasskeyAsepAttributes.class, attributes);
        log.debug("ASEP: PasskeyAsepAttributes stored/updated in sharedObjects for builder hash: {}", System.identityHashCode(builder));
        return self();
    }

    @Override
    protected PasskeyDslConfigurerImpl<H> self() {
        return this;
    }

    @Override
    public void configure(H builder) throws Exception {

    }
}
