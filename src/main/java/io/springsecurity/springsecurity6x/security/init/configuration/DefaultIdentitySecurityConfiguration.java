package io.springsecurity.springsecurity6x.security.init.configuration;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfigFactory;
import io.springsecurity.springsecurity6x.security.build.option.FormOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import io.springsecurity.springsecurity6x.security.init.IdentityConfig;
import io.springsecurity.springsecurity6x.security.init.IdentityDslRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;

import java.util.List;

@Configuration
@ConditionalOnMissingBean(IdentityDslRegistry.class)
public class DefaultIdentitySecurityConfiguration {

    @Bean
    public IdentityDslRegistry identityDslRegistry() {
        IdentityConfig config = new IdentityConfig();

        FormOptions options = new FormOptions();
        options.loginPage("/login");
        options.matchers(List.of("/login", "/api/**"));

        config.add(AuthenticationConfigFactory.create(AuthType.FORM, options, StateType.JWT, Customizer.withDefaults()));

        return new IdentityDslRegistry();
    }
}