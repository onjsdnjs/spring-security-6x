package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;

public class PrimaryAuthDslConfigurerImpl implements PrimaryAuthDslConfigurer {

    private Customizer<FormDslConfigurer> formLoginCustomizer;
    private Customizer<RestDslConfigurer> restLoginCustomizer;

    public PrimaryAuthDslConfigurerImpl() { }

    @Override
    public PrimaryAuthDslConfigurer formLogin(Customizer<FormDslConfigurer> formLoginCustomizer) {
        this.formLoginCustomizer = formLoginCustomizer;
        this.restLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthDslConfigurer restLogin(Customizer<RestDslConfigurer> restLoginCustomizer) {
        this.restLoginCustomizer = restLoginCustomizer;
        this.formLoginCustomizer = null;
        return this;
    }

    @Override
    public PrimaryAuthenticationOptions buildOptions() {
        PrimaryAuthenticationOptions.Builder optionsBuilder = PrimaryAuthenticationOptions.builder();
        String determinedLoginProcessingUrl = null;

        if (formLoginCustomizer != null) {
            FormDslOptionsBuilderConfigurer formDslBuilder = new FormDslOptionsBuilderConfigurer();
            formLoginCustomizer.customize(formDslBuilder);
            FormOptions builtFormOptions = formDslBuilder.buildConcreteOptions();
            optionsBuilder.formOptions(builtFormOptions);
            determinedLoginProcessingUrl = builtFormOptions.getLoginProcessingUrl();
        } else if (restLoginCustomizer != null) {
            RestDslOptionsBuilderConfigurer restDslBuilder = new RestDslOptionsBuilderConfigurer();
            restLoginCustomizer.customize(restDslBuilder);
            RestOptions builtRestOptions = restDslBuilder.buildConcreteOptions();
            optionsBuilder.restOptions(builtRestOptions);
            determinedLoginProcessingUrl = builtRestOptions.getLoginProcessingUrl();
        } else {
            throw new DslConfigurationException("Either formLogin or restLogin must be configured for primary authentication in MFA.");
        }

        Assert.hasText(determinedLoginProcessingUrl,
                "loginProcessingUrl could not be determined from FormLogin or RestLogin configuration for MFA primary authentication.");
        optionsBuilder.loginProcessingUrl(determinedLoginProcessingUrl);

        return optionsBuilder.build();
    }
}