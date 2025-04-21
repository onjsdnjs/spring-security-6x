package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.configurer.authentication.AuthenticationEntryConfigurer;
import io.springsecurity.springsecurity6x.jwt.strategy.AuthenticationStateStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.function.Consumer;

public class IdentityConfigurer extends AbstractHttpConfigurer<IdentityConfigurer, HttpSecurity> {

    private final AuthenticationTypeConfigurer typeConfigurer = new AuthenticationTypeConfigurer();
    private final AuthenticationStateConfigurer stateConfigurer = new AuthenticationStateConfigurer();

    public IdentityConfigurer authentication(Consumer<AuthenticationTypeConfigurer> customizer) {
        customizer.accept(this.typeConfigurer);
        return this;
    }

    public IdentityConfigurer state(Consumer<AuthenticationStateConfigurer> customizer) {
        customizer.accept(this.stateConfigurer);
        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationStateStrategy strategy = stateConfigurer.buildStrategy();
        for (AuthenticationEntryConfigurer entry : typeConfigurer.getEntries()) {
            entry.setStateStrategy(strategy);
            entry.configure(http);
        }
    }
}


