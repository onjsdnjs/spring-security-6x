package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.token.AuthorizationServerConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.token.ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.function.Consumer;

public class SecurityIntegrationConfigurer extends AbstractHttpConfigurer<SecurityIntegrationConfigurer, HttpSecurity> {

    private final AuthenticationTypesConfigurer typesConfigurer = new AuthenticationTypesConfigurer();
    private final AuthenticationStateConfigurer stateConfigurer = new AuthenticationStateConfigurer();
    private final AuthorizationServerConfigurer authorizationServerConfigurer = new AuthorizationServerConfigurer();
    private final ResourceServerConfigurer resourceServerConfigurer = new ResourceServerConfigurer();

    public SecurityIntegrationConfigurer authentication(Consumer<AuthenticationTypesConfigurer> customizer) {
        customizer.accept(this.typesConfigurer);
        return this;
    }

    public SecurityIntegrationConfigurer state(Consumer<AuthenticationStateConfigurer> customizer) {
        customizer.accept(this.stateConfigurer);
        return this;
    }

    public SecurityIntegrationConfigurer authorizationServer(Consumer<AuthorizationServerConfigurer> customizer) {
        customizer.accept(this.authorizationServerConfigurer);
        return this;
    }

    public SecurityIntegrationConfigurer resourceServer(Consumer<ResourceServerConfigurer> customizer) {
        customizer.accept(this.resourceServerConfigurer);
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

         AuthenticationStateStrategy strategy = stateConfigurer.buildStrategy();
        for (AuthenticationConfigurer configurer : typesConfigurer.getEntries()) {
            configurer.stateStrategy(strategy);
            configurer.configure(http);
        }
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

    }
}




