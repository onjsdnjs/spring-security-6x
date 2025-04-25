package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.authentication.AuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.token.AuthorizationServerConfigurer;
import io.springsecurity.springsecurity6x.security.configurer.token.ResourceServerConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class SecurityIntegrationConfigurer extends AbstractHttpConfigurer<SecurityIntegrationConfigurer, HttpSecurity> {

    private final AuthenticationTypesConfigurer typesConfigurer = new AuthenticationTypesConfigurer();
    private AuthenticationStateConfigurer stateConfigurer ;
    private final AuthorizationServerConfigurer authorizationServerConfigurer = new AuthorizationServerConfigurer();
    private final ResourceServerConfigurer resourceServerConfigurer = new ResourceServerConfigurer();
    private final HttpSecurity http;

    public SecurityIntegrationConfigurer(HttpSecurity http) {
        this.http = http;
    }

    public SecurityIntegrationConfigurer authentication(Customizer<AuthenticationTypesConfigurer> customizer) {
        customizer.customize(this.typesConfigurer);
        try {
            this.http.with(typesConfigurer, Customizer.withDefaults());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return this;
    }

    public SecurityIntegrationConfigurer state(Customizer<AuthenticationStateConfigurer> customizer) {
        stateConfigurer = new AuthenticationStateConfigurer(http);
        customizer.customize(this.stateConfigurer);

        try {
            http.with(stateConfigurer, Customizer.withDefaults());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return this;
    }

    public SecurityIntegrationConfigurer authorizationServer(Customizer<AuthorizationServerConfigurer> customizer) {
        customizer.customize(this.authorizationServerConfigurer);
        return this;
    }

    public SecurityIntegrationConfigurer resourceServer(Customizer<ResourceServerConfigurer> customizer) {
        customizer.customize(this.resourceServerConfigurer);
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        AuthenticationStateStrategy strategy = stateConfigurer.buildStrategy();
        http.setSharedObject(AuthenticationStateStrategy.class, strategy);
        for (AuthenticationConfigurer configurer : typesConfigurer.entries()) {
            configurer.stateStrategy(strategy);
            configurer.configure(http);
        }
    }

   @Override
    public void configure(HttpSecurity http) throws Exception {
       super.configure(http);
   }
}




