package io.springsecurity.springsecurity6x.jwt.configurer;

import io.springsecurity.springsecurity6x.jwt.configurer.authentication.AuthenticationEntryConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.jwt.configurer.token.AuthorizationServerConfigurer;
import io.springsecurity.springsecurity6x.jwt.configurer.token.ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.function.Consumer;

public class IdentityConfigurer extends AbstractHttpConfigurer<IdentityConfigurer, HttpSecurity> {

    private final AuthenticationTypeConfigurer authenticationTypeConfigurer = new AuthenticationTypeConfigurer();
    private final AuthenticationStateConfigurer stateConfigurer = new AuthenticationStateConfigurer();
    private final AuthorizationServerConfigurer authorizationServerConfigurer = new AuthorizationServerConfigurer();
    private final ResourceServerConfigurer resourceServerConfigurer = new ResourceServerConfigurer();

    public IdentityConfigurer authentication(Consumer<AuthenticationTypeConfigurer> customizer) {
        customizer.accept(this.authenticationTypeConfigurer);
        return this;
    }

    public IdentityConfigurer state(Consumer<AuthenticationStateConfigurer> customizer) {
        customizer.accept(this.stateConfigurer);
        return this;
    }

    public IdentityConfigurer authorizationServer(Consumer<AuthorizationServerConfigurer> customizer) {
        customizer.accept(this.authorizationServerConfigurer);
        return this;
    }

    public IdentityConfigurer resourceServer(Consumer<ResourceServerConfigurer> customizer) {
        customizer.accept(this.resourceServerConfigurer);
        return this;
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationStateStrategy strategy = stateConfigurer.buildStrategy();

        for (AuthenticationEntryConfigurer configurer : authenticationTypeConfigurer.getEntries()) {
            configurer.setStateStrategy(strategy);
            configurer.configure(http);
        }

        // 내부 인가서버 적용
        authorizationServerConfigurer.configure(http);
    }
}




