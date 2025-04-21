package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InternalTokenSecurityStrategy implements TokenSecurityStrategy{

    private final JwtDecoder jwtDecoder;
    private final List<AuthConfigurerStrategy> authStrategies;
    private final IntegrationAuthProperties props;
    private final AuthorizationServerSettings authorizationServerSettings;

    public InternalTokenSecurityStrategy(JwtDecoder jwtDecoder, List<AuthConfigurerStrategy> authStrategies, IntegrationAuthProperties integrationAuthProperties, AuthorizationServerSettings authorizationServerSettings) {
        this.jwtDecoder = jwtDecoder;
        this.authStrategies = authStrategies;
        this.props = integrationAuthProperties;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Override
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .oauth2ResourceServer(resourceServer ->
                        resourceServer.jwt(Customizer.withDefaults()))

                .with(authorizationServerConfigurer, configurer -> {
                    configurer.authorizationServerSettings(authorizationServerSettings);
                });

        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));

        for (AuthConfigurerStrategy strategy : authStrategies) {
            strategy.configureIfEnabled(http, props);
        }

        return http.build();
    }
}
