package io.springsecurity.springsecurity6x.security.config;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.dsl.AuthIntegrationPlatformConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.oauth2client.OAuth2ClientDsl;
import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateDsl;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class AuthConfig {

    @Bean
    public AuthIntegrationPlatformConfigurer authIntegrationPlatformConfigurer(
            AuthenticationStateDsl stateDsl,
            AuthContextProperties props,
            OAuth2ClientDsl oauth2ClientDsl) {
        return new AuthIntegrationPlatformConfigurer(stateDsl, oauth2ClientDsl);
    }

    @Bean
    public AuthenticationStateDsl authenticationStateDsl(AuthContextProperties props) {
        return new AuthenticationStateDsl(props, secretKey());
    }

    @Bean
    public SecretKey secretKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Bean
    public OAuth2ClientDsl oauth2ClientDsl(AuthContextProperties props) {
        return new OAuth2ClientDsl()
                .tokenUri(props.getExternal().getIssuerUri() + props.getExternal().getTokenEndpoint())
                .clientId(props.getExternal().getClientId())
                .clientSecret(props.getExternal().getClientSecret())
                .scope(props.getExternal().getScope())
                .build();
    }
}

