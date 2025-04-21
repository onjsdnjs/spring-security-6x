package io.springsecurity.springsecurity6x.jwt.strategy;

import io.springsecurity.springsecurity6x.jwt.enums.AuthType;
import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

@Component
public class OttAuthConfigurerStrategy implements AuthConfigurerStrategy {

    @Override
    public void configureIfEnabled(HttpSecurity http, IntegrationAuthProperties props) throws Exception {
        if (props.isAuthEnabled(AuthType.OTT)) {
            http.oneTimeTokenLogin(ott -> ott
                    .tokenGeneratingUrl("/ott/generate")
                    .defaultSubmitPageUrl("/login/ott*")
                    .showDefaultSubmitPage(true)
                    .tokenService(new InMemoryOneTimeTokenService()));
        }
    }
}

