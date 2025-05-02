package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class IdentitySecurityConfiguration {

    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final IdentityDslRegistry registry;
    private final SecretKey secretKey;
    private final AuthContextProperties props;

    @Bean
    public List<SecurityFilterChain> securityFilterChains() throws Exception {
        List<AuthenticationConfig> configs = registry.config();
        List<IdentitySecurityConfigurer> configurers = registry.configurerList();
        IdentitySecurityBuilder builder = new IdentitySecurityBuilder(httpSecurityProvider, configs, configurers);
        return builder.build();
    }
}


