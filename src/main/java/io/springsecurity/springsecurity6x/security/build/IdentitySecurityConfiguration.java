package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class IdentitySecurityConfiguration {

    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final List<AuthenticationConfig> authenticationConfigs;
    private final List<IdentitySecurityConfigurer> configurers;

    /**
     * Spring Security가 자동 감지할 수 있도록 SecurityFilterChain 목록을 직접 빈으로 노출
     */
    @Bean
    public List<SecurityFilterChain> securityFilterChains() {
        IdentitySecurityBootstrapper bootstrapper = new IdentitySecurityBootstrapper(
                httpSecurityProvider, authenticationConfigs, configurers
        );
        return bootstrapper.initialize(); // 최종 SecurityFilterChain 생성
    }
}

