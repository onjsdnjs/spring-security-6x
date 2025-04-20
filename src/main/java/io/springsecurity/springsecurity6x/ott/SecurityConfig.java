package io.springsecurity.springsecurity6x.ott;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public InMemoryOneTimeTokenService tokenService() {
        return new InMemoryOneTimeTokenService();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           InMemoryOneTimeTokenService tokenService) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login/**", "/ott/**", "/css/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .oneTimeTokenLogin(ott -> ott.tokenGeneratingUrl("/ott/generate")       // 토큰 생성 요청
                        .defaultSubmitPageUrl("/login/ott*")  // 토큰 포함 링크(/login/ott?token=…)
                        .showDefaultSubmitPage(true)
                        .tokenService(tokenService))
                .webAuthn(web -> web
                        .rpName("DemoPasskey App")
                        .rpId("localhost")
                        .allowedOrigins("http://localhost:8080"))
                .csrf(Customizer.withDefaults());
        return http.build();
    }
}
