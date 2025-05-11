package io.springsecurity.springsecurity6x;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@RequiredArgsConstructor
public class SecurityConfig {

//    private final AuthIntegrationPlatformConfigurer platformConfigurer;

//    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            .authorizeHttpRequests(authReq -> authReq
                    .requestMatchers("/api/register").permitAll()
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().permitAll())
                ;

            /*.with(platformConfigurer, platformConfigurer -> platformConfigurer
                    .rest(rest -> rest.loginProcessingUrl("/api/auth/login"))
                    .form(form -> form.loginPage("/login"))
                    .ott(ott -> ott.loginProcessingUrl("/login/ott"))
                    .passkey(passkey -> passkey.rpName("SecureApp").rpId("localhost").allowedOrigins("http://localhost:8080"))
                    .state(AuthenticationStateDsl::jwt)
            );*/
        return http.build();
    }

    /*@Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }*/
}