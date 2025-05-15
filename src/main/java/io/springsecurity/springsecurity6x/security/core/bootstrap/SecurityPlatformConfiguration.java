package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.FlowConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.GlobalConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.Filter;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

import java.util.List;
import java.util.Map;

@EnableConfigurationProperties(AuthContextProperties.class)
@Configuration
public class SecurityPlatformConfiguration {

    @Bean
    public PlatformContext platformContext(ApplicationContext ctx,
                                           ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    @Bean
    public FeatureRegistry featureRegistry() {
        return new FeatureRegistry();
    }

    @Bean
    public List<SecurityConfigurer> staticConfigurers() {
        return List.of(
                new FlowConfigurer(),
                new GlobalConfigurer()
        );
    }

    @Bean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(FeatureRegistry featureRegistry) {
        // MFA 단계별 인증 필터 클래스 매핑
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.of(
                "form", UsernamePasswordAuthenticationFilter.class,
                "rest", RestAuthenticationFilter.class,
                "ott", AuthenticationFilter.class,
                "passkey", WebAuthnAuthenticationFilter.class
        );
        return new SecurityFilterChainRegistrar(featureRegistry, stepFilterClasses);
    }

    @Bean
    public DslValidator dslValidator() {
        return new DslValidator(List.of(
                new DslSyntaxValidator(),
                new DslSemanticValidator(),
                new ConflictRiskAnalyzer(),
                new DuplicateMfaFlowValidator()
        ));
    }

    @Bean
    public PlatformContextInitializer platformContextInitializer(PlatformContext platformContext,
                                                                 SecretKey secretKey,
                                                                 AuthContextProperties authContextProperties,
                                                                 ObjectMapper objectMapper) {
        return new PlatformContextInitializer(platformContext, secretKey, authContextProperties, objectMapper);
    }

    @Bean
    public SecurityPlatform securityPlatform(PlatformContext context,DslValidator validator,
                                             List<SecurityConfigurer> staticConfigurers,
                                             FeatureRegistry featureRegistry,
                                             PlatformContextInitializer platformContextInitializer,
                                             SecurityFilterChainRegistrar securityFilterChainRegistrar) {

        platformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider =
                new DefaultSecurityConfigurerProvider(staticConfigurers, featureRegistry);

        return new SecurityPlatformInitializer(
                context,
                securityFilterChainRegistrar,
                new FlowContextFactory(featureRegistry),
                new DslValidatorService(validator),
                new SecurityConfigurerOrchestrator(configurerProvider)
        );
    }

    @Bean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
                                               PlatformConfig platformConfig,
                                               FeatureRegistry registry) {
        return new PlatformBootstrap(securityPlatform, platformConfig, registry);
    }
}



