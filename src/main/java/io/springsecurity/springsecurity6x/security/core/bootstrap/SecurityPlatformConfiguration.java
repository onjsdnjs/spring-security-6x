package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.FlowConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.GlobalConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
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
import java.util.List;

@EnableConfigurationProperties(AuthContextProperties.class)
@Configuration
public class SecurityPlatformConfiguration {

    /**
     * JWT 서명을 위한 SecretKey bean
     */
    @Bean
    public SecretKey secretKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    /**
     * PlatformContext bean 생성
     */
    @Bean
    public PlatformContext platformContext(ApplicationContext ctx,
                                           ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    /**
     * FeatureRegistry bean
     */
    @Bean
    public FeatureRegistry featureRegistry() {
        return new FeatureRegistry();
    }

    /**
     * 플랫폼 기본 Configurer 모음
     */
    @Bean
    public List<SecurityConfigurer> staticConfigurers() {
        return List.of(
                new FlowConfigurer(),
                new GlobalConfigurer()
        );
    }

    /**
     * SecurityPlatform bean 생성
     * staticConfigurers: 플랫폼 기본 설정들
     * featureRegistry: 인증 및 상태 Feature 레지스트리
     */
    @Bean
    public SecurityPlatform securityPlatform(PlatformContext context,AuthContextProperties properties,
                                             List<SecurityConfigurer> staticConfigurers,
                                             FeatureRegistry featureRegistry) {
        // 글로벌 공유 객체 설정
        context.share(SecretKey.class, secretKey());
        context.share(AuthContextProperties.class, properties);

        return new SecurityPlatformInitializer(
                context,
                staticConfigurers,
                featureRegistry
        );
    }

    /**
     * PlatformBootstrap bean
     */
    @Bean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
                                               PlatformConfig platformConfig,
                                               FeatureRegistry registry) {
        return new PlatformBootstrap(securityPlatform, platformConfig, registry);
    }

    /**
     * ModelMapper bean
     */
    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    // AuthContextProperties는 @EnableConfigurationProperties로 자동 주입
}



