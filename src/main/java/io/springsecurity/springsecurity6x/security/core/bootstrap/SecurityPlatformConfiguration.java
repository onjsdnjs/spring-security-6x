package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.*;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;
import java.util.List;

@EnableConfigurationProperties(AuthContextProperties.class)
@Configuration
public class SecurityPlatformConfiguration {

    @Bean
    public SecretKey secretKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    @Bean
    public PlatformContext platformContext(ApplicationContext context, ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(context, provider);
    }

    @Bean
    public FeatureRegistry featureRegistry() {
        return new FeatureRegistry();
    }

    @Bean
    public List<SecurityConfigurer> securityConfigurers(FeatureRegistry registry) {
        return List.of(new GlobalConfigurer(), new FlowConfigurer(),
                new StateConfigurer(registry), new StepConfigurer(registry));
    }

    @Bean
    public SecurityPlatform securityPlatform(PlatformContext context, List<SecurityConfigurer> securityConfigurers,
                                             SecretKey secretKey, AuthContextProperties props) {

        context.share(SecretKey.class, secretKey);
        context.share(AuthContextProperties.class, props);

        return new SecurityPlatformImpl(context, securityConfigurers);
    }

    @Bean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
                                               PlatformConfig platformConfig, FeatureRegistry registry) {
        return new PlatformBootstrap(securityPlatform, platformConfig, registry);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }
}


