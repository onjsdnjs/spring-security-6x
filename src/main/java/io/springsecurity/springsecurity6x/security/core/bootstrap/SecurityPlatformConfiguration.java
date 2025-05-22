package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.FlowConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.GlobalConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(AuthContextProperties.class)
@Slf4j
public class SecurityPlatformConfiguration {

    @Bean
    public PlatformContext platformContext(ApplicationContext ctx,
                                           ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    @Bean
    public FeatureRegistry featureRegistry(ApplicationContext applicationContext) {
        return new FeatureRegistry(applicationContext);
    }

    @Bean
    public SecurityConfigurer flowConfigurer() {
        return new FlowConfigurer();
    }

    @Bean
    public SecurityConfigurer globalConfigurer() {
        return new GlobalConfigurer();
    }

    @Bean
    public ConfiguredFactorFilterProvider factorFilterProvider() {
        return new ConfiguredFactorFilterProvider();
    }

    @Bean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(ConfiguredFactorFilterProvider factorFilterProvider) {
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.of(
                "form", UsernamePasswordAuthenticationFilter.class,
                "rest", RestAuthenticationFilter.class,
                "ott", AuthenticationFilter.class, // Spring Security 6.x 에서는 org.springframework.security.web.authentication.AuthenticationFilter
                "passkey", WebAuthnAuthenticationFilter.class
        );
        return new SecurityFilterChainRegistrar(factorFilterProvider, stepFilterClasses);
    }

    @Bean public LoginProcessingUrlUniquenessValidator loginProcessingUrlUniquenessValidator() { return new LoginProcessingUrlUniquenessValidator(); }
    @Bean public MfaFlowStructureValidator mfaFlowStructureValidator() { return new MfaFlowStructureValidator(); }
    @Bean public RequiredPlatformOptionsValidator requiredPlatformOptionsValidator() { return new RequiredPlatformOptionsValidator(); }
    @Bean public FeatureAvailabilityValidator featureAvailabilityValidator(FeatureRegistry featureRegistry) { return new FeatureAvailabilityValidator(featureRegistry); }
    @Bean public CustomBeanDependencyValidator customBeanDependencyValidator(ApplicationContext applicationContext) { return new CustomBeanDependencyValidator(applicationContext); }
    @Bean public DuplicateFlowTypeNameValidator duplicateMfaFlowValidator() { return new DuplicateFlowTypeNameValidator(); }


    @Bean
    @ConditionalOnMissingBean
    public DslValidator dslValidator(
            ObjectProvider<List<Validator<PlatformConfig>>> platformConfigValidatorsProvider,
            ObjectProvider<List<Validator<List<AuthenticationFlowConfig>>>> flowListValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationFlowConfig>>> singleFlowValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationStepConfig>>> stepValidatorsProvider,
            ObjectProvider<List<Validator<List<FlowContext>>>> duplicatedFlowValidators) {

        List<Validator<PlatformConfig>> platformValidators = platformConfigValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<List<AuthenticationFlowConfig>>> flowListValidators = flowListValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationFlowConfig>> singleFlowValidators = singleFlowValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationStepConfig>> stepValidators = stepValidatorsProvider.getIfAvailable(Collections::emptyList);

        return new DslValidator(
                platformValidators,
                flowListValidators,
                singleFlowValidators,
                stepValidators
        );
    }

    @Bean
    public DslValidatorService dslValidatorService(DslValidator dslValidator) {
        return new DslValidatorService(dslValidator);
    }

    @Bean
    public PlatformContextInitializer platformContextInitializer(PlatformContext platformContext,
                                                                 SecretKey secretKey, // Provided by TokenServiceConfiguration
                                                                 AuthContextProperties authContextProperties,
                                                                 ObjectMapper objectMapper) { // Provided by MySecurityConfig
        return new PlatformContextInitializer(platformContext, secretKey, authContextProperties, objectMapper);
    }

    @Bean
    public FlowContextFactory flowContextFactory(FeatureRegistry featureRegistry, ApplicationContext applicationContext){
        return new FlowContextFactory(featureRegistry, applicationContext);
    }


    @Bean
    public SecurityPlatform securityPlatform(PlatformContext context,
                                             List<SecurityConfigurer> allRegisteredConfigurers,
                                             FeatureRegistry featureRegistry,
                                             PlatformContextInitializer platformContextInitializer,
                                             SecurityFilterChainRegistrar securityFilterChainRegistrar,
                                             FlowContextFactory flowContextFactory,
                                             PlatformConfig platformConfig,
                                             ApplicationContext applicationContext) {
        platformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider =
                new DefaultSecurityConfigurerProvider(allRegisteredConfigurers, featureRegistry, applicationContext);

        return new SecurityPlatformInitializer(
                context,
                platformConfig,
                securityFilterChainRegistrar,
                flowContextFactory,
                new SecurityConfigurerOrchestrator(configurerProvider)
        );
    }

    @Bean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
                                               PlatformConfig platformConfig,
                                               FeatureRegistry registry,
                                               DslValidatorService dslValidatorService) {
        return new PlatformBootstrap(securityPlatform, platformConfig, registry, dslValidatorService);
    }
}


