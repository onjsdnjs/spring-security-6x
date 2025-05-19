package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.FlowConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.GlobalConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import jakarta.servlet.Filter;
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
public class SecurityPlatformConfiguration {

    @Bean
    public PlatformContext platformContext(ApplicationContext ctx,
                                           ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    @Bean
    public FeatureRegistry featureRegistry(ApplicationContext applicationContext) { // Spring이 모든 AuthenticationFeature 빈을 주입
        return new FeatureRegistry(applicationContext);
    }

    @Bean
    public List<SecurityConfigurer> globalConfigurers() {
        return List.of(
                new FlowConfigurer(),
                new GlobalConfigurer()
        );
    }

    @Bean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(FeatureRegistry featureRegistry) {
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.of(
                "form", UsernamePasswordAuthenticationFilter.class,
                "rest", RestAuthenticationFilter.class,
                "ott", AuthenticationFilter.class,
                "passkey", WebAuthnAuthenticationFilter.class
        );
        return new SecurityFilterChainRegistrar(featureRegistry, stepFilterClasses);
    }

    // --- 개별 Validator Beans (구현체 패키지 확인 필요) ---
    @Bean public LoginProcessingUrlUniquenessValidator loginProcessingUrlUniquenessValidator() { return new LoginProcessingUrlUniquenessValidator(); }
    @Bean public MfaFlowStructureValidator mfaFlowStructureValidator() { return new MfaFlowStructureValidator(); }
    @Bean public RequiredPlatformOptionsValidator requiredPlatformOptionsValidator() { return new RequiredPlatformOptionsValidator(); }
    @Bean public FeatureAvailabilityValidator featureAvailabilityValidator(FeatureRegistry featureRegistry) { return new FeatureAvailabilityValidator(featureRegistry); }
    @Bean public CustomBeanDependencyValidator customBeanDependencyValidator(ApplicationContext applicationContext) { return new CustomBeanDependencyValidator(applicationContext); }
    @Bean public DuplicateMfaFlowValidator duplicateMfaFlowValidator() { return new DuplicateMfaFlowValidator(); }


    // --- 통합 DslValidator Bean ---
    @Bean
    @ConditionalOnMissingBean
    public DslValidator dslValidator(
            ObjectProvider<List<Validator<PlatformConfig>>> platformConfigValidatorsProvider,
            ObjectProvider<List<Validator<List<AuthenticationFlowConfig>>>> flowListValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationFlowConfig>>> singleFlowValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationStepConfig>>> stepValidatorsProvider) {

        List<Validator<PlatformConfig>> platformValidators = platformConfigValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<List<AuthenticationFlowConfig>>> flowListValidators = flowListValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationFlowConfig>> singleFlowValidators = singleFlowValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationStepConfig>> stepValidators = stepValidatorsProvider.getIfAvailable(Collections::emptyList);

        // 명시적으로 어떤 Validator가 어떤 리스트에 속해야 하는지 정의하는 것이 더 안전할 수 있음.
        // 예를 들어, LoginProcessingUrlUniquenessValidator는 flowListValidators에 포함되어야 함.
        // 지금은 Spring이 타입에 맞춰 자동으로 주입하는 것에 의존.
        // 만약 특정 Validator가 원하는 리스트에 주입되지 않으면, @Order 또는 @Qualifier 등을 사용하거나,
        // 여기서 직접 리스트를 구성해야 함.

        // 이전 답변에서 제공된 Validator 들을 올바른 리스트에 매핑하여 DslValidator 생성자에 전달
        return new DslValidator(
                platformValidators, // 현재는 비어있음
                flowListValidators, // LoginProcessingUrlUniquenessValidator, DuplicateMfaFlowValidator 포함
                singleFlowValidators, // MfaFlowStructureValidator 포함
                stepValidators      // RequiredPlatformOptionsValidator, FeatureAvailabilityValidator, CustomBeanDependencyValidator 포함
        );
    }

    @Bean
    public DslValidatorService dslValidatorService(DslValidator dslValidator) {
        return new DslValidatorService(dslValidator);
    }

    @Bean
    public PlatformContextInitializer platformContextInitializer(PlatformContext platformContext,
                                                                 SecretKey secretKey,
                                                                 AuthContextProperties authContextProperties,
                                                                 ObjectMapper objectMapper) {
        return new PlatformContextInitializer(platformContext, secretKey, authContextProperties, objectMapper);
    }

    @Bean
    public FlowContextFactory flowContextFactory(FeatureRegistry featureRegistry, ApplicationContext applicationContext){
        return new FlowContextFactory(featureRegistry, applicationContext);
    }


    @Bean
    public SecurityPlatform securityPlatform(PlatformContext context,
                                             List<SecurityConfigurer> staticConfigurers,
                                             FeatureRegistry featureRegistry,
                                             PlatformContextInitializer platformContextInitializer,
                                             SecurityFilterChainRegistrar securityFilterChainRegistrar,
                                             FlowContextFactory flowContextFactory, // 주입
                                             PlatformConfig platformConfig // 주입
    ) {

        platformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider =
                new DefaultSecurityConfigurerProvider(staticConfigurers, featureRegistry);

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


