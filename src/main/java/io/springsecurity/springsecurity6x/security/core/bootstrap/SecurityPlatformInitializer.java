package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.DslValidationConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.MfaDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityPlatform 구현체
 * - DSL, AuthenticationFeature, StateFeature를 결합해 SecurityFilterChain을 빌드
 */
@Slf4j
public class SecurityPlatformInitializer implements SecurityPlatform {
    private final PlatformContext context;
    private final List<SecurityConfigurer> baseConfigurers;
    private final FeatureRegistry featureRegistry;
    private PlatformConfig config;
    private final Map<String, Class<? extends Filter>> stepToFilter;

    public SecurityPlatformInitializer(
            PlatformContext context,
            List<SecurityConfigurer> baseConfigurers,
            FeatureRegistry featureRegistry,
            Map<String, Class<? extends Filter>> stepToFilter) {
        this.context = context;
        this.baseConfigurers = baseConfigurers;
        this.featureRegistry = featureRegistry;
        this.stepToFilter = stepToFilter;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {

        List<FlowContext> flows = createAndSortFlows();
        List<SecurityConfigurer> configurers = buildConfigurers();

        // 1) init 단계: PlatformContext, PlatformConfig 전달
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try {
                        cfg.init(context, config);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer init 실패: " + cfg, e);
                    }
                });

        // 2) configure 단계: FlowContext 별로 호출
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> flows.forEach(fc -> {
                    try {
                        cfg.configure(fc);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer configure 실패: " + cfg + " on flow: " + fc.flow().typeName(), e);
                    }
                }));

        // 3) 동적 SecurityFilterChain 등록
        registerSecurityFilterChains(flows);
    }

    private List<FlowContext> createAndSortFlows() throws Exception {
        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flow : config.flows()) {
            HttpSecurity http = context.newHttp();
            FlowContext fc = new FlowContext(flow, http, context, config);
            context.share(FlowContext.class, fc);
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(fc -> fc.flow().order()));
        return flows;
    }

    private List<SecurityConfigurer> buildConfigurers() {
        List<SecurityConfigurer> configurers = new ArrayList<>();
        DslValidator validator = new DslValidator(List.of(
                new DslSyntaxValidator(),
                new DslSemanticValidator(),
                new ConflictRiskAnalyzer()
        ));
        configurers.add(new DslValidationConfigurer(validator, new ValidationReportReporter()));

        featureRegistry.getAuthFeaturesFor(config.flows())
                .forEach(f -> configurers.add(new AuthFeatureConfigurerAdapter(f)));

        featureRegistry.getStateFeaturesFor(config.flows())
                .forEach(sf -> configurers.add(new StateFeatureConfigurerAdapter(sf, context)));

        return configurers;
    }

    private void registerSecurityFilterChains(List<FlowContext> flows) {
        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context.applicationContext();
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger index = new AtomicInteger(0);

        for (FlowContext fc : flows) {
            String name = fc.flow().typeName();
            int orderVal = fc.flow().order();
            String beanName = name + "SecurityFilterChain" + index.incrementAndGet();

            BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(SecurityFilterChain.class, () -> {
                DefaultSecurityFilterChain built;
                try {
                    built = fc.http().build();
                    // 각 스텝 필터를 FeatureRegistry에 등록
                    for (AuthenticationStepConfig step : fc.flow().stepConfigs()) {
                        String type = step.type();  // "form", "rest", "ott", "passkey"
                        Class<? extends Filter> filterClass = stepToFilter.get(type);
                        if (filterClass == null) {
                            throw new IllegalStateException("알 수 없는 MFA 단계: " + type);
                        }

                        Filter f = built.getFilters().stream()
                                .filter(filterClass::isInstance)
                                .findFirst()
                                .orElseThrow(() ->
                                        new IllegalStateException("필터를 찾을 수 없습니다 for type: " + type)
                                );

                        featureRegistry.registerFactorFilter(type, f);
                    }
                    return new OrderedSecurityFilterChain(
                            Ordered.HIGHEST_PRECEDENCE + orderVal,
                            built.getRequestMatcher(),
                            built.getFilters());
                } catch (Exception ex) {
                    log.error("SecurityFilterChain 생성 실패 (flow={}): 건너뜁니다.", fc.flow().typeName(), ex);
                    throw new BeanCreationException(
                            "SecurityFilterChain 생성 실패 for flow: " + fc.flow().typeName(), ex);
                }
            });
            builder.setLazyInit(true);
            builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
        }
    }
}

