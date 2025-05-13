package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.DslValidationConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.*;
import io.springsecurity.springsecurity6x.security.core.validator.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
    private final SecurityFilterChainRegistrar registrar;

    public SecurityPlatformInitializer(
            PlatformContext context,
            List<SecurityConfigurer> baseConfigurers,
            FeatureRegistry featureRegistry,
            SecurityFilterChainRegistrar registrar) {
        this.context = context;
        this.baseConfigurers = baseConfigurers;
        this.featureRegistry = featureRegistry;
        this.registrar = registrar;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {

        List<FlowContext> flows = createAndSortFlows();
        for (FlowContext fc : flows) {
            HttpSecurity http = fc.http();
            http.setSharedObject(FeatureRegistry.class, featureRegistry);
        }

        List<SecurityConfigurer> configurers = buildConfigurers();
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try {
                        cfg.init(context, config);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer init 실패: " + cfg, e);
                    }
                });

        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> flows.forEach(fc -> {
                    try {
                        cfg.configure(fc);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer configure 실패: " + cfg + " on flow: " + fc.flow().typeName(), e);
                    }
                }));

        registrar.registerSecurityFilterChains(flows,context.applicationContext());
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

    private List<SecurityConfigurer> buildConfigurers() throws Exception {

        List<SecurityConfigurer> configurers = new ArrayList<>(baseConfigurers);
        DslValidator validator = new DslValidator(List.of(
                new DslSyntaxValidator(),
                new DslSemanticValidator(),
                new ConflictRiskAnalyzer()
        ));
        configurers.add(new DslValidationConfigurer(validator, createAndSortFlows()));

        featureRegistry.getAuthFeaturesFor(config.flows())
                .forEach(f -> configurers.add(new AuthFeatureConfigurerAdapter(f)));

        featureRegistry.getStateFeaturesFor(config.flows())
                .forEach(sf -> configurers.add(new StateFeatureConfigurerAdapter(sf, context)));

        return configurers;
    }
}

