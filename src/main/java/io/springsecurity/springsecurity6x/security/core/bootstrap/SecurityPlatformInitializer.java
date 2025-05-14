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
    private final SecurityFilterChainRegistrar registrar;

    private PlatformConfig config;

    public SecurityPlatformInitializer(PlatformContext context, List<SecurityConfigurer> baseConfigurers,
                                       FeatureRegistry featureRegistry, SecurityFilterChainRegistrar registrar) {
        this.context = context;
        this.baseConfigurers = List.copyOf(baseConfigurers);
        this.featureRegistry = featureRegistry;
        this.registrar = registrar;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {

        // 1. Flow 생성 및 정렬
        List<FlowContext> flows = createAndSortFlows();

        // 2. DSL 검증
        validateDsl(flows);

        // 3. SecurityConfigurer 초기화
        List<SecurityConfigurer> configurers = buildConfigurers(flows);
        initConfigurers(configurers);

        // 4. Flow별 구성 적용
        configureFlows(flows, configurers);

        // 5. SecurityFilterChain 등록
        registerFilterChains(flows);
    }

    private List<FlowContext> createAndSortFlows() {

        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flowCfg : config.flows()) {
            HttpSecurity http = context.newHttp();
            FlowContext fc = new FlowContext(flowCfg, http, context, config);
            context.share(FlowContext.class, fc);
            setupSharedObjects(fc);
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().order()));
        return flows;
    }

    private void setupSharedObjects(FlowContext fc) {

        HttpSecurity http = fc.http();
        http.setSharedObject(ContextPersistence.class, new HttpSessionContextPersistence());
        http.setSharedObject(StateMachineManager.class, new StateMachineManager(fc.flow()));
        List<MfaStateHandler> handlers = List.of(
                new FormStateHandler(), new RestStateHandler(),
                new OttStateHandler(), new PasskeyStateHandler(),
                new RecoveryStateHandler(), new TokenStateHandler()
        );
        http.setSharedObject(StateHandlerRegistry.class, new StateHandlerRegistry(handlers));
        http.setSharedObject(ChallengeRouter.class, new ChallengeRouter(new DefaultChallengeGenerator()));
        http.setSharedObject(FeatureRegistry.class, featureRegistry);
    }

    private void validateDsl(List<FlowContext> flows) {

        DslValidator validator = new DslValidator(List.of(
                new DslSyntaxValidator(), new DslSemanticValidator(),
                new ConflictRiskAnalyzer(), new DuplicateMfaFlowValidator()
        ));
        var result = validator.validate(flows);
        ValidationReportReporter.report(result);
    }

    private List<SecurityConfigurer> buildConfigurers(List<FlowContext> flows) {

        List<SecurityConfigurer> configurers = new ArrayList<>(baseConfigurers);
        DslValidator validator = new DslValidator(List.of(
                new DslSyntaxValidator(), new DslSemanticValidator(),
                new ConflictRiskAnalyzer(), new DuplicateMfaFlowValidator()
        ));
        configurers.add(new DslValidationConfigurer(validator, flows));
        featureRegistry.getAuthFeaturesFor(config.flows())
                .forEach(f -> configurers.add(new AuthFeatureConfigurerAdapter(f)));
        featureRegistry.getStateFeaturesFor(config.flows())
                .forEach(sf -> configurers.add(new StateFeatureConfigurerAdapter(sf, context)));
        return configurers;
    }

    private void initConfigurers(List<SecurityConfigurer> configurers){
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> cfg.init(context, config));
    }

    private void configureFlows(List<FlowContext> flows, List<SecurityConfigurer> configurers) throws Exception {
        for (SecurityConfigurer cfg : configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder)).toList()) {
            for (FlowContext fc : flows) {
                cfg.configure(fc);
            }
        }
    }

    private void registerFilterChains(List<FlowContext> flows) {
        registrar.registerSecurityFilterChains(flows, context.applicationContext());
    }
}

