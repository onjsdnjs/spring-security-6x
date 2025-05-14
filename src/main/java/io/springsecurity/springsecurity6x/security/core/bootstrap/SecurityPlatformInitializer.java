package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.AuthFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.DslValidationConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.StateFeatureConfigurerAdapter;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
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
    private final SecurityFilterChainRegistrar registrar;
    private final FlowContextFactory flowContextFactory; // 새로 추가
    private final DslValidatorService dslValidatorService; // 새로 추가
    private final SecurityConfigurerOrchestrator securityConfigurerOrchestrator; // 새로 추가

    private PlatformConfig config;

    public SecurityPlatformInitializer(PlatformContext context,
                                       SecurityFilterChainRegistrar registrar,
                                       FlowContextFactory flowContextFactory,
                                       DslValidatorService dslValidatorService,
                                       SecurityConfigurerOrchestrator securityConfigurerOrchestrator) {
        this.context = context;
        this.registrar = registrar;
        this.flowContextFactory = flowContextFactory;
        this.dslValidatorService = dslValidatorService;
        this.securityConfigurerOrchestrator = securityConfigurerOrchestrator;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
        // featureRegistry 관련 로직은 SecurityConfigurerOrchestrator 등으로 이동 고려
    }

    @Override
    public void initialize() throws Exception {
        // 1. Flow 생성 및 정렬
        List<FlowContext> flows = flowContextFactory.createAndSortFlows(config, context);

        // 2. DSL 검증
        dslValidatorService.validate(flows);

        // 3. SecurityConfigurer 초기화 및 Flow별 구성 적용
        securityConfigurerOrchestrator.applyConfigurations(flows, context, config);

        // 4. SecurityFilterChain 등록
        registrar.registerSecurityFilterChains(flows, context.applicationContext());
    }
}

