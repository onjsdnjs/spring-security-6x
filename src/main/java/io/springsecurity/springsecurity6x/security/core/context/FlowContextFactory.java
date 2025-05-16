package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.DefaultRiskEngine;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.*;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public class FlowContextFactory {

    private static final Logger log = LoggerFactory.getLogger(FlowContextFactory.class);
    private final FeatureRegistry featureRegistry;

    public FlowContextFactory(FeatureRegistry featureRegistry) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "featureRegistry cannot be null");
    }

    public List<FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContext) {
        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flowCfg : config.getFlows()) {
            HttpSecurity http = platformContext.newHttp(); // 새로운 HttpSecurity 인스턴스 생성
            platformContext.registerHttp(flowCfg, http); // PlatformContext 내부 맵에 <FlowConfig, HttpSecurity> 저장

            // --- 여기가 핵심 수정 ---
            // 생성된 HttpSecurity 객체에 PlatformContext 자체를 공유 객체로 등록합니다.
            // 이렇게 함으로써 AbstractAuthenticationFeature 등에서 http.getSharedObject(PlatformContext.class) 호출 시
            // null이 아닌 PlatformContext 인스턴스를 반환받을 수 있습니다.
            log.debug("Sharing PlatformContext with HttpSecurity instance for flow: {}", flowCfg.getTypeName());
            http.setSharedObject(PlatformContext.class, platformContext);
            // ----------------------

            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            setupSharedObjectsForFlow(fc); // FlowContext 내부의 HttpSecurity에 MFA 관련 객체 등 공유
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
        log.info("{} FlowContext(s) created and sorted.", flows.size());
        return flows;
    }

    /**
     * 특정 FlowContext에 필요한 공유 객체들을 HttpSecurity에 설정합니다.
     * 주로 MFA 관련 객체들이 여기에 해당됩니다.
     * @param fc 대상 FlowContext
     */
    private void setupSharedObjectsForFlow(FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        PlatformContext platformContext = fc.context(); // PlatformContext 가져오기

        log.debug("Setting up shared objects for flow: {}", flowConfig.getTypeName());

        // 공통적으로 필요할 수 있는 빈들을 PlatformContext에서 가져와 HttpSecurity에 공유
        // 예: UserDetailsService, PasswordEncoder 등은 PlatformContext의 applicationContext()를 통해 얻을 수 있음
        // http.setSharedObject(UserDetailsService.class, platformContext.applicationContext().getBean(UserDetailsService.class));
        // http.setSharedObject(PasswordEncoder.class, platformContext.applicationContext().getBean(PasswordEncoder.class));

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());

            // MfaPolicyProvider, ContextPersistence 등은 PlatformContext의 applicationContext를 통해 빈을 가져와서 설정
            // 또는 MfaInfrastructureAutoConfiguration에서 이미 빈으로 등록되어 있다면,
            // SecurityPlatformConfiguration에서 PlatformContext에 미리 share() 해두는 방법도 있음.
            // 여기서는 applicationContext에서 가져오는 방식을 예시로 사용합니다.

            setSharedObjectIfAbsent(http, ContextPersistence.class,
                    () -> platformContext.applicationContext().getBean(ContextPersistence.class));
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class,
                    () -> platformContext.applicationContext().getBean(MfaPolicyProvider.class));


            // StateMachineManager는 flowConfig에 따라 달라질 수 있으므로 여기서 생성
            setSharedObjectIfAbsent(http, StateMachineManager.class, () -> new StateMachineManager(flowConfig));


            // StateHandlerRegistry는 여러 핸들러를 포함하므로, 필요시 PlatformContext를 통해 주입받거나 생성
            // 현재는 StateHandlerRegistry가 PlatformContextInitializer에서 주입되지 않음.
            // 만약 StateHandlerRegistry가 빈이라면 아래와 같이 가져올 수 있음:
            // setSharedObjectIfAbsent(http, StateHandlerRegistry.class,
            //        () -> platformContext.applicationContext().getBean(StateHandlerRegistry.class));
            // 여기서는 임시로 new로 생성 (실제로는 빈으로 관리되어야 함)
            if (http.getSharedObject(StateHandlerRegistry.class) == null) {
                // 실제 핸들러 목록은 MfaInfrastructureAutoConfiguration 등에서 정의된 빈들을 주입받아 구성해야 함
                List<MfaStateHandler> handlers = List.of(
                        new PrimaryAuthCompletedStateHandler(), // 추가
                        new AutoAttemptFactorStateHandler(),    // 추가
                        new FactorSelectionStateHandler(),      // 추가
                        new ChallengeInitiatedStateHandler(),   // 추가
                        new VerificationPendingStateHandler(platformContext.applicationContext().getBean(MfaPolicyProvider.class)), // 추가
                        new OttStateHandler(),
                        new PasskeyStateHandler(),
                        new RecoveryStateHandler(),
                        new TokenStateHandler()
                );
                http.setSharedObject(StateHandlerRegistry.class, new StateHandlerRegistry(handlers));
            }


            setSharedObjectIfAbsent(http, ChallengeRouter.class, () -> new ChallengeRouter(new DefaultChallengeGenerator()));
            setSharedObjectIfAbsent(http, FeatureRegistry.class, () -> this.featureRegistry);

            setSharedObjectIfAbsent(http, AuditEventPublisher.class, DefaultAuditEventPublisher::new);
            setSharedObjectIfAbsent(http, RiskEngine.class, DefaultRiskEngine::new);
            setSharedObjectIfAbsent(http, TrustedDeviceService.class, DefaultTrustedDeviceService::new);
            setSharedObjectIfAbsent(http, RecoveryService.class, DefaultRecoveryService::new);

            log.info("MFA specific shared objects configured for flow: {}", flowConfig.getTypeName());
        } else {
            log.debug("Non-MFA flow or MFA objects not explicitly required for flow: {}", flowConfig.getTypeName());
        }
    }

    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            http.setSharedObject(type, supplier.get());
            log.trace("Shared object {} set in HttpSecurity for current flow.", type.getSimpleName());
        } else {
            log.trace("Shared object {} already exists in HttpSecurity for current flow.", type.getSimpleName());
        }
    }
}