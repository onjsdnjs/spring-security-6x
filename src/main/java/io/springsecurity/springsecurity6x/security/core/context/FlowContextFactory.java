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
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
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
            // 생성된 HttpSecurity 객체에 PlatformContext 자체를 공유 객체로 "먼저" 등록합니다.
            log.debug("Sharing PlatformContext with HttpSecurity instance for flow: {}", flowCfg.getTypeName());
            http.setSharedObject(PlatformContext.class, platformContext); // <--- 이 라인이 중요!
            // ----------------------

            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config); // 그 다음에 FlowContext 생성
            setupSharedObjectsForFlow(fc); // FlowContext 내부의 HttpSecurity에 MFA 관련 객체 등 공유
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
        log.info("{} FlowContext(s) created and sorted.", flows.size());
        return flows;
    }

    private void setupSharedObjectsForFlow(FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        PlatformContext platformContext = fc.context();
        ApplicationContext appContext = platformContext.applicationContext(); // ApplicationContext 가져오기

        log.debug("Setting up shared objects for flow: {}", flowConfig.getTypeName());

        // 공통적으로 HttpSecurity에 공유될 수 있는 객체들 (예: AuthenticationManager는 Spring Security가 자동으로 공유)
        // http.setSharedObject(AuthenticationManager.class, appContext.getBean(AuthenticationManager.class)); // 이미 공유될 가능성 높음

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());

            // MfaInfrastructureAutoConfiguration 등에서 빈으로 등록된 MFA 핵심 서비스들을 HttpSecurity에 공유
            setSharedObjectIfAbsent(http, ContextPersistence.class, () -> appContext.getBean(ContextPersistence.class));
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class, () -> appContext.getBean(MfaPolicyProvider.class));
            setSharedObjectIfAbsent(http, StateMachineManager.class, () -> new StateMachineManager(flowConfig)); // flowConfig에 따라 생성

            // StateHandlerRegistry 설정
            if (http.getSharedObject(StateHandlerRegistry.class) == null) {
                try {
                    // MfaPolicyProvider 빈을 가져와서 VerificationPendingStateHandler 생성자에 주입
                    MfaPolicyProvider policyProvider = appContext.getBean(MfaPolicyProvider.class);
                    List<MfaStateHandler> handlers = List.of(
                            new PrimaryAuthCompletedStateHandler(),
                            new AutoAttemptFactorStateHandler(),
                            new FactorSelectionStateHandler(),
                            new ChallengeInitiatedStateHandler(),
                            new VerificationPendingStateHandler(policyProvider), // MfaPolicyProvider 주입
                            new OttStateHandler(),
                            new PasskeyStateHandler(),
                            new RecoveryStateHandler(),
                            new TokenStateHandler()
                    );
                    http.setSharedObject(StateHandlerRegistry.class, new StateHandlerRegistry(handlers));
                } catch (NoSuchBeanDefinitionException e) {
                    log.error("Failed to get MfaPolicyProvider bean for StateHandlerRegistry setup in flow: {}", flowConfig.getTypeName(), e);
                    // 적절한 예외 처리 또는 기본 핸들러 설정
                }
            }

            setSharedObjectIfAbsent(http, ChallengeRouter.class, () -> new ChallengeRouter(new DefaultChallengeGenerator()));
            setSharedObjectIfAbsent(http, FeatureRegistry.class, () -> this.featureRegistry); // FeatureRegistry는 싱글톤처럼 사용
            setSharedObjectIfAbsent(http, AuditEventPublisher.class, DefaultAuditEventPublisher::new);
            // RiskEngine, TrustedDeviceService, RecoveryService 등도 필요시 appContext.getBean()으로 가져와 설정
            trySetSharedObject(http, RiskEngine.class, () -> appContext.getBean(RiskEngine.class), DefaultRiskEngine::new);
            trySetSharedObject(http, TrustedDeviceService.class, () -> appContext.getBean(TrustedDeviceService.class), DefaultTrustedDeviceService::new);
            trySetSharedObject(http, RecoveryService.class, () -> appContext.getBean(RecoveryService.class), DefaultRecoveryService::new);

            log.info("MFA specific shared objects configured for flow: {}", flowConfig.getTypeName());
        } else {
            log.debug("Non-MFA flow or MFA objects not explicitly required for flow: {}", flowConfig.getTypeName());
        }
    }

    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            try {
                T object = supplier.get();
                if (object != null) {
                    http.setSharedObject(type, object);
                    log.trace("Shared object {} set in HttpSecurity for current flow.", type.getSimpleName());
                } else {
                    log.warn("Supplier for {} returned null, object not shared.", type.getSimpleName());
                }
            } catch (Exception e) {
                log.warn("Failed to create or set shared object of type {} for current flow. Error: {}", type.getSimpleName(), e.getMessage());
            }
        } else {
            log.trace("Shared object {} already exists in HttpSecurity for current flow.", type.getSimpleName());
        }
    }

    // 빈이 존재하면 가져오고, 없으면 기본 공급자로 생성하는 헬퍼 메소드
    private <T> void trySetSharedObject(HttpSecurity http, Class<T> type, Supplier<T> beanSupplier, Supplier<T> defaultSupplier) {
        if (http.getSharedObject(type) == null) {
            T objectToShare = null;
            try {
                objectToShare = beanSupplier.get(); // 먼저 빈으로 등록된 것을 찾음
            } catch (NoSuchBeanDefinitionException e) {
                log.warn("No bean of type {} found, trying default supplier.", type.getSimpleName());
                if (defaultSupplier != null) {
                    objectToShare = defaultSupplier.get();
                }
            } catch (Exception e) {
                log.error("Error while trying to get bean or use default supplier for type {}: {}", type.getSimpleName(), e.getMessage());
            }

            if (objectToShare != null) {
                http.setSharedObject(type, objectToShare);
                log.trace("Shared object {} (from bean or default) set in HttpSecurity for current flow.", type.getSimpleName());
            } else {
                log.warn("Could not obtain or create shared object for type {}.", type.getSimpleName());
            }
        } else {
            log.trace("Shared object {} already exists in HttpSecurity for current flow.", type.getSimpleName());
        }
    }
}