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

    public List<FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContextInstanceToShare) {
        // platformContextInstanceToShare가 null 이면 심각한 문제이므로 미리 확인
        Objects.requireNonNull(platformContextInstanceToShare, "platformContextInstanceToShare cannot be null when creating flows.");
        log.debug("FlowContextFactory creating flows with PlatformContext instance: {}", System.identityHashCode(platformContextInstanceToShare));

        List<FlowContext> flows = new ArrayList<>();
        for (AuthenticationFlowConfig flowCfg : config.getFlows()) {
            // 각 SecurityFilterChain은 고유한 HttpSecurity 인스턴스를 가질 수 있음
            HttpSecurity http = platformContextInstanceToShare.newHttp();
            log.debug("Created new HttpSecurity instance: {} for flow: {}", System.identityHashCode(http), flowCfg.getTypeName());

            // PlatformContext에 현재 Flow와 HttpSecurity 매핑 등록 (이는 PlatformContext 내부 로직)
            platformContextInstanceToShare.registerHttp(flowCfg, http);

            // --- 여기가 가장 중요한 부분 ---
            // 생성된 HttpSecurity 객체에 PlatformContext 자체를 공유 객체로 "먼저" 등록합니다.
            log.debug("Sharing PlatformContext (instance: {}) with HttpSecurity (instance: {}) for flow: {}",
                    System.identityHashCode(platformContextInstanceToShare), System.identityHashCode(http), flowCfg.getTypeName());
            http.setSharedObject(PlatformContext.class, platformContextInstanceToShare);
            // --------------------------

            // 공유 직후 확인 로그
            PlatformContext sharedCtxCheck = http.getSharedObject(PlatformContext.class);
            if (sharedCtxCheck == null) {
                log.error("CRITICAL: PlatformContext IS NULL in HttpSecurity (instance: {}) immediately after sharing for flow: {}",
                        System.identityHashCode(http), flowCfg.getTypeName());
            } else {
                log.debug("PlatformContext (instance: {}) successfully shared with HttpSecurity (instance: {}) for flow: {}. Retrieved instance: {}",
                        System.identityHashCode(platformContextInstanceToShare), System.identityHashCode(http), flowCfg.getTypeName(), System.identityHashCode(sharedCtxCheck));
            }

            FlowContext fc = new FlowContext(flowCfg, http, platformContextInstanceToShare, config);
            setupSharedObjectsForFlow(fc);
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
        log.info("{} FlowContext(s) created and sorted.", flows.size());
        return flows;
    }

    // setupSharedObjectsForFlow 메소드는 이전 답변의 최종 제안 버전 사용
    private void setupSharedObjectsForFlow(FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        PlatformContext platformContext = fc.context(); // fc를 통해 platformContext를 가져옴
        ApplicationContext appContext = platformContext.applicationContext();

        log.debug("Setting up shared objects for flow: {} using HttpSecurity instance: {}", flowConfig.getTypeName(), System.identityHashCode(http));

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());

            setSharedObjectIfAbsent(http, ContextPersistence.class, () -> appContext.getBean(ContextPersistence.class));
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class, () -> appContext.getBean(MfaPolicyProvider.class));
            setSharedObjectIfAbsent(http, StateMachineManager.class, () -> new StateMachineManager(flowConfig));

            if (http.getSharedObject(StateHandlerRegistry.class) == null) {
                try {
                    MfaPolicyProvider policyProvider = appContext.getBean(MfaPolicyProvider.class);
                    List<MfaStateHandler> handlers = List.of(
                            new PrimaryAuthCompletedStateHandler(),
                            new AutoAttemptFactorStateHandler(),
                            new FactorSelectionStateHandler(),
                            new ChallengeInitiatedStateHandler(),
                            new VerificationPendingStateHandler(policyProvider),
                            new OttStateHandler(),
                            new PasskeyStateHandler(),
                            new RecoveryStateHandler(),
                            new TokenStateHandler()
                    );
                    http.setSharedObject(StateHandlerRegistry.class, new StateHandlerRegistry(handlers));
                } catch (NoSuchBeanDefinitionException e) {
                    log.error("Failed to get MfaPolicyProvider bean for StateHandlerRegistry setup in flow: {}", flowConfig.getTypeName(), e);
                }
            }

            setSharedObjectIfAbsent(http, ChallengeRouter.class, () -> new ChallengeRouter(new DefaultChallengeGenerator()));
            setSharedObjectIfAbsent(http, FeatureRegistry.class, () -> this.featureRegistry);
            setSharedObjectIfAbsent(http, AuditEventPublisher.class, DefaultAuditEventPublisher::new);
            trySetSharedObject(http, RiskEngine.class, () -> appContext.getBean(RiskEngine.class), DefaultRiskEngine::new);
            trySetSharedObject(http, TrustedDeviceService.class, () -> appContext.getBean(TrustedDeviceService.class), DefaultTrustedDeviceService::new);
            trySetSharedObject(http, RecoveryService.class, () -> appContext.getBean(RecoveryService.class), DefaultRecoveryService::new);

            log.info("MFA specific shared objects configured for flow: {}", flowConfig.getTypeName());
        } else {
            log.debug("Non-MFA flow or MFA objects not explicitly required for flow: {}", flowConfig.getTypeName());
        }
    }

    // setSharedObjectIfAbsent 및 trySetSharedObject 메소드는 이전 답변과 동일하게 유지
    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            try {
                T object = supplier.get();
                if (object != null) {
                    http.setSharedObject(type, object);
                    log.trace("Shared object {} (instance: {}) set in HttpSecurity (instance: {}) for current flow.", type.getSimpleName(), System.identityHashCode(object), System.identityHashCode(http));
                } else {
                    log.warn("Supplier for {} returned null, object not shared for HttpSecurity instance: {}.", type.getSimpleName(), System.identityHashCode(http));
                }
            } catch (Exception e) {
                log.warn("Failed to create or set shared object of type {} for HttpSecurity instance: {}. Error: {}", type.getSimpleName(), System.identityHashCode(http), e.getMessage());
            }
        } else {
            log.trace("Shared object {} already exists in HttpSecurity (instance: {}) for current flow.", type.getSimpleName(), System.identityHashCode(http));
        }
    }

    private <T> void trySetSharedObject(HttpSecurity http, Class<T> type, Supplier<T> beanSupplier, Supplier<T> defaultSupplier) {
        if (http.getSharedObject(type) == null) {
            T objectToShare = null;
            try {
                objectToShare = beanSupplier.get();
            } catch (NoSuchBeanDefinitionException e) {
                log.warn("No bean of type {} found for HttpSecurity instance: {}, trying default supplier.", type.getSimpleName(), System.identityHashCode(http));
                if (defaultSupplier != null) {
                    objectToShare = defaultSupplier.get();
                }
            } catch (Exception e) {
                log.error("Error while trying to get bean or use default supplier for type {} for HttpSecurity instance: {}: {}", type.getSimpleName(), System.identityHashCode(http), e.getMessage());
            }

            if (objectToShare != null) {
                http.setSharedObject(type, objectToShare);
                log.trace("Shared object {} (instance: {}, from bean or default) set in HttpSecurity (instance: {}) for current flow.", type.getSimpleName(), System.identityHashCode(objectToShare), System.identityHashCode(http));
            } else {
                log.warn("Could not obtain or create shared object for type {} for HttpSecurity instance: {}.", type.getSimpleName(), System.identityHashCode(http));
            }
        } else {
            log.trace("Shared object {} already exists in HttpSecurity (instance: {}) for current flow.", type.getSimpleName(), System.identityHashCode(http));
        }
    }
}