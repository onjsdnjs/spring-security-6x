package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.DefaultRiskEngine;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.*;
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
            platformContext.registerHttp(flowCfg, http); // PlatformContext에 현재 Flow와 HttpSecurity 매핑 등록

            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            setupSharedObjectsForFlow(fc);
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

        log.debug("Setting up shared objects for flow: {}", flowConfig.getTypeName());

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());

            // 람다를 사용하여 지연 초기화 및 객체 재사용 방지 (HttpSecurity 인스턴스별로 새로 생성)
            setSharedObjectIfAbsent(http, ContextPersistence.class, HttpSessionContextPersistence::new);
            setSharedObjectIfAbsent(http, StateMachineManager.class, () -> new StateMachineManager(flowConfig));

            List<MfaStateHandler> handlers = List.of(
                    new OttStateHandler(), new PasskeyStateHandler(),
                    new RecoveryStateHandler(), new TokenStateHandler()
            );
            setSharedObjectIfAbsent(http, StateHandlerRegistry.class, () -> new StateHandlerRegistry(handlers));
            setSharedObjectIfAbsent(http, ChallengeRouter.class, () -> new ChallengeRouter(new DefaultChallengeGenerator()));
            setSharedObjectIfAbsent(http, FeatureRegistry.class, () -> this.featureRegistry); // FeatureRegistry는 싱글톤이므로 그대로 전달

            // MFA 관련 기타 서비스 (필요시)
            setSharedObjectIfAbsent(http, AuditEventPublisher.class, DefaultAuditEventPublisher::new);
            setSharedObjectIfAbsent(http, RiskEngine.class, DefaultRiskEngine::new); // DefaultRiskEngine은 예시
            setSharedObjectIfAbsent(http, TrustedDeviceService.class, DefaultTrustedDeviceService::new); // DefaultTrustedDeviceService는 예시
            setSharedObjectIfAbsent(http, RecoveryService.class, DefaultRecoveryService::new); // DefaultRecoveryService는 예시

            log.info("MFA specific shared objects configured for flow: {}", flowConfig.getTypeName());
        } else {
            log.debug("Non-MFA flow or MFA objects not explicitly required for flow: {}", flowConfig.getTypeName());
        }
    }

    /**
     * HttpSecurity에 공유 객체가 없는 경우에만 Supplier를 통해 생성하여 설정합니다.
     */
    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            http.setSharedObject(type, supplier.get());
        }
    }
}
