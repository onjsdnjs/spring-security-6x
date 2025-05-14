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
            // platformContext.share(FlowContext.class, fc); // 주의: FlowContext는 Flow마다 다르므로 이렇게 공유하면 마지막 것만 남음.
            // 대신 HttpSecurity.getSharedObject(FlowContext.class) 형태로 사용하거나
            // SecurityConfigurerOrchestrator에서 루프 돌 때마다 fc를 직접 전달.
            // 이전 답변에서 이 부분을 platformContext.share로 두었는데, 이는 수정이 필요함.
            // SecurityConfigurerOrchestrator.applyConfigurations에서 fc를 직접 사용하도록 수정.

            setupSharedObjectsForFlow(fc); // 변경된 메소드 호출
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

        // CSRF, CORS 등은 GlobalConfigurer 또는 각 Feature 내에서 HttpSecurity에 직접 적용되므로 여기서 제외.
        // 여기서는 주로 MFA 흐름에 필요한 객체들을 설정합니다.

        // MFA 흐름이거나, 단일 단계라도 MFA 요소(예: 커스텀 필터에서 FactorContext 사용)를 사용할 가능성이 있다면 설정
        // 좀 더 명확하게는, DSL 에서 mfa {} 블록을 사용했거나, 특정 feature가 MFA 컨텍스트를 요구한다고 명시된 경우로 제한 가능
        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        // TODO: 또는, flowConfig.requiresMfaContext() 와 같은 플래그를 두어 더 명시적으로 제어 가능

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
