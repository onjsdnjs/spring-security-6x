package io.springsecurity.springsecurity6x.security.core.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public class FlowContextFactory {

    private static final Logger log = LoggerFactory.getLogger(FlowContextFactory.class);
    private final FeatureRegistry featureRegistry;
    private final ApplicationContext applicationContext; // 추가

    public FlowContextFactory(FeatureRegistry featureRegistry, ApplicationContext applicationContext) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry, "featureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
    }

    public List<io.springsecurity.springsecurity6x.security.core.context.FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContext) {
        List<io.springsecurity.springsecurity6x.security.core.context.FlowContext> flows = new ArrayList<>();
        if (config == null || CollectionUtils.isEmpty(config.getFlows())) {
            log.warn("PlatformConfig or its flows are null/empty. No FlowContexts will be created.");
            return flows;
        }

        for (AuthenticationFlowConfig flowCfg : config.getFlows()) {
            // HttpSecurity 인스턴스를 PlatformContext를 통해 새로 생성
            HttpSecurity http = platformContext.newHttp();
            // 생성된 HttpSecurity를 현재 FlowConfig와 함께 PlatformContext에 등록 (매핑)
            platformContext.registerHttp(flowCfg, http);

            // FlowContext를 생성하기 전에, 현재 처리중인 flowCfg를 HttpSecurity의 공유 객체로 먼저 설정.
            // 이는 MfaAuthenticationFeature.apply 등에서 현재 FlowConfig 정보에 접근해야 할 때 사용됨.
            http.setSharedObject(AuthenticationFlowConfig.class, flowCfg);
            // PlatformContext 자체도 HttpSecurity에 공유 (AbstractAuthenticationFeature 등에서 ApplicationContext 접근용)
            http.setSharedObject(PlatformContext.class, platformContext);
            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            setupSharedObjectsForFlow(fc); // HttpSecurity에 필요한 공유 객체들 설정
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
        log.info("{} FlowContext(s) created and sorted.", flows.size());
        return flows;
    }

    private void setupSharedObjectsForFlow(io.springsecurity.springsecurity6x.security.core.context.FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        ApplicationContext appContext = this.applicationContext; // 직접 주입받은 것 사용

        log.debug("Setting up shared objects for flow: {}", flowConfig.getTypeName());

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
            log.debug("MFA flow detected for '{}', setting up MFA shared objects.", flowConfig.getTypeName());
            setSharedObjectIfAbsent(http, ContextPersistence.class, () -> appContext.getBean(ContextPersistence.class));
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class, () -> appContext.getBean(MfaPolicyProvider.class));
            /*flowConfig*/
            setSharedObjectIfAbsent(http, ObjectMapper.class, ObjectMapper::new);
        }
    }
    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            try {
                T object = supplier.get();
                if (object != null) {
                    http.setSharedObject(type, object);
                }
            } catch (Exception e) {
                log.warn("Failed to create/set shared object of type {} for current flow: {}", type.getSimpleName(), e.getMessage());
            }
        }
    }
}