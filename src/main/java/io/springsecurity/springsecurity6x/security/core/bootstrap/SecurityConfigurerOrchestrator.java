package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SecurityConfigurer 들의 초기화(init) 및 구성(configure) 생명주기를 관리하고 실행합니다.
 * 플랫폼의 보안 설정을 최종적으로 HttpSecurity 객체들에 적용하는 역할을 합니다.
 */
@Slf4j
public final class SecurityConfigurerOrchestrator { // final class

    private final SecurityConfigurerProvider configurerProvider;

    public SecurityConfigurerOrchestrator(SecurityConfigurerProvider configurerProvider) {
        this.configurerProvider = Objects.requireNonNull(configurerProvider, "SecurityConfigurerProvider cannot be null");
    }

    /**
     * 제공된 모든 FlowContext에 대해 SecurityConfigurer들을 순서대로 초기화하고 적용합니다.
     * @param flows 처리할 모든 FlowContext 리스트
     * @param platformContext 플랫폼 전역 컨텍스트
     * @param platformConfig 플랫폼 전역 설정 (FlowContext 내부의 config와 다를 수 있음)
     * @throws Exception 설정 적용 중 발생할 수 있는 예외
     */
    public void applyConfigurations(
            List<FlowContext> flows,
            PlatformContext platformContext,
            PlatformConfig platformConfig) throws Exception {

        Objects.requireNonNull(flows, "Flows list cannot be null");
        Objects.requireNonNull(platformContext, "PlatformContext cannot be null");
        Objects.requireNonNull(platformConfig, "PlatformConfig cannot be null");

        log.info("SecurityConfigurerOrchestrator: Starting to apply configurations for {} flows.", flows.size());

        // 1. 모든 전역 SecurityConfigurer의 init() 호출 (애플리케이션 시작 시 1회)
        // 이 Configurer 들은 특정 Flow에 종속되지 않는 전역 설정을 담당 (예: AsepConfigurer의 기본 설정 로드)
        List<SecurityConfigurer> globalConfigurers = configurerProvider.getGlobalConfigurers(platformContext, platformConfig);
        if (globalConfigurers == null) {
            globalConfigurers = Collections.emptyList();
        }
        log.debug("SecurityConfigurerOrchestrator: Initializing {} global configurers.", globalConfigurers.size());
        globalConfigurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try {
                        log.trace("SecurityConfigurerOrchestrator: Initializing global configurer: {}", cfg.getClass().getSimpleName());
                        cfg.init(platformContext, platformConfig);
                    } catch (Exception e) {
                        log.error("SecurityConfigurerOrchestrator: Error during global SecurityConfigurer initialization: {}", cfg.getClass().getSimpleName(), e);
                        throw new RuntimeException("Error during global SecurityConfigurer initialization: " + cfg.getClass().getSimpleName(), e);
                    }
                });

        // 2. 각 FlowContext (즉, 각 HttpSecurity 인스턴스) 별로 Configurer 구성 적용
        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null");
            Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null");
            Objects.requireNonNull(fc.http(), "HttpSecurity in FlowContext cannot be null");

            log.debug("SecurityConfigurerOrchestrator: Applying configurations for flow: {}", fc.flow().getTypeName());
            platformContext.share(FlowContext.class, fc); // 현재 처리 중인 FlowContext를 플랫폼 컨텍스트에 공유 (필요시)

            // 현재 Flow의 HttpSecurity에 적용될 Configurer 리스트 가져오기
            // (전역 Configurer + 현재 Flow에 특화된 Configurer - 예: DSL을 통해 커스터마이징된 AsepConfigurer)
            List<SecurityConfigurer> flowSpecificConfigurers = configurerProvider.getFlowSpecificConfigurers(platformContext, platformConfig, fc.http());
            if (flowSpecificConfigurers == null) {
                flowSpecificConfigurers = Collections.emptyList();
            }

            // 전역 Configurer와 Flow 특화 Configurer를 합치고 중복 제거 후 정렬 (선택적)
            // 여기서는 Provider가 이미 적절한 리스트를 반환한다고 가정하고 flowSpecificConfigurers만 사용.
            // 또는, globalConfigurers와 flowSpecificConfigurers를 합쳐서 고유한 Configurer 리스트를 만들고 정렬.
            List<SecurityConfigurer> finalConfigurersForFlow = Stream.concat(globalConfigurers.stream(), flowSpecificConfigurers.stream())
                    .distinct() // 동일 인스턴스 중복 제거
                    .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                    .toList();


            log.debug("SecurityConfigurerOrchestrator: Configuring flow {} with {} configurers: {}",
                    fc.flow().getTypeName(), finalConfigurersForFlow.size(),
                    finalConfigurersForFlow.stream().map(cfg -> cfg.getClass().getSimpleName()).collect(Collectors.toList()));

            for (SecurityConfigurer cfg : finalConfigurersForFlow) {
                try {
                    // cfg.init(platformContext, platformConfig); // init은 이미 전역적으로 호출했으므로 여기서는 configure만
                    // 만약 Configurer가 FlowContext 별로 다른 init 로직이 필요하다면, init 시그니처 변경 또는 다른 init 메소드 필요.
                    // 현재 SecurityConfigurer 인터페이스의 init은 PlatformContext만 받음.
                    // 여기서는 configure만 호출.
                    log.trace("SecurityConfigurerOrchestrator: Configuring flow {} with configurer: {}",
                            fc.flow().getTypeName(), cfg.getClass().getSimpleName());
                    cfg.configure(fc);
                } catch (Exception e) {
                    String errorMessage = String.format(
                            "SecurityConfigurerOrchestrator: Error applying SecurityConfigurer '%s' for flow '%s'.",
                            cfg.getClass().getSimpleName(), fc.flow().getTypeName()
                    );
                    log.error(errorMessage, e);
                    throw new RuntimeException(errorMessage, e);
                }
            }
            log.info("SecurityConfigurerOrchestrator: Successfully applied all configurers for flow: {}", fc.flow().getTypeName());
        }
        log.info("SecurityConfigurerOrchestrator: All configurations applied successfully for {} flows.", flows.size());
    }
}
