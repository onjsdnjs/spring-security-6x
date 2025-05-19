package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;

import java.util.Comparator;
import java.util.List;

public class SecurityConfigurerOrchestrator {

    private final SecurityConfigurerProvider configurerProvider;

    public SecurityConfigurerOrchestrator(SecurityConfigurerProvider configurerProvider) {
        this.configurerProvider = configurerProvider;
    }

    public void applyConfigurations(List<FlowContext> flows, PlatformContext platformContext, PlatformConfig platformConfig) throws Exception {

        List<SecurityConfigurer> configurers = configurerProvider.getConfigurers(platformContext, platformConfig);

        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try {
                        cfg.init(platformContext, platformConfig);
                    } catch (Exception e) { // init 과정에서 발생할 수 있는 예외 처리
                        // 로깅 또는 적절한 예외 전파
                        throw new RuntimeException("SecurityConfigurer 초기화 중 오류 발생: " + cfg.getClass().getSimpleName(), e);
                    }
                });

        // Flow별 구성 적용
        List<SecurityConfigurer> sortedConfigurers = configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .toList();

        for (FlowContext fc : flows) { // Flow를 외부 루프로 변경하여 각 Flow에 대해 모든 Configurer를 순서대로 적용
            platformContext.share(FlowContext.class, fc); // 각 Flow 처리 전에 FlowContext 공유 (필요시)
            for (SecurityConfigurer cfg : sortedConfigurers) {
                try {
                    cfg.configure(fc);
                } catch (Exception e) {
                    // 로깅 또는 적절한 예외 전파
                    // 특정 Flow의 특정 Configurer 에서 오류 발생 시 어떻게 처리할지 정책 필요
                    throw new RuntimeException(
                            "Flow '" + fc.flow().getTypeName() + "' 구성 중 SecurityConfigurer '" +
                                    cfg.getClass().getSimpleName() + "' 적용 오류 발생", e);
                }
            }
        }
    }
}
