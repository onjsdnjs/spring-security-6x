package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import io.springsecurity.springsecurity6x.security.core.adapter.StateAdapter;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.statemachine.config.MfaStateMachineConfiguration;
import io.springsecurity.springsecurity6x.security.statemachine.core.MfaStateMachineService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * State Machine을 플랫폼의 StateAdapter로 통합하는 Feature
 * ServiceLoader를 통해 자동으로 로드됨
 */
@Slf4j
public class MfaStateMachineFeature implements StateAdapter {

    @Override
    public String getId() {
        return "mfa-state-machine";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext context) {
        log.info("Applying MFA State Machine feature to HttpSecurity");

        try {
            // ApplicationContext에서 필요한 빈들 가져오기
            var appContext = context.applicationContext();

            // State Machine 서비스를 SharedObject로 등록
            MfaStateMachineService stateMachineService = appContext.getBean(MfaStateMachineService.class);
            http.setSharedObject(MfaStateMachineService.class, stateMachineService);

            // State Machine Configuration도 공유
            MfaStateMachineConfiguration stateMachineConfig = appContext.getBean(MfaStateMachineConfiguration.class);
            http.setSharedObject(MfaStateMachineConfiguration.class, stateMachineConfig);

            log.info("MFA State Machine components registered as HttpSecurity shared objects");

        } catch (Exception e) {
            log.error("Failed to apply MFA State Machine feature: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to configure MFA State Machine", e);
        }
    }
}