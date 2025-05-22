package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationSuccessHandler; // 기존 핸들러 사용
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
@Component("finalizeMfaSuccessAction") // 빈 이름 명시
@RequiredArgsConstructor
public class FinalizeMfaSuccessAction implements MfaAction {

    private final ContextPersistence contextPersistence;
    private final ApplicationContext applicationContext; // UnifiedAuthenticationSuccessHandler 빈 가져오기

    @Override
    public void execute(MfaProcessingContext context) throws IOException, ServletException {
        FactorContext factorContext = context.getFactorContext();
        HttpServletRequest request = context.getRequest();
        HttpServletResponse response = context.getResponse();
        Authentication primaryAuthentication = factorContext.getPrimaryAuthentication(); // 1차 인증 정보 사용

        Assert.notNull(factorContext, "FactorContext cannot be null");
        Assert.notNull(request, "HttpServletRequest cannot be null");
        Assert.notNull(response, "HttpServletResponse cannot be null");
        Assert.notNull(primaryAuthentication, "PrimaryAuthentication from FactorContext cannot be null");

        log.info("FinalizeMfaSuccessAction: MFA process fully completed for user '{}'. Invoking final success handler.",
                factorContext.getUsername());

        // 최종 성공 핸들러 (UnifiedAuthenticationSuccessHandler 또는 flowConfig에 지정된 핸들러) 호출
        AuthenticationSuccessHandler finalSuccessHandler = context.getFlowConfig().getFinalSuccessHandler();
        if (finalSuccessHandler == null) {
            try {
                finalSuccessHandler = applicationContext.getBean(UnifiedAuthenticationSuccessHandler.class);
                log.warn("No explicit finalSuccessHandler in flow config for '{}'. Using default UnifiedAuthenticationSuccessHandler bean.", context.getFlowConfig().getTypeName());
            } catch (Exception e) {
                log.error("CRITICAL: FinalSuccessHandler not configured for flow '{}' AND UnifiedAuthenticationSuccessHandler bean not found. Cannot finalize MFA success.",
                        context.getFlowConfig().getTypeName(), e);
                // 이 경우 심각한 설정 오류이므로, 적절한 오류 응답 처리 필요
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA success handling misconfigured.");
                return;
            }
        }

        log.debug("Invoking final success handler: {}", finalSuccessHandler.getClass().getSimpleName());
        finalSuccessHandler.onAuthenticationSuccess(request, response, primaryAuthentication);

        // MFA 컨텍스트 정리
        log.debug("Deleting FactorContext for user '{}' after successful MFA.", factorContext.getUsername());
        contextPersistence.deleteContext(request);
    }
}
