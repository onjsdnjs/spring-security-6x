package io.springsecurity.springsecurity6x.security.mfa.statemachine.action;

import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler; // 기존 핸들러 재활용
import io.springsecurity.springsecurity6x.security.mfa.statemachine.MfaProcessingContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext; // MfaContinuationHandler 빈 가져오기
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;

@Slf4j
@Component("redirectToFactorSelectionAction") // 빈 이름 명시
@RequiredArgsConstructor
public class RedirectToFactorSelectionAction implements MfaAction {

    // MfaContinuationHandler를 직접 주입받거나 ApplicationContext에서 getBean으로 가져옴
    // 여기서는 getBean 방식을 유지 (생성자 주입이 더 권장됨)
    private final ApplicationContext applicationContext;

    private MfaContinuationHandler getMfaContinuationHandler() {
        return applicationContext.getBean(MfaContinuationHandler.class);
    }

    @Override
    public void execute(MfaProcessingContext context) throws IOException, ServletException {
        HttpServletRequest request = context.getRequest();
        HttpServletResponse response = context.getResponse();

        Assert.notNull(request, "HttpServletRequest cannot be null");
        Assert.notNull(response, "HttpServletResponse cannot be null");
        Assert.notNull(context.getFactorContext(), "FactorContext cannot be null");
        Assert.notNull(context.getFlowConfig(), "AuthenticationFlowConfig cannot be null");

        log.info("RedirectToFactorSelectionAction: Redirecting user '{}' to factor selection for flow '{}'. Current state: {}",
                context.getFactorContext().getUsername(),
                context.getFlowConfig().getTypeName(),
                context.getFactorContext().getCurrentState());

        // 기존 MfaContinuationHandler의 로직 중 팩터 선택 UI로 보내는 부분을 호출하거나 재구현
        // MfaContinuationHandler.handle() 메소드는 더 많은 일을 하므로,
        // UI 렌더링/리디렉션만 담당하는 별도 메소드가 MfaContinuationHandler에 있거나,
        // 여기서 직접 리디렉션 URL을 구성하여 response.sendRedirect() 호출.
        // 여기서는 MfaContinuationHandler.handle을 호출하여 다음 단계를 결정하도록 위임한다고 가정.
        // 이 때, justCompletedFactorType은 null이거나 이전 단계를 나타낼 수 있음.
        // MfaContinuationHandler가 MfaState.AWAITING_FACTOR_SELECTION 상태를 보고 적절한 UI로 안내할 것임.
        getMfaContinuationHandler().continueMfaFlow(
                request,
                response,
                context.getFactorContext().getPrimaryAuthentication(), // 또는 context.getCurrentAuthentication()
                context.getFactorContext(),
                context.getFlowConfig(),
                null // 이전 완료 팩터가 없거나, 선택 UI로 가는 것이므로 null
        );
    }
}
