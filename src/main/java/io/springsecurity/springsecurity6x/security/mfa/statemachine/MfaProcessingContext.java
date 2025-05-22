package io.springsecurity.springsecurity6x.security.mfa.statemachine;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import java.util.Map;

@Getter
@Builder(toBuilder = true) // toBuilder=true를 통해 불변 객체를 쉽게 복사 및 수정
public class MfaProcessingContext {
    private final FactorContext factorContext;
    private final AuthenticationFlowConfig flowConfig;
    private final MfaEvent event;
    @Nullable private final MfaEventPayload payload; // 이벤트 페이로드
    @Nullable private final Authentication currentAuthentication;
    @Nullable private final HttpServletRequest request;
    @Nullable private final HttpServletResponse response;
    // 상태 머신 자체에 접근해야 하는 경우 (예: 액션 내부에서 다른 이벤트 발생)
    // 이 부분은 상태 머신 실행기(engine)가 컨텍스트에 주입해 줄 수 있음
    @Nullable private final Object stateMachine; // 타입은 실제 상태 머신 객체로 (여기서는 Object로 단순화)
    // 추가적인 공유 데이터 (스프링 상태 머신의 Message Headers 또는 ExtendedState.variables 벤치마킹)
    @Nullable private final Map<String, Object> variables;
}