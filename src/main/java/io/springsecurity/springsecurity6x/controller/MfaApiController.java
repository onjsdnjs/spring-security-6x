package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaApiController {

    private final ContextPersistence contextPersistence;
    private final MfaStateMachineService stateMachineService;

    @PostMapping("/select-factor")
    public ResponseEntity<?> selectFactor(@RequestBody Map<String, String> request,
                                          HttpServletRequest httpRequest) {
        String factorType = request.get("factor");

        FactorContext ctx = contextPersistence.contextLoad(httpRequest);
        if (ctx == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid MFA session"));
        }

        try {
            // 상태 머신으로 팩터 선택 이벤트 전송
            // 팩터 정보는 메시지 헤더로 전달
            MfaEvent event = MfaEvent.FACTOR_SELECTED;

            // 이벤트와 함께 선택된 팩터 정보 전달
            boolean accepted = stateMachineService.sendEvent(
                    MessageBuilder
                            .withPayload(event)
                            .setHeader("selectedFactor", factorType)
                            .setHeader("sessionId", ctx.getMfaSessionId())
                            .build(),
                    ctx,
                    httpRequest
            );

            if (accepted) {
                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "Factor selected successfully",
                        "nextStep", determineNextStep(ctx)
                ));
            } else {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid state for factor selection"));
            }

        } catch (Exception e) {
            log.error("Error selecting factor for session: {}", ctx.getMfaSessionId(), e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to select factor"));
        }
    }

    @PostMapping("/cancel")
    public ResponseEntity<?> cancelMfa(HttpServletRequest httpRequest) {
        FactorContext ctx = contextPersistence.contextLoad(httpRequest);
        if (ctx == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid MFA session"));
        }

        try {
            // 취소 이벤트 전송
            boolean accepted = stateMachineService.sendEvent(
                    MfaEvent.USER_ABORTED_MFA, ctx, httpRequest
            );

            if (accepted) {
                return ResponseEntity.ok(Map.of(
                        "status", "cancelled",
                        "message", "MFA cancelled successfully"
                ));
            } else {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Cannot cancel MFA in current state"));
            }

        } catch (Exception e) {
            log.error("Error cancelling MFA for session: {}", ctx.getMfaSessionId(), e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to cancel MFA"));
        }
    }

    private String determineNextStep(FactorContext ctx) {
        // 현재 상태에 따른 다음 단계 URL 결정
        AuthType currentFactor = ctx.getCurrentProcessingFactor();
        if (currentFactor == null) {
            return "/mfa/select-factor";
        }

        switch (currentFactor) {
            case OTT:
                return "/mfa/ott/request-code";
            case PASSKEY:
                return "/mfa/passkey/challenge";
            default:
                return "/mfa/select-factor";
        }
    }
}