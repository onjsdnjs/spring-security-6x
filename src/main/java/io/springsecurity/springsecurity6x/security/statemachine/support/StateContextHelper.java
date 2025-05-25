package io.springsecurity.springsecurity6x.security.statemachine.support;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * State Machine Context와 FactorContext 간의 변환을 담당하는 헬퍼 클래스
 * - 효율적인 직렬화/역직렬화
 * - 타입 안전성 보장
 * - 메모리 최적화
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateContextHelper {

    private final ContextPersistence contextPersistence;

    // 직렬화 최적화를 위한 캐시
    private final Map<Class<?>, Map<String, java.lang.reflect.Field>> fieldCache = new ConcurrentHashMap<>();

    /**
     * StateContext에서 FactorContext 추출 (최적화)
     */
    public FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 1. 직접 저장된 FactorContext 확인
        Object storedContext = variables.get("factorContext");
        if (storedContext instanceof FactorContext) {
            return (FactorContext) storedContext;
        }

        // 2. 압축된 FactorContext 확인
        Object compressedContext = variables.get("factorContext_compressed");
        if (compressedContext instanceof byte[]) {
            try {
                return decompressFactorContext((byte[]) compressedContext);
            } catch (Exception e) {
                log.error("Failed to decompress FactorContext", e);
            }
        }

        // 3. 개별 변수들로부터 재구성
        return reconstructFactorContext(variables, context);
    }

    /**
     * FactorContext를 StateContext에 저장 (최적화)
     */
    public void saveFactorContext(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 크기에 따라 압축 여부 결정
        try {
            byte[] serialized = serializeFactorContext(factorContext);

            if (serialized.length > 1024) { // 1KB 이상이면 압축
                byte[] compressed = compressFactorContext(factorContext);
                variables.put("factorContext_compressed", compressed);
                log.debug("FactorContext compressed from {} to {} bytes", serialized.length, compressed.length);
            } else {
                // 핵심 필드만 저장
                saveEssentialFields(variables, factorContext);
            }
        } catch (Exception e) {
            log.error("Failed to save FactorContext", e);
            // Fallback: 기본 필드만 저장
            saveBasicFields(variables, factorContext);
        }
    }

    /**
     * FactorContext 재구성
     */
    private FactorContext reconstructFactorContext(Map<Object, Object> variables,
                                                   StateContext<MfaState, MfaEvent> context) {
        String mfaSessionId = (String) variables.get("mfaSessionId");
        if (mfaSessionId == null) {
            throw new IllegalStateException("MFA session ID not found in state context");
        }

        // Authentication 복원
        Authentication authentication = extractAuthentication(context, mfaSessionId);
        if (authentication == null) {
            throw new IllegalStateException("Authentication not found for session: " + mfaSessionId);
        }

        // State 복원
        MfaState currentState = extractCurrentState(variables);
        String flowTypeName = (String) variables.getOrDefault("flowTypeName", "mfa");

        // FactorContext 생성
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                currentState,
                flowTypeName
        );

        // 추가 필드 복원
        restoreAdditionalFields(factorContext, variables);

        return factorContext;
    }

    /**
     * 핵심 필드만 저장 (메모리 최적화)
     */
    private void saveEssentialFields(Map<Object, Object> variables, FactorContext factorContext) {
        // 필수 필드
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("currentState", factorContext.getCurrentState());
        variables.put("flowTypeName", factorContext.getFlowTypeName());
        variables.put("username", factorContext.getUsername());
        variables.put("version", factorContext.getVersion().get());

        // 현재 처리 정보
        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put("currentFactorType", factorContext.getCurrentProcessingFactor().name());
        }
        if (factorContext.getCurrentStepId() != null) {
            variables.put("currentStepId", factorContext.getCurrentStepId());
        }

        // 상태 정보
        variables.put("retryCount", factorContext.getRetryCount());
        variables.put("mfaRequired", factorContext.isMfaRequiredAsPerPolicy());

        // 완료된 팩터 (압축된 형태로)
        if (!factorContext.getCompletedFactors().isEmpty()) {
            variables.put("completedFactors", serializeCompletedFactors(factorContext.getCompletedFactors()));
        }

        // 중요한 속성들
        saveImportantAttributes(variables, factorContext);
    }

    /**
     * 기본 필드만 저장 (Fallback)
     */
    private void saveBasicFields(Map<Object, Object> variables, FactorContext factorContext) {
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("currentState", factorContext.getCurrentState().name());
        variables.put("username", factorContext.getUsername());
        variables.put("flowTypeName", factorContext.getFlowTypeName());
    }

    /**
     * 중요한 속성 저장
     */
    private void saveImportantAttributes(Map<Object, Object> variables, FactorContext factorContext) {
        // 디바이스 ID
        Object deviceId = factorContext.getAttribute("deviceId");
        if (deviceId != null) {
            variables.put("attr_deviceId", deviceId);
        }

        // 타임스탬프
        variables.put("createdAt", factorContext.getCreatedAt());
        Object lastActivity = factorContext.getAttribute("lastActivityTimestamp");
        if (lastActivity != null) {
            variables.put("attr_lastActivityTimestamp", lastActivity);
        }
    }

    /**
     * 추가 필드 복원
     */
    private void restoreAdditionalFields(FactorContext factorContext, Map<Object, Object> variables) {
        // 버전
        Object version = variables.get("version");
        if (version instanceof Integer) {
            factorContext.getVersion().set((Integer) version);
        }

        // 현재 처리 정보
        String currentFactorType = (String) variables.get("currentFactorType");
        if (currentFactorType != null) {
            try {
                factorContext.setCurrentProcessingFactor(AuthType.valueOf(currentFactorType));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid currentFactorType: {}", currentFactorType);
            }
        }

        factorContext.setCurrentStepId((String) variables.get("currentStepId"));

        // 재시도 횟수
        Object retryCount = variables.get("retryCount");
        if (retryCount instanceof Integer) {
            factorContext.setRetryCount((Integer) retryCount);
        }

        // MFA 필요 여부
        Object mfaRequired = variables.get("mfaRequired");
        if (mfaRequired instanceof Boolean) {
            factorContext.setMfaRequiredAsPerPolicy((Boolean) mfaRequired);
        }

        // 완료된 팩터
        restoreCompletedFactors(factorContext, variables);

        // 속성 복원
        restoreAttributes(factorContext, variables);
    }

    /**
     * Authentication 추출 (최적화)
     */
    private Authentication extractAuthentication(StateContext<MfaState, MfaEvent> context, String mfaSessionId) {
        Map<Object, Object> variables = context.getExtendedState().getVariables();

        // 1. 저장된 Authentication
        Object storedAuth = variables.get("primaryAuthentication");
        if (storedAuth instanceof Authentication) {
            return (Authentication) storedAuth;
        }

        // 2. 메시지 헤더에서 확인
        Object authHeader = context.getMessageHeader("authentication");
        if (authHeader instanceof Authentication) {
            return (Authentication) authHeader;
        }

        // 3. ContextPersistence에서 로드
        HttpServletRequest request = extractHttpServletRequest(context);
        if (request != null) {
            try {
                FactorContext persistedContext = contextPersistence.loadContext(mfaSessionId, request);
                if (persistedContext != null && persistedContext.getPrimaryAuthentication() != null) {
                    return persistedContext.getPrimaryAuthentication();
                }
            } catch (Exception e) {
                log.warn("Failed to load authentication from persistence", e);
            }
        }

        return null;
    }

    /**
     * 완료된 팩터 복원
     */
    private void restoreCompletedFactors(FactorContext factorContext, Map<Object, Object> variables) {
        Object completedFactorsObj = variables.get("completedFactors");

        if (completedFactorsObj instanceof String) {
            List<AuthenticationStepConfig> configs = parseCompletedFactors(
                    (String) completedFactorsObj, factorContext.getFlowTypeName()
            );
            factorContext.getCompletedFactors().clear();
            factorContext.getCompletedFactors().addAll(configs);
        }
    }

    /**
     * 속성 복원
     */
    private void restoreAttributes(FactorContext factorContext, Map<Object, Object> variables) {
        variables.entrySet().stream()
                .filter(entry -> entry.getKey().toString().startsWith("attr_"))
                .forEach(entry -> {
                    String key = entry.getKey().toString().substring(5);
                    factorContext.setAttribute(key, entry.getValue());
                });
    }

    /**
     * 현재 상태 추출
     */
    private MfaState extractCurrentState(Map<Object, Object> variables) {
        Object currentStateObj = variables.get("currentState");

        if (currentStateObj instanceof MfaState) {
            return (MfaState) currentStateObj;
        } else if (currentStateObj instanceof String) {
            try {
                return MfaState.valueOf((String) currentStateObj);
            } catch (IllegalArgumentException e) {
                log.error("Invalid state: {}", currentStateObj);
                return MfaState.NONE;
            }
        }

        return MfaState.NONE;
    }

    /**
     * HttpServletRequest 추출
     */
    private HttpServletRequest extractHttpServletRequest(StateContext<MfaState, MfaEvent> context) {
        Object request = context.getMessageHeader("request");
        return request instanceof HttpServletRequest ? (HttpServletRequest) request : null;
    }

    /**
     * 완료된 팩터 직렬화
     */
    private String serializeCompletedFactors(List<AuthenticationStepConfig> completedFactors) {
        return completedFactors.stream()
                .map(config -> String.format("%s:%s:%d",
                        config.getStepId(),
                        config.getType(),
                        config.getOrder()))
                .collect(Collectors.joining(","));
    }

    /**
     * 완료된 팩터 파싱
     */
    private List<AuthenticationStepConfig> parseCompletedFactors(String completedFactorsStr, String flowTypeName) {
        if (completedFactorsStr == null || completedFactorsStr.isEmpty()) {
            return new ArrayList<>();
        }

        return Arrays.stream(completedFactorsStr.split(","))
                .filter(s -> !s.isEmpty())
                .map(factorStr -> {
                    String[] parts = factorStr.split(":");
                    if (parts.length >= 2) {
                        AuthenticationStepConfig config = new AuthenticationStepConfig();
                        config.setStepId(parts[0]);
                        config.setType(parts[1]);
                        config.setOrder(parts.length > 2 ? Integer.parseInt(parts[2]) : 1);
                        config.setRequired(true);
                        return config;
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * FactorContext 직렬화
     */
    private byte[] serializeFactorContext(FactorContext factorContext) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(factorContext);
            return baos.toByteArray();
        }
    }

    /**
     * FactorContext 압축
     */
    private byte[] compressFactorContext(FactorContext factorContext) throws IOException {
        byte[] serialized = serializeFactorContext(factorContext);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(baos)) {
            gzip.write(serialized);
            gzip.finish();
            return baos.toByteArray();
        }
    }

    /**
     * FactorContext 압축 해제
     */
    private FactorContext decompressFactorContext(byte[] compressed) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
             java.util.zip.GZIPInputStream gzip = new java.util.zip.GZIPInputStream(bais);
             ObjectInputStream ois = new ObjectInputStream(gzip)) {
            return (FactorContext) ois.readObject();
        }
    }
}