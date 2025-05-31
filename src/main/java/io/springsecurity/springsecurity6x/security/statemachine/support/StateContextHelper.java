package io.springsecurity.springsecurity6x.security.statemachine.support;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.adapter.FactorContextStateAdapter;
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
 * 완전 일원화된 StateContextHelper
 * - ContextPersistence 완전 제거
 * - FactorContextStateAdapter 사용으로 통일
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StateContextHelper {

    // ContextPersistence 완전 제거
    private final FactorContextStateAdapter factorContextAdapter;

    // 직렬화 최적화를 위한 캐시
    private final Map<Class<?>, Map<String, java.lang.reflect.Field>> fieldCache = new ConcurrentHashMap<>();

    // 변경 추적을 위한 델타 트래커
    private final Map<String, DeltaTracker> deltaTrackers = new ConcurrentHashMap<>();

    /**
     * StateContext 에서 FactorContext 추출 (완전 일원화)
     */
    public FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        try {
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

            // 3. 어댑터를 통한 재구성 (일원화)
            return reconstructFromStateContext(context);

        } catch (Exception e) {
            log.error("Failed to extract FactorContext from StateContext", e);
            return createEmptyFactorContext(variables);
        }
    }

    /**
     * FactorContext를 StateContext에 저장 (어댑터 사용)
     */
    public void saveFactorContext(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        try {
            // 어댑터를 통한 변환 (일원화)
            Map<Object, Object> adapterVariables = factorContextAdapter.toStateMachineVariables(factorContext);

            // 기존 변수 업데이트
            variables.putAll(adapterVariables);

            // 메타데이터 추가
            variables.put("_lastSaved", System.currentTimeMillis());
            variables.put("_saveMethod", "STATE_CONTEXT_HELPER");

            log.debug("FactorContext saved to StateContext via adapter: sessionId={}, variables={}",
                    factorContext.getMfaSessionId(), adapterVariables.size());

        } catch (Exception e) {
            log.error("Failed to save FactorContext to StateContext", e);
            // Fallback: 기본 필드만 저장
            saveBasicFields(variables, factorContext);
        }
    }

    /**
     * StateContext 에서 FactorContext 재구성 (어댑터 사용)
     */
    private FactorContext reconstructFromStateContext(StateContext<MfaState, MfaEvent> context) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        // 필수 정보 추출
        String mfaSessionId = (String) variables.get("mfaSessionId");
        if (mfaSessionId == null) {
            throw new IllegalStateException("MFA session ID not found in state context");
        }

        // Authentication 추출
        Authentication authentication = extractAuthentication(context);
        if (authentication == null) {
            throw new IllegalStateException("Authentication not found for session: " + mfaSessionId);
        }

        // State 추출
        MfaState currentState = context.getTarget() != null ?
                context.getTarget().getId() : MfaState.NONE;

        String flowTypeName = (String) variables.getOrDefault("flowTypeName", "mfa");

        // FactorContext 생성
        FactorContext factorContext = new FactorContext(
                mfaSessionId,
                authentication,
                currentState,
                flowTypeName
        );

        // 어댑터를 통한 추가 필드 복원
        factorContextAdapter.updateFactorContext(context, factorContext);

        return factorContext;
    }

    /**
     * Authentication 추출 (State Machine 일원화 방식)
     */
    private Authentication extractAuthentication(StateContext<MfaState, MfaEvent> context) {
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

        // 3. Context의 Source에서 추출
        if (context.getSource() != null) {
            Object sourceAuth = context.getExtendedState().getVariables().get("authentication");
            if (sourceAuth instanceof Authentication) {
                return (Authentication) sourceAuth;
            }
        }

        log.warn("Authentication not found in StateContext");
        return null;
    }

    /**
     * 빈 FactorContext 생성 (Fallback)
     */
    private FactorContext createEmptyFactorContext(Map<Object, Object> variables) {
        String sessionId = (String) variables.getOrDefault("mfaSessionId", "unknown-" + System.currentTimeMillis());

        // 더미 Authentication 생성
        Authentication dummyAuth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "unknown", null, Collections.emptyList());

        return new FactorContext(sessionId, dummyAuth, MfaState.NONE, "mfa");
    }

    /**
     * 기본 필드만 저장 (Fallback)
     */
    private void saveBasicFields(Map<Object, Object> variables, FactorContext factorContext) {
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("currentState", factorContext.getCurrentState().name());
        variables.put("username", factorContext.getUsername());
        variables.put("flowTypeName", factorContext.getFlowTypeName());
        variables.put("primaryAuthentication", factorContext.getPrimaryAuthentication());
        variables.put("version", factorContext.getVersion());
        variables.put("_fallbackSave", true);

        log.debug("Basic fields saved as fallback for session: {}", factorContext.getMfaSessionId());
    }

    // === 압축 관련 메서드들 (기존 유지) ===

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
     * 델타 트래커 정리
     */
    public void clearDeltaTracker(String sessionId) {
        deltaTrackers.remove(sessionId);
    }

    // === 기존 DeltaTracker 클래스 유지 ===
    private static class DeltaTracker {
        private final Map<String, Object> originalValues = new HashMap<>();
        private final Map<String, Object> changedFields = new HashMap<>();
        private final Set<String> deletedFields = new HashSet<>();

        public void trackOriginal(String field, Object value) {
            if (!originalValues.containsKey(field)) {
                originalValues.put(field, value);
            }
        }

        public void trackChange(String field, Object value) {
            Object original = originalValues.get(field);
            if (!Objects.equals(original, value)) {
                changedFields.put(field, value);
            }
        }

        public void trackDeletion(String field) {
            deletedFields.add(field);
            changedFields.remove(field);
        }

        public boolean hasChanges() {
            return !changedFields.isEmpty() || !deletedFields.isEmpty();
        }

        public Map<String, Object> getChanges() {
            return new HashMap<>(changedFields);
        }

        public Set<String> getDeletions() {
            return new HashSet<>(deletedFields);
        }

        public void reset() {
            changedFields.clear();
            deletedFields.clear();
        }
    }
}