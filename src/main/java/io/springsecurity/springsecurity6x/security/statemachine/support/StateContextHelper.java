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

@Slf4j
@Component
@RequiredArgsConstructor
public class StateContextHelper {

    private final ContextPersistence contextPersistence;

    // 직렬화 최적화를 위한 캐시
    private final Map<Class<?>, Map<String, java.lang.reflect.Field>> fieldCache = new ConcurrentHashMap<>();

    // 변경 추적을 위한 델타 트래커
    private final Map<String, DeltaTracker> deltaTrackers = new ConcurrentHashMap<>();

    /**
     * 델타 추적 클래스
     */
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

        // 3. 델타 정보가 있는지 확인
        String sessionId = (String) variables.get("mfaSessionId");
        if (sessionId != null) {
            DeltaTracker tracker = deltaTrackers.get(sessionId);
            if (tracker != null && tracker.hasChanges()) {
                // 델타 정보로 업데이트
                return applyDelta(variables, tracker);
            }
        }

        // 4. 개별 변수들로부터 재구성
        return reconstructFactorContext(variables, context);
    }

    /**
     * FactorContext를 StateContext에 저장 (델타 방식)
     */
    public void saveFactorContext(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        ExtendedState extendedState = context.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        String sessionId = factorContext.getMfaSessionId();
        DeltaTracker tracker = deltaTrackers.computeIfAbsent(sessionId, k -> new DeltaTracker());

        // 현재 값들을 원본으로 추적
        trackCurrentValues(tracker, factorContext);

        // 크기에 따라 압축 여부 결정
        try {
            byte[] serialized = serializeFactorContext(factorContext);

            if (serialized.length > 1024) { // 1KB 이상이면 압축
                byte[] compressed = compressFactorContext(factorContext);
                variables.put("factorContext_compressed", compressed);
                log.debug("FactorContext compressed from {} to {} bytes", serialized.length, compressed.length);
            } else {
                // 변경된 필드만 저장
                saveChangedFields(variables, factorContext, tracker);
            }
        } catch (Exception e) {
            log.error("Failed to save FactorContext", e);
            // Fallback: 기본 필드만 저장
            saveBasicFields(variables, factorContext);
        }

        log.debug("Saved {} changed fields for session: {}",
                tracker.getChanges().size(), sessionId);
    }

    /**
     * 현재 값들을 원본으로 추적
     */
    private void trackCurrentValues(DeltaTracker tracker, FactorContext factorContext) {
        // 기본 필드들
        tracker.trackOriginal("currentState", factorContext.getCurrentState());
        tracker.trackOriginal("version", factorContext.getVersion());
        tracker.trackOriginal("retryCount", factorContext.getRetryCount());
        tracker.trackOriginal("lastError", factorContext.getLastError());

        // 현재 처리 정보
        tracker.trackOriginal("currentProcessingFactor", factorContext.getCurrentProcessingFactor());
        tracker.trackOriginal("currentStepId", factorContext.getCurrentStepId());

        // 완료된 팩터들 (해시값으로 추적)
        tracker.trackOriginal("completedFactorsHash",
                calculateCompletedFactorsHash(factorContext.getCompletedFactors()));
    }

    /**
     * 변경된 필드만 저장
     */
    private void saveChangedFields(Map<Object, Object> variables,
                                   FactorContext factorContext,
                                   DeltaTracker tracker) {
        // 필수 필드는 항상 저장
        variables.put("mfaSessionId", factorContext.getMfaSessionId());
        variables.put("username", factorContext.getUsername());
        variables.put("flowTypeName", factorContext.getFlowTypeName());

        // 변경 추적 및 저장
        trackAndSave(variables, tracker, "currentState", factorContext.getCurrentState());
        trackAndSave(variables, tracker, "version", factorContext.getVersion());
        trackAndSave(variables, tracker, "retryCount", factorContext.getRetryCount());
        trackAndSave(variables, tracker, "lastError", factorContext.getLastError());
        trackAndSave(variables, tracker, "mfaRequired", factorContext.isMfaRequiredAsPerPolicy());

        // 현재 처리 정보
        if (factorContext.getCurrentProcessingFactor() != null) {
            trackAndSave(variables, tracker, "currentFactorType",
                    factorContext.getCurrentProcessingFactor().name());
        }
        trackAndSave(variables, tracker, "currentStepId", factorContext.getCurrentStepId());

        // 완료된 팩터들 (변경된 경우만)
        String currentHash = calculateCompletedFactorsHash(factorContext.getCompletedFactors());
        if (!currentHash.equals(tracker.originalValues.get("completedFactorsHash"))) {
            variables.put("completedFactors", serializeCompletedFactors(factorContext.getCompletedFactors()));
            tracker.trackChange("completedFactorsHash", currentHash);
        }

        // 타임스탬프
        variables.put("lastModified", System.currentTimeMillis());
        variables.put("createdAt", factorContext.getCreatedAt());

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
     * 값 변경 추적 및 저장
     */
    private void trackAndSave(Map<Object, Object> variables, DeltaTracker tracker,
                              String key, Object value) {
        tracker.trackChange(key, value);
        if (value != null) {
            variables.put(key, value);
        } else {
            variables.remove(key);
            tracker.trackDeletion(key);
        }
    }

    /**
     * 델타 정보 적용
     */
    private FactorContext applyDelta(Map<Object, Object> variables, DeltaTracker tracker) {
        // 기존 컨텍스트 로드
        String sessionId = (String) variables.get("mfaSessionId");
        FactorContext context = loadStoredContext(sessionId);

        if (context == null) {
            // 새로 생성
            return reconstructFactorContext(variables, null);
        }

        // 변경사항 적용
        Map<String, Object> changes = tracker.getChanges();

        // 상태 업데이트
        if (changes.containsKey("currentState")) {
            context.changeState((MfaState) changes.get("currentState"));
        }

        // 버전 업데이트
        if (changes.containsKey("version")) {
            // 버전은 AtomicInteger이므로 직접 설정 불가, 대신 증가
            int targetVersion = (Integer) changes.get("version");
            while (context.getVersion().get() < targetVersion) {
                context.incrementVersion();
            }
        }

        // 기타 필드 업데이트
        applyFieldChanges(context, changes);

        return context;
    }

    /**
     * 필드 변경사항 적용
     */
    private void applyFieldChanges(FactorContext context, Map<String, Object> changes) {
        changes.forEach((key, value) -> {
            switch (key) {
                case "retryCount":
                    context.setRetryCount((Integer) value);
                    break;
                case "lastError":
                    context.setLastError((String) value);
                    break;
                case "currentFactorType":
                    context.setCurrentProcessingFactor(AuthType.valueOf((String) value));
                    break;
                case "currentStepId":
                    context.setCurrentStepId((String) value);
                    break;
                case "mfaRequired":
                    context.setMfaRequiredAsPerPolicy((Boolean) value);
                    break;
                // 기타 필드들...
            }
        });
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
     * 추가 필드 복원
     */
    private void restoreAdditionalFields(FactorContext factorContext, Map<Object, Object> variables) {
        // 버전
        Object version = variables.get("version");
        if (version instanceof Integer) {
            // 버전은 AtomicInteger이므로 직접 설정 불가, 대신 증가
            int targetVersion = (Integer) version;
            while (factorContext.getVersion().get() < targetVersion) {
                factorContext.incrementVersion();
            }
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
        if (context == null) {
            return null;
        }

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
                    String key = entry.getKey().toString().substring(5); // "attr_" 제거
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
     * 완료된 팩터 해시 계산
     */
    private String calculateCompletedFactorsHash(List<AuthenticationStepConfig> completedFactors) {
        if (completedFactors == null || completedFactors.isEmpty()) {
            return "EMPTY";
        }

        String concatenated = completedFactors.stream()
                .map(config -> config.getStepId() + ":" + config.getType() + ":" + config.getOrder())
                .sorted()
                .collect(Collectors.joining(","));

        return Integer.toHexString(concatenated.hashCode());
    }

    /**
     * 저장된 컨텍스트 로드
     */
    private FactorContext loadStoredContext(String sessionId) {
        try {
            HttpServletRequest request = null; // 현재 요청 컨텍스트에서 가져와야 함
            return contextPersistence.loadContext(sessionId, request);
        } catch (Exception e) {
            log.warn("Failed to load stored context for session: {}", sessionId, e);
            return null;
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
     * 압축 여부 확인
     */
    private boolean isCompressed(String data) {
        return data != null && data.startsWith("GZIP:");
    }

    /**
     * 델타 트래커 정리
     */
    public void clearDeltaTracker(String sessionId) {
        deltaTrackers.remove(sessionId);
    }
}