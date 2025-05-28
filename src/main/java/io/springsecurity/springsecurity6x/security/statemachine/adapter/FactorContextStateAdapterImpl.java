package io.springsecurity.springsecurity6x.security.statemachine.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.StateMachine;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class FactorContextStateAdapterImpl implements FactorContextStateAdapter {

    private final ObjectMapper objectMapper; // JSON 직렬화/역직렬화를 위해 ObjectMapper 주입

    @Override
    public Map<Object, Object> toStateMachineVariables(FactorContext factorContext) {
        Map<Object, Object> variables = new HashMap<>();
        if (factorContext == null) {
            log.error("FactorContext is null in toStateMachineVariables");
            variables.put("_error", "null_factor_context");
            return variables;
        }

        putSafely(variables, "mfaSessionId", factorContext.getMfaSessionId(), "error_session_id");
        putSafely(variables, "username", factorContext.getUsername(), "error_username");
        putSafely(variables, "flowTypeName", factorContext.getFlowTypeName(), "mfa");
        putSafely(variables, "currentStateName", factorContext.getCurrentState() != null ? factorContext.getCurrentState().name() : MfaState.NONE.name(), MfaState.NONE.name());
        putSafely(variables, "version", factorContext.getVersion(), 0);

        if (factorContext.getPrimaryAuthentication() != null) {
            // Authentication 객체는 직접 저장하지 않고, 주요 정보만 추출하여 저장하거나,
            // FactorContext를 reconstruct할 때 SecurityContextHolder에서 가져오는 것을 고려.
            // 여기서는 예시로 principal 이름만 저장 (실제로는 더 많은 정보나 다른 방식 필요할 수 있음)
            variables.put("primaryAuthenticationPrincipalName", factorContext.getPrimaryAuthentication().getName());
            // 더 안전한 방법은 Authentication 객체를 외부에서 관리하고 ID만 참조하는 것입니다.
            // Spring Security의 기본 Authentication 객체들은 Serializable이지만, 커스텀 구현은 아닐 수 있습니다.
            // 여기서는 SM 변수에 직접 넣는 것을 유지하되, 직렬화 문제를 인지해야 합니다.
            variables.put("primaryAuthentication", factorContext.getPrimaryAuthentication());

        }

        if (factorContext.getCurrentProcessingFactor() != null) {
            variables.put("currentProcessingFactorName", factorContext.getCurrentProcessingFactor().name());
        }
        putSafely(variables, "currentStepId", factorContext.getCurrentStepId(), null);

        // currentFactorOptions는 직접 직렬화하지 않음. currentStepId로 조회하여 재구성.
        // putSafely(variables, "currentFactorOptionsSerialized", factorContext.getCurrentFactorOptions() != null ? serializeObjectToJson(factorContext.getCurrentFactorOptions()) : null, null);

        putSafely(variables, "retryCount", factorContext.getRetryCount(), 0);
        putSafely(variables, "lastError", factorContext.getLastError(), null);
        putSafely(variables, "mfaRequiredAsPerPolicy", factorContext.isMfaRequiredAsPerPolicy(), false);
        putSafely(variables, "createdAt", factorContext.getCreatedAt(), System.currentTimeMillis());
        if (factorContext.getLastActivityTimestamp() != null) {
            putSafely(variables, "lastActivityTimestamp", factorContext.getLastActivityTimestamp().toEpochMilli(), System.currentTimeMillis());
        }

        // Collections (CompletedFactors, RegisteredMfaFactors 등)
        // 이들은 FactorContext가 직접 관리하고, FactorContext 자체가 직렬화 대상이거나,
        // ResilientRedisStateMachinePersist처럼 필드별로 직렬화될 때 각 타입의 직렬화 방식에 따름.
        // 여기서는 toStateMachineVariables가 개별 필드로 분해하는 역할을 하므로, 주요 식별 정보 위주로 저장.
        putSafely(variables, "completedFactorStepIds",
                factorContext.getCompletedFactors().stream().map(AuthenticationStepConfig::getStepId).collect(Collectors.toList()),
                Collections.emptyList());

        putSafely(variables, "registeredMfaFactorNames",
                factorContext.getRegisteredMfaFactors().stream().map(AuthType::name).collect(Collectors.toList()),
                Collections.emptyList());


        // 사용자 정의 속성 (Serializable 값만 저장 시도)
        Map<String, Object> serializableAttributes = new HashMap<>();
        factorContext.getAttributes().forEach((key, value) -> {
            if (value instanceof java.io.Serializable) { // 기본 직렬화 가능 여부 체크
                serializableAttributes.put(key, value);
            } else if (value != null) {
                log.warn("Attribute '{}' of type {} is not Serializable, attempting JSON serialization for session: {}",
                        key, value.getClass().getName(), factorContext.getMfaSessionId());
                try {
                    String jsonValue = objectMapper.writeValueAsString(value);
                    serializableAttributes.put(key + "_json", jsonValue); // JSON 직렬화된 값 저장
                    serializableAttributes.put(key + "_json_type", value.getClass().getName()); // 원래 타입 저장
                } catch (JsonProcessingException e) {
                    log.error("Failed to serialize attribute '{}' to JSON for session: {}", key, factorContext.getMfaSessionId(), e);
                }
            }
        });
        variables.put("userAttributes", serializableAttributes);


        variables.put("_adapterVersion", "2.4_FIXED_OPTIONS_SERIALIZATION");
        return variables;
    }

    @Override
    public void updateFactorContext(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext factorContext) {
        ExtendedState extendedState = stateMachine.getExtendedState();
        Map<Object, Object> variables = extendedState.getVariables();

        if (stateMachine.getState() != null) {
            factorContext.changeState(stateMachine.getState().getId());
        } else {
            log.warn("StateMachine state is null during updateFactorContext for session {}. FactorContext state remains {}.",
                    factorContext.getMfaSessionId(), factorContext.getCurrentState());
        }
        updateFactorContextFromVariablesMap(factorContext, variables);
    }

    @Override
    public void updateFactorContext(StateContext<MfaState, MfaEvent> stateContext, FactorContext factorContext) {
        Map<Object, Object> variables = stateContext.getExtendedState().getVariables();
        if (stateContext.getTarget() != null) {
            factorContext.changeState(stateContext.getTarget().getId());
        }
        updateFactorContextFromVariablesMap(factorContext, variables);
    }

    @Override
    public FactorContext reconstructFromStateMachine(StateMachine<MfaState, MfaEvent> stateMachine) {
        ExtendedState extendedState = stateMachine.getExtendedState();
        if (extendedState == null) {
            log.error("ExtendedState is null for SM ID: {}. Cannot reconstruct FactorContext.", stateMachine.getId());
            return createDummyErrorContext(stateMachine.getId() != null ? stateMachine.getId() : "UnknownSession-NullExtendedState");
        }
        Map<Object, Object> variables = extendedState.getVariables();
        if (variables == null) {
            log.error("ExtendedState variables are null for SM ID: {}. Cannot reconstruct FactorContext.", stateMachine.getId());
            return createDummyErrorContext(stateMachine.getId() != null ? stateMachine.getId() : "UnknownSession-NullVariables");
        }


        String mfaSessionId = (String) variables.get("mfaSessionId");
        if (mfaSessionId == null) {
            mfaSessionId = stateMachine.getId(); // Fallback to SM ID
            if (mfaSessionId == null) {
                log.error("Cannot reconstruct FactorContext: mfaSessionId is missing and SM ID is null.");
                return createDummyErrorContext("UnknownSession-NoId");
            }
            log.warn("mfaSessionId missing in variables for SM ID: {}, using SM ID as session ID.", mfaSessionId);
        }

        Authentication authentication = (Authentication) variables.get("primaryAuthentication");
        if (authentication == null) {
            String principalName = (String) variables.get("primaryAuthenticationPrincipalName");
            if (principalName != null) {
                log.warn("PrimaryAuthentication object missing for session {}, reconstructing from principal name: {}", mfaSessionId, principalName);
                // 실제로는 권한 등 다른 정보도 필요할 수 있으므로, 이는 매우 제한적인 복구입니다.
                // 애플리케이션의 UserDetailsService 등을 통해 Authentication 객체를 재구성하는 것이 더 좋습니다.
                authentication = new AnonymousAuthenticationToken(principalName, principalName, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
            } else {
                log.error("Cannot reconstruct FactorContext for session {}: primaryAuthentication (and principal name) is missing.", mfaSessionId);
                authentication = new AnonymousAuthenticationToken("key-" + mfaSessionId, "anonymous-" + mfaSessionId, List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
            }
        }

        MfaState currentState = MfaState.NONE;
        String currentStateName = (String) variables.get("currentStateName");
        if (currentStateName != null) {
            try {
                currentState = MfaState.valueOf(currentStateName);
            } catch (IllegalArgumentException e) {
                log.warn("Invalid MfaState name '{}' in SM variables for session {}. Defaulting to NONE.", currentStateName, mfaSessionId);
            }
        } else if (stateMachine.getState() != null) {
            currentState = stateMachine.getState().getId();
        } else {
            log.warn("SM state and currentStateName are both null for session {}. Defaulting to NONE.", mfaSessionId);
        }

        String flowTypeName = (String) variables.getOrDefault("flowTypeName", "mfa");
        long createdAt = (variables.get("createdAt") instanceof Long) ? (Long)variables.get("createdAt") : System.currentTimeMillis();


        FactorContext factorContext = new FactorContext(mfaSessionId, authentication, currentState, flowTypeName /*, createdAt*/); // createdAt은 생성자에서 자동 설정됨
        updateFactorContextFromVariablesMap(factorContext, variables);

        // currentFactorOptions는 여기서 직접 복원하지 않고,
        // currentStepId와 flowConfig를 기반으로 외부 로직(예: MfaPolicyProvider, 핸들러)에서 설정합니다.
        // 이는 옵션 객체의 복잡한 직렬화/역직렬화를 피하기 위함입니다.
        // 필요하다면, currentStepId를 사용하여 PlatformConfig에서 해당 step의 options를 찾아 설정할 수 있습니다.

        log.debug("Reconstructed FactorContext from State Machine: sessionId={}, state={}, version={}",
                mfaSessionId, currentState, factorContext.getVersion());
        return factorContext;
    }


    @SuppressWarnings("unchecked")
    private void updateFactorContextFromVariablesMap(FactorContext factorContext, Map<Object, Object> variables) {
        if (variables == null || factorContext == null) return;

        Object versionObj = variables.get("version");
        if (versionObj instanceof Integer) {
            factorContext.setVersion((Integer) versionObj);
        }

        String currentProcessingFactorName = (String) variables.get("currentProcessingFactorName");
        if (currentProcessingFactorName != null) {
            try {
                factorContext.setCurrentProcessingFactor(AuthType.valueOf(currentProcessingFactorName));
            } catch (IllegalArgumentException e) {
                log.warn("Invalid AuthType name '{}' for currentProcessingFactorName in session {}.", currentProcessingFactorName, factorContext.getMfaSessionId());
                factorContext.setCurrentProcessingFactor(null);
            }
        } else {
            factorContext.setCurrentProcessingFactor(null);
        }

        factorContext.setCurrentStepId((String) variables.get("currentStepId"));

        Object retryCountObj = variables.get("retryCount");
        if (retryCountObj instanceof Integer) {
            factorContext.setRetryCount((Integer) retryCountObj);
        } else if (retryCountObj instanceof String) { // Redis에서 문자열로 올 수 있음
            try {
                factorContext.setRetryCount(Integer.parseInt((String) retryCountObj));
            } catch (NumberFormatException e) {
                log.warn("Could not parse retryCount '{}' for session {}", retryCountObj, factorContext.getMfaSessionId());
            }
        }


        factorContext.setLastError((String) variables.get("lastError"));

        Object mfaRequiredObj = variables.get("mfaRequiredAsPerPolicy");
        if (mfaRequiredObj instanceof Boolean) {
            factorContext.setMfaRequiredAsPerPolicy((Boolean) mfaRequiredObj);
        } else if (mfaRequiredObj instanceof String) {
            factorContext.setMfaRequiredAsPerPolicy(Boolean.parseBoolean((String) mfaRequiredObj));
        }


        Object lastActivityTimestampObj = variables.get("lastActivityTimestamp");
        if (lastActivityTimestampObj instanceof Long) {
            factorContext.setLastActivityTimestamp(Instant.ofEpochMilli((Long) lastActivityTimestampObj));
        } else if (lastActivityTimestampObj instanceof String) {
            try {
                factorContext.setLastActivityTimestamp(Instant.ofEpochMilli(Long.parseLong((String) lastActivityTimestampObj)));
            } catch (NumberFormatException e) {
                log.warn("Could not parse lastActivityTimestamp '{}' for session {}", lastActivityTimestampObj, factorContext.getMfaSessionId());
            }
        }


        // Deserialize collections
        Object completedStepIdsObj = variables.get("completedFactorStepIds");
        if (completedStepIdsObj instanceof List) {
            factorContext.getCompletedFactors().clear(); // Clear before adding
            ((List<?>) completedStepIdsObj).forEach(item -> {
                if (item instanceof String stepId) {
                    // 실제 AuthenticationStepConfig를 복원하려면 flowConfig가 필요합니다.
                    // 여기서는 stepId만으로 식별 가능한 더미 AuthenticationStepConfig를 추가하거나,
                    // FactorContext에 stepId 목록만 저장하고, 필요시 flowConfig에서 전체 정보를 조회하도록 변경.
                    // 현재 FactorContext.addCompletedFactor는 AuthenticationStepConfig를 받음.
                    // 임시로 타입만 설정하여 추가.
                    AuthenticationStepConfig dummyStep = new AuthenticationStepConfig();
                    dummyStep.setStepId(stepId);
                    // type, order, required 등은 실제 flowConfig에서 가져와야 함.
                    // 이 부분은 FactorContext를 사용하는 측에서 flowConfig를 참조하여 해석해야 함.
                    // 여기서는 단순화를 위해 type을 stepId의 일부로 가정하거나 null로 둠.
                    String[] parts = stepId.split(":");
                    if (parts.length > 1) dummyStep.setType(parts[1].toUpperCase());
                    factorContext.addCompletedFactor(dummyStep);
                }
            });
        }

        Object registeredFactorNamesObj = variables.get("registeredMfaFactorNames");
        if (registeredFactorNamesObj instanceof List) {
            List<AuthType> registeredFactors = ((List<?>) registeredFactorNamesObj).stream()
                    .filter(String.class::isInstance)
                    .map(name -> {
                        try { return AuthType.valueOf((String) name); }
                        catch (IllegalArgumentException e) {
                            log.warn("Invalid registered factor name '{}' in SM variables for session {}", name, factorContext.getMfaSessionId());
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
            factorContext.setRegisteredMfaFactors(registeredFactors);
        }


        Object userAttributesObj = variables.get("userAttributes");
        if (userAttributesObj instanceof Map) {
            try {
                Map<String, Object> userAttrs = (Map<String, Object>) userAttributesObj;
                userAttrs.forEach((key, value) -> {
                    if (key.endsWith("_json") && value instanceof String jsonValue) {
                        String originalKey = key.substring(0, key.length() - "_json".length());
                        String typeName = (String) userAttrs.get(originalKey + "_json_type");
                        if (typeName != null) {
                            try {
                                Class<?> originalType = Class.forName(typeName);
                                Object deserializedValue = objectMapper.readValue(jsonValue, originalType);
                                factorContext.setAttribute(originalKey, deserializedValue);
                            } catch (ClassNotFoundException | IOException e) {
                                log.error("Failed to deserialize attribute '{}' from JSON for session {}", originalKey, factorContext.getMfaSessionId(), e);
                                factorContext.setAttribute(originalKey, jsonValue); // Fallback to string
                            }
                        } else {
                            factorContext.setAttribute(originalKey, jsonValue); // Type info missing, store as string
                        }
                    } else if (!key.endsWith("_json_type")) { // Avoid re-adding type hints
                        factorContext.setAttribute(key, value);
                    }
                });
            } catch (ClassCastException e) {
                log.warn("Could not cast userAttributes to Map<String, Object> for session {}", factorContext.getMfaSessionId());
            }
        }
    }

    private void putSafely(Map<Object, Object> map, String key, Object value, Object defaultValue) {
        if (key == null) {
            log.warn("Attempted to use null key for StateMachine variable. This is likely a bug.");
            return;
        }
        if (value != null) {
            map.put(key, value);
        } else if (defaultValue != null) {
            map.put(key, defaultValue);
        }
        // If value is null and defaultValue is null, the key is not added.
    }

    private FactorContext createDummyErrorContext(String sessionIdHint) {
        Authentication dummyAuth = new AnonymousAuthenticationToken("key", "errorUser-" + sessionIdHint, Collections.singletonList(new SimpleGrantedAuthority("ROLE_NONE")));
        return new FactorContext(sessionIdHint + "-ERROR", dummyAuth, MfaState.MFA_SYSTEM_ERROR, "error_flow");
    }

}