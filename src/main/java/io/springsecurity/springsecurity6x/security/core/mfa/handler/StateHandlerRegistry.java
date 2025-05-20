package io.springsecurity.springsecurity6x.security.core.mfa.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j // Slf4j 어노테이션으로 변경
public class StateHandlerRegistry {
    // private static final Logger log = LoggerFactory.getLogger(StateHandlerRegistry.class); // Slf4j 사용 시 불필요
    private final Map<MfaState, MfaStateHandler> registry = new EnumMap<>(MfaState.class);

    // @Autowired // 스프링이 List<MfaStateHandler> 타입의 모든 빈을 주입 (선택적, 생성자 주입 권장)
    public StateHandlerRegistry(List<MfaStateHandler> handlers, MfaPolicyProvider mfaPolicyProvider /* VerificationPendingStateHandler에 필요 */) {
        Objects.requireNonNull(handlers, "Handlers list cannot be null.");
        Objects.requireNonNull(mfaPolicyProvider, "MfaPolicyProvider cannot be null for StateHandlerRegistry (used by VerificationPendingStateHandler).");

        log.info("Initializing StateHandlerRegistry with {} MfaStateHandler beans...", handlers.size());

        for (MfaStateHandler handler : handlers) {
            if (handler == null) {
                log.warn("Null MfaStateHandler instance found in the provided list, skipping.");
                continue;
            }

            // VerificationPendingStateHandler와 같이 특정 의존성이 필요한 핸들러 처리
            // (이 방식보다는 각 핸들러를 빈으로 등록하고 Spring이 의존성을 주입하도록 하는 것이 더 좋음)
            // MfaInfrastructureAutoConfiguration에서 각 핸들러를 빈으로 등록하고, 그 리스트를 여기에 주입하는 것이 더 Spring-friendly.
            // 여기서는 주입받은 handlers 리스트를 그대로 사용한다고 가정.
            // 단, VerificationPendingStateHandler는 MfaPolicyProvider가 필요하므로,
            // MfaInfrastructureAutoConfiguration에서 VerificationPendingStateHandler 빈 생성 시 주입하거나,
            // 여기서 new 할 때 mfaPolicyProvider를 넘겨줘야 함. (후자는 좋지 않음)
            // ==> 가장 좋은 방법: 모든 MfaStateHandler를 @Component로 만들고, 필요한 의존성은 @Autowired로 주입.
            //     그리고 이 StateHandlerRegistry는 List<MfaStateHandler>를 주입받기만 함.

            for (MfaState state : MfaState.values()) {
                try {
                    if (handler.supports(state)) {
                        if (registry.containsKey(state)) {
                            log.warn("Overwriting handler for MfaState {}. Old: {}, New: {}",
                                    state, registry.get(state).getClass().getSimpleName(), handler.getClass().getSimpleName());
                        }
                        registry.put(state, handler);
                        log.debug("Registered handler {} for MfaState {}", handler.getClass().getSimpleName(), state);
                    }
                } catch (Exception e) {
                    // supports() 메소드에서 예외 발생 가능성은 낮지만, 방어적으로 처리
                    log.error("Error while checking support or registering handler for state {} with handler {}: {}",
                            state, handler.getClass().getSimpleName(), e.getMessage(), e);
                }
            }
        }
        log.info("StateHandlerRegistry initialized. Total mappings: {}", registry.size());
    }

    @Nullable // 핸들러가 없을 수 있음을 명시
    public MfaStateHandler get(MfaState state) {
        if (state == null) {
            log.warn("Attempted to get MfaStateHandler for a null MfaState.");
            return null;
        }
        MfaStateHandler handler = registry.get(state);
        if (handler == null) {
            log.warn("No MfaStateHandler found for MfaState: {}. This might lead to an InvalidTransitionException if this state is expected to be handled.", state);
        } else {
            log.debug("Retrieved handler {} for MfaState {}", handler.getClass().getSimpleName(), state);
        }
        return handler;
    }
}
