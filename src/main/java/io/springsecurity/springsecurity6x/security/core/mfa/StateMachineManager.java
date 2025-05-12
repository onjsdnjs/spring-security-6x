package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import io.springsecurity.springsecurity6x.security.exception.InvalidTransitionException;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class StateMachineManager {
    private final Map<MfaState, Map<MfaEvent,MfaState>> transitions;

    public StateMachineManager(AuthenticationFlowConfig flow) {
        this.transitions = buildTable(flow);
    }

    private Map<MfaState,Map<MfaEvent,MfaState>> buildTable(AuthenticationFlowConfig flow) {

        Map<MfaState,Map<MfaEvent,MfaState>> table = new EnumMap<>(MfaState.class);
        List<AuthenticationStepConfig> steps = flow.stepConfigs();
        MfaState prev = MfaState.INIT;

        for (AuthenticationStepConfig step : steps) {
            MfaState challengeState = step.getChallengeState();
            MfaState submittedState = step.getSubmittedState();
            table.put(prev, Map.of(
                    MfaEvent.REQUEST_CHALLENGE, challengeState
            ));
            table.put(challengeState, Map.of(
                    MfaEvent.SUBMIT_CREDENTIAL, submittedState
            ));
            prev = submittedState;
        }
        // 마지막 단계 이후 토큰 발급 전이
        table.put(prev, Map.of(MfaEvent.ISSUE_TOKEN, MfaState.COMPLETED));
        return table;
    }

    public void fireEvent(FactorContext ctx, MfaEvent event) {

        MfaState current = ctx.getCurrentState();
        Map<MfaEvent, MfaState> map = transitions.get(current);

        if (map == null || !map.containsKey(event)) {
            throw new InvalidTransitionException(current, event);
        }
        MfaState next = map.get(event);
        ctx.setCurrentState(next);
        ctx.incrementVersion();
    }
}
