package io.springsecurity.springsecurity6x.security.core.mfa;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultChallengeGenerator implements ChallengeGenerator {

    @Override
    public Map<String, Object> generate(FactorContext ctx) {
        MfaState state = ctx.getCurrentState();
        Map<String,Object> payload = new HashMap<>();

        switch (state) {
            case FORM_CHALLENGE:
                payload.put("mode", "INLINE");
                payload.put("url", ctx.getAttributes().getOrDefault("loginUrl", "/login"));
                payload.put("fields", List.of("username", "password"));
                break;

            case OTT_CHALLENGE:
                payload.put("mode", "INLINE");
                payload.put("url", ctx.getAttributes().getOrDefault("ottUrl", "/ott/generate"));
                payload.put("fields", List.of("ottCode"));
                break;

            case PASSKEY_CHALLENGE:
                payload.put("mode", "INLINE");
                payload.put("url", ctx.getAttributes().getOrDefault("passkeyUrl", "/webauthn/challenge"));
                payload.put("options", ctx.getAttributes().getOrDefault("passkeyOptions", Map.of()));
                break;

            default:
                throw new IllegalStateException("Unsupported challenge state: " + state);
        }
        return payload;
    }
}
