package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer.*;
import io.springsecurity.springsecurity6x.security.core.feature.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.state.session.SessionStateConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * 사용자용 MFA DSL 빌더.
 * Consumer<MfaDslConfigurer> 를 구현하여
 * IdentityDslRegistry.mfa(...) 에 바로 전달할 수 있습니다.
 */
public class MfaDsl implements Consumer<MfaDslConfigurer> {
    private final List<Consumer<FactorDslConfigurer>> factorSteps = new ArrayList<>();
    private int order = 0;
    private Consumer<RetryPolicyDslConfigurer> retryPolicyConsumer;
    private Consumer<AdaptiveDslConfigurer> adaptiveConsumer;
    private boolean deviceTrust;
    private Consumer<RecoveryDslConfigurer> recoveryConsumer;
    private boolean sessionFlow;
    private Consumer<SessionStateConfigurer> sessionCustomizer;
    private boolean jwtFlow;
    private Consumer<JwtStateConfigurer> jwtCustomizer;

    private MfaDsl() {}

    // ────────────────────────────────────────────────────────────
    // 스텝 추가 메서드 (factor 대신 간편 rest()/ott()/passkey())
    // ────────────────────────────────────────────────────────────

    /** 기존 RestDslConfigurer 와 연결 */
    public MfaDsl rest(Consumer<RestDslConfigurer> customizer) {
        factorSteps.add(cfg -> customizer.accept((RestDslConfigurer) cfg));
        return this;
    }
    /** OTT 스텝 */
    public MfaDsl ott(Consumer<OttDslConfigurer> customizer) {
        factorSteps.add(cfg -> customizer.accept((OttDslConfigurer) cfg));
        return this;
    }
    /** Passkey(WebAuthn) 스텝 */
    /*public MfaDsl passkey(Consumer<PasskeyDslConfigurer> customizer) {
        factorSteps.add(cfg -> customizer.accept((PasskeyDslConfigurer) cfg));
        return this;
    }*/

    // ────────────────────────────────────────────────────────────
    // 전체 Flow 우선순위
    // ────────────────────────────────────────────────────────────

    /** 전체 MFA Flow의 실행 순서를 지정 */
    public MfaDsl order(int order) {
        this.order = order;
        return this;
    }

    // ────────────────────────────────────────────────────────────
    // Retry / Adaptive / DeviceTrust / Recovery
    // ────────────────────────────────────────────────────────────

    /** 재시도 정책 설정 */
    public MfaDsl retryPolicy(Consumer<RetryPolicyDslConfigurer> c) {
        this.retryPolicyConsumer = c;
        return this;
    }

    /** Adaptive 정책 설정 */
    public MfaDsl adaptive(Consumer<AdaptiveDslConfigurer> c) {
        this.adaptiveConsumer = c;
        return this;
    }

    /** 디바이스 신뢰 기능 활성화 */
    public MfaDsl deviceTrust(boolean enable) {
        this.deviceTrust = enable;
        return this;
    }

    /** 복구 워크플로우 설정 */
    public MfaDsl recoveryFlow(Consumer<RecoveryDslConfigurer> c) {
        this.recoveryConsumer = c;
        return this;
    }

    // ────────────────────────────────────────────────────────────
    // 상태 관리 방식 선택
    // ────────────────────────────────────────────────────────────

    /** 마지막에 .session() 을 호출하면 세션 방식으로 */
    public MfaDsl session() {
        this.sessionFlow = true;
        this.sessionCustomizer = c -> {};
        return this;
    }
    public MfaDsl session(Consumer<SessionStateConfigurer> customizer) {
        this.sessionFlow = true;
        this.sessionCustomizer = customizer;
        return this;
    }

    /** 마지막에 .jwt() 을 호출하면 JWT 방식으로 */
    public MfaDsl jwt() {
        this.jwtFlow = true;
        this.jwtCustomizer = c -> {};
        return this;
    }
    public MfaDsl jwt(Consumer<JwtStateConfigurer> customizer) {
        this.jwtFlow = true;
        this.jwtCustomizer = customizer;
        return this;
    }

    // ────────────────────────────────────────────────────────────
    // static 팩토리 메서드
    // ────────────────────────────────────────────────────────────

    public static MfaDsl rest()        { return new MfaDsl(); }
    public static MfaDsl ott()         { return new MfaDsl(); }
    public static MfaDsl passkey()     { return new MfaDsl(); }
    public static MfaDsl mfa()         { return new MfaDsl(); }

    // ────────────────────────────────────────────────────────────
    // Consumer<MfaDslConfigurer> 구현
    // ────────────────────────────────────────────────────────────

    @Override
    public void accept(MfaDslConfigurer builder) {
        // factor 스텝 적용
        for (Consumer<FactorDslConfigurer> step : factorSteps) {
            builder.factor(step);
        }
        // order
        builder.order(order);
        // retry / adaptive / deviceTrust / recovery
        if (retryPolicyConsumer != null)   builder.retryPolicy(retryPolicyConsumer);
        if (adaptiveConsumer != null)      builder.adaptive(adaptiveConsumer);
        if (deviceTrust)                   builder.deviceTrust(true);
        if (recoveryConsumer != null)      builder.recoveryFlow(recoveryConsumer);
        // 상태 관리
        if (sessionFlow) builder.session(sessionCustomizer);
        if (jwtFlow)     builder.jwt(jwtCustomizer);
    }
}

