// static/js/mfa-state-tracker.js
class MfaStateTracker {
    constructor() {
        this.currentState = null;
        this.sessionId = null;
        this.stateMetadata = {};
        this.transitions = [];
        this.lastUpdate = null;
    }

    updateFromServerResponse(response) {
        if (!response.stateMachine) return;

        const sm = response.stateMachine;
        const previousState = this.currentState;

        this.currentState = sm.currentState;
        this.sessionId = sm.sessionId || this.sessionId;
        this.stateMetadata = sm.stateMetadata || {};
        this.lastUpdate = new Date();

        // 전이 기록
        if (previousState && previousState !== this.currentState) {
            this.transitions.push({
                from: previousState,
                to: this.currentState,
                timestamp: this.lastUpdate,
                event: sm.lastEvent
            });
        }

        // 세션 스토리지에 저장
        this.saveToSession();

        console.log(`[State Machine] State updated: ${previousState} -> ${this.currentState}`);
    }

    canTransitionTo(targetState) {
        // 클라이언트 측 전이 검증 (서버와 동기화)
        const validTransitions = {
            'PRIMARY_AUTH_SUCCESS': ['AWAITING_FACTOR_SELECTION', 'AWAITING_FACTOR_CHALLENGE_INITIATION'],
            'AWAITING_FACTOR_SELECTION': ['FACTOR_SELECTED'],
            'FACTOR_SELECTED': ['FACTOR_CHALLENGE_INITIATED'],
            'FACTOR_CHALLENGE_INITIATED': ['FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION'],
            'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION': ['FACTOR_VERIFICATION_COMPLETED', 'FAILED'],
            'FACTOR_VERIFICATION_COMPLETED': ['ALL_FACTORS_COMPLETED', 'AWAITING_FACTOR_SELECTION'],
            'ALL_FACTORS_COMPLETED': ['MFA_SUCCESSFUL']
        };

        const allowed = validTransitions[this.currentState] || [];
        return allowed.includes(targetState);
    }

    isValid() {
        return this.currentState && this.sessionId &&
            (new Date() - this.lastUpdate) < 30 * 60 * 1000; // 30분
    }

    saveToSession() {
        sessionStorage.setItem('mfaStateTracker', JSON.stringify({
            currentState: this.currentState,
            sessionId: this.sessionId,
            stateMetadata: this.stateMetadata,
            transitions: this.transitions,
            lastUpdate: this.lastUpdate
        }));
    }

    restoreFromSession() {
        const stored = sessionStorage.getItem('mfaStateTracker');
        if (stored) {
            try {
                const data = JSON.parse(stored);
                Object.assign(this, data);
                this.lastUpdate = new Date(data.lastUpdate);
                console.log(`[State Machine] Restored state: ${this.currentState}`);
            } catch (e) {
                console.error('[State Machine] Failed to restore state:', e);
            }
        }
    }

    clear() {
        this.currentState = null;
        this.sessionId = null;
        this.stateMetadata = {};
        this.transitions = [];
        this.lastUpdate = null;
        sessionStorage.removeItem('mfaStateTracker');
    }
}

// 전역 인스턴스 생성
window.mfaStateTracker = new MfaStateTracker();