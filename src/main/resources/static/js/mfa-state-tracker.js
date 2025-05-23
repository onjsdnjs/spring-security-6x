// src/main/resources/static/js/mfa-state-tracker.js
// MFA State Machine 상태 추적 및 관리 모듈

class MfaStateTracker {
    constructor() {
        this.currentState = null;
        this.allowedTransitions = [];
        this.stateHistory = [];
        this.stateMetadata = {};
        this.sessionId = null;
    }

    /**
     * 서버 응답으로부터 상태 정보 업데이트
     */
    updateFromServerResponse(response) {
        if (response.stateMachine) {
            const sm = response.stateMachine;

            // 현재 상태 업데이트
            if (sm.currentState) {
                this.currentState = sm.currentState;
                this.stateHistory.push({
                    state: sm.currentState,
                    timestamp: new Date().toISOString(),
                    event: response.lastEvent || 'UNKNOWN'
                });
            }

            // 허용된 전이 업데이트
            if (sm.allowedTransitions) {
                this.allowedTransitions = sm.allowedTransitions;
            }

            // 메타데이터 업데이트
            if (sm.stateMetadata) {
                this.stateMetadata = sm.stateMetadata;
            }

            // 세션 저장
            this.saveToSession();
        }

        // MFA 세션 ID 업데이트
        if (response.mfaSessionId) {
            this.sessionId = response.mfaSessionId;
            sessionStorage.setItem('mfaSessionId', this.sessionId);
        }
    }

    /**
     * 특정 상태로의 전이가 가능한지 확인
     */
    canTransitionTo(targetState) {
        return this.allowedTransitions.includes(targetState);
    }

    /**
     * 특정 이벤트가 현재 상태에서 가능한지 확인
     */
    canTriggerEvent(event) {
        const eventToStateMap = {
            'SELECT_OTT': 'OTT_CHALLENGE',
            'SELECT_PASSKEY': 'PASSKEY_CHALLENGE',
            'VERIFY_OTT': 'OTT_VERIFIED',
            'VERIFY_PASSKEY': 'PASSKEY_VERIFIED'
        };

        const targetState = eventToStateMap[event];
        return targetState ? this.canTransitionTo(targetState) : false;
    }

    /**
     * 현재 상태 정보를 세션에 저장
     */
    saveToSession() {
        const stateData = {
            currentState: this.currentState,
            allowedTransitions: this.allowedTransitions,
            stateMetadata: this.stateMetadata,
            stateHistory: this.stateHistory,
            timestamp: new Date().toISOString()
        };

        sessionStorage.setItem('mfaState', JSON.stringify(stateData));
    }

    /**
     * 세션에서 상태 정보 복원
     */
    restoreFromSession() {
        const savedState = sessionStorage.getItem('mfaState');
        if (!savedState) return false;

        try {
            const state = JSON.parse(savedState);
            const stateAge = new Date() - new Date(state.timestamp);

            // 5분 이상 지난 상태는 무효화
            if (stateAge > 300000) {
                this.clear();
                return false;
            }

            this.currentState = state.currentState;
            this.allowedTransitions = state.allowedTransitions || [];
            this.stateMetadata = state.stateMetadata || {};
            this.stateHistory = state.stateHistory || [];

            // 세션 ID 복원
            this.sessionId = sessionStorage.getItem('mfaSessionId');

            return true;
        } catch (e) {
            console.error('Failed to restore MFA state:', e);
            this.clear();
            return false;
        }
    }

    /**
     * 상태 초기화
     */
    clear() {
        this.currentState = null;
        this.allowedTransitions = [];
        this.stateHistory = [];
        this.stateMetadata = {};
        this.sessionId = null;

        sessionStorage.removeItem('mfaState');
        sessionStorage.removeItem('mfaSessionId');
        sessionStorage.removeItem('mfaUsername');
        sessionStorage.removeItem('currentMfaFactor');
        sessionStorage.removeItem('currentMfaStepId');
    }

    /**
     * 현재 상태가 유효한지 확인
     */
    isValid() {
        return this.currentState !== null && this.sessionId !== null;
    }

    /**
     * 상태별 사용자 친화적 설명 반환
     */
    getStateDescription() {
        const descriptions = {
            'INITIAL': '인증 시작',
            'PRIMARY_AUTH_SUCCESS': '1차 인증 완료',
            'AWAITING_FACTOR_SELECTION': '2차 인증 수단 선택 대기',
            'OTT_CHALLENGE': 'OTT 코드 입력 대기',
            'OTT_VERIFIED': 'OTT 인증 완료',
            'PASSKEY_CHALLENGE': 'Passkey 인증 대기',
            'PASSKEY_VERIFIED': 'Passkey 인증 완료',
            'COMPLETED': '모든 인증 완료',
            'FAILED': '인증 실패',
            'CANCELLED': '인증 취소됨'
        };

        return descriptions[this.currentState] || '알 수 없는 상태';
    }

    /**
     * 진행률 계산 (0-100)
     */
    getProgress() {
        const progressMap = {
            'INITIAL': 0,
            'PRIMARY_AUTH_SUCCESS': 25,
            'AWAITING_FACTOR_SELECTION': 40,
            'OTT_CHALLENGE': 60,
            'PASSKEY_CHALLENGE': 60,
            'OTT_VERIFIED': 80,
            'PASSKEY_VERIFIED': 80,
            'COMPLETED': 100,
            'FAILED': 0,
            'CANCELLED': 0
        };

        return progressMap[this.currentState] || 0;
    }

    /**
     * 디버그 정보 출력
     */
    debug() {
        console.group('MFA State Tracker Debug Info');
        console.log('Current State:', this.currentState);
        console.log('Allowed Transitions:', this.allowedTransitions);
        console.log('State Metadata:', this.stateMetadata);
        console.log('Session ID:', this.sessionId);
        console.log('State History:', this.stateHistory);
        console.groupEnd();
    }
}

// 전역 인스턴스 생성
window.mfaStateTracker = new MfaStateTracker();

// 페이지 로드 시 상태 복원 시도
document.addEventListener('DOMContentLoaded', () => {
    if (window.mfaStateTracker.restoreFromSession()) {
        console.log('MFA state restored from session');
        window.mfaStateTracker.debug();
    }
});