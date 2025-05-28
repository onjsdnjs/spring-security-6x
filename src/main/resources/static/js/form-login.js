// src/main/resources/static/js/form-login.js
// State Machine 통합 버전

document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const messageDiv = document.getElementById("loginFormMessage");

    if (!loginForm) {
        console.warn("Login form with ID 'loginForm' not found. Login functionality will not work.");
        return;
    }

    // CSRF 토큰 및 헤더 이름 가져오기
    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    // 메시지 표시 함수
    function displayLoginMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        displayLoginMessage("", "info"); // 이전 메시지 초기화

        const username = loginForm.username.value;
        const password = loginForm.password.value;
        const authMode = localStorage.getItem("authMode") || "header";

        const headers = {
            "Content-Type": "application/json",
            "X-Device-Id": getOrCreateDeviceId()
        };

        if (authMode !== "header" && csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch("/api/auth/login", {
                method: "POST",
                credentials: "same-origin",
                headers: headers,
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (response.ok) {
                // State Machine 상태 업데이트
                if (window.mfaStateTracker && result.stateMachine) {
                    window.mfaStateTracker.updateFromServerResponse(result);
                    logClientSide(`State Machine updated: ${result.stateMachine.currentState}`);
                }

                if (result.status === "MFA_CONFIG_REQUIRED") {
                    // MFA 필요: State Machine이 PRIMARY_AUTH_SUCCESS 상태
                    sessionStorage.setItem("mfaSessionId", result.mfaSessionId);
                    sessionStorage.setItem("mfaUsername", username);

                    displayLoginMessage("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info");
                    showToast("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info", 2000);

                    // State Machine 상태 확인
                    if (window.mfaStateTracker.currentState === 'PRIMARY_AUTH_SUCCESS' ||
                        window.mfaStateTracker.currentState === 'AWAITING_FACTOR_SELECTION') {
                        const nextUrl = result.nextStepUrl || "/mfa/select-factor";
                        logClientSide(`1차 인증 성공, MFA 필요. State: ${window.mfaStateTracker.currentState}, Next URL: ${nextUrl}`);

                        setTimeout(() => {
                            window.location.href = nextUrl;
                        }, 1500);
                    } else {
                        // 예상치 못한 상태
                        logClientSide(`Unexpected state after primary auth: ${window.mfaStateTracker.currentState}`);
                        displayLoginMessage("인증 상태 오류가 발생했습니다. 다시 시도해주세요.", "error");
                    }
                    return;
                }

                // MFA가 필요 없는 일반 로그인 성공 또는 모든 MFA 단계 완료
                if (authMode === "header" || authMode === "header_cookie") {
                    if (result.accessToken) TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header" && result.refreshToken) {
                        TokenMemory.refreshToken = result.refreshToken;
                    }
                }

                // State Machine 정리
                if (window.mfaStateTracker) {
                    window.mfaStateTracker.clear();
                }

                showToast("로그인 성공!", "success");
                logClientSide("로그인 성공. Redirect URL: " + (result.redirectUrl || "/"));
                setTimeout(() => {
                    window.location.href = result.redirectUrl || "/";
                }, 1000);

            } else {
                // 로그인 실패
                const message = result.message || (response.status === 401 ? "아이디 또는 비밀번호가 잘못되었습니다." : "로그인에 실패했습니다. (" + response.status + ")");
                displayLoginMessage(message, "error");
                logClientSide("로그인 실패: " + message);

                // State Machine 실패 상태 처리
                if (result.stateMachine && result.stateMachine.currentState === 'FAILED') {
                    const failureReason = result.stateMachine.stateMetadata?.failureReason;
                    if (failureReason) {
                        displayLoginMessage(`로그인 실패: ${failureReason}`, "error");
                    }
                }
            }
        } catch (error) {
            console.error("Login request processing error:", error);
            displayLoginMessage("로그인 요청 중 오류가 발생했습니다. 네트워크 연결을 확인하거나 잠시 후 다시 시도해주세요.", "error");
            logClientSide("로그인 요청 중 예외 발생: " + error.message);
        }
    });

    // Device ID 생성 또는 가져오기
    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
            logClientSide("New Device ID created: " + deviceId);
        }
        return deviceId;
    }

    // 클라이언트 사이드 로깅 함수
    function logClientSide(message) {
        console.log("[Client FormLogin] " + message);
    }
});