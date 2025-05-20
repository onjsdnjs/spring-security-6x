// onjsdnjs/spring-security-6x/spring-security-6x-IdentityPlatform_0.0.4/src/main/resources/static/js/form-login.js

document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const messageDiv = document.getElementById("loginFormMessage");

    if (!loginForm) {
        console.warn("Login form with ID 'loginForm' not found. Login functionality will not work.");
        return;
    }

    // CSRF 토큰 및 헤더 이름 가져오기 (HTML의 meta 태그에서)
    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    // 메시지 표시 함수
    function displayLoginMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        } else if (typeof showToast === 'function') { // toast.js가 로드되었다면 사용
            showToast(message, type);
        } else {
            alert(message); // 최후의 수단
        }
    }

    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        displayLoginMessage("", "info"); // 이전 메시지 초기화

        const username = loginForm.username.value;
        const password = loginForm.password.value;
        const authMode = localStorage.getItem("authMode") || "header"; // 인증 모드 (토큰 전송 방식)

        const headers = {
            "Content-Type": "application/json",
            "X-Device-Id": getOrCreateDeviceId() // Device ID 추가
        };

        // 'cookie' 또는 'header_cookie' 모드이고 CSRF 토큰이 존재할 때 헤더에 추가
        if (authMode !== "header" && csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch("/api/auth/login", { // 1차 인증 요청 URL (서버 RestAuthenticationFilter가 처리)
                method: "POST",
                credentials: "same-origin", // 쿠키 방식 인증(예: CSRF 쿠키)을 위해 필요
                headers: headers,
                body: JSON.stringify({ username, password })
            });

            const result = await response.json(); // 서버 응답을 JSON으로 파싱

            if (response.ok) {
                if (result.status === "MFA_REQUIRED") {
                    // MFA 필요: 서버는 mfaSessionId와 다음 UI 페이지 URL을 반환해야 함.
                    sessionStorage.setItem("mfaSessionId", result.mfaSessionId);
                    sessionStorage.setItem("mfaUsername", username); // 다음 MFA UI 페이지에서 사용자 식별자로 사용 가능
                    displayLoginMessage("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info");
                    showToast("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info", 2000);

                    // result.nextStepUrl은 MfaContinuationFilter가 GET으로 처리할 UI 페이지 URL이어야 함.
                    // 예: /mfa/select-factor 또는 /mfa/challenge/ott
                    // 서버의 AuthContextProperties.mfa.initiateUrl 기본값이 /mfa/select-factor 이므로, 그것을 우선 사용.
                    const nextUrlForMfaUi = result.nextStepUrl || "/mfa/select-factor";
                    logClientSide("1차 인증 성공, MFA 필요. 다음 UI URL: " + nextUrlForMfaUi);

                    setTimeout(() => {
                        window.location.href = nextUrlForMfaUi; // GET 요청으로 MFA UI 페이지로 이동
                    }, 1500);
                    return; // MFA 흐름으로 진입하므로 여기서 종료
                }

                // MFA가 필요 없는 일반 로그인 성공 또는 모든 MFA 단계 완료 후 토큰 발급
                // (이 부분은 JwtEmittingAndMfaAwareSuccessHandler 또는 CustomTokenIssuingSuccessHandler가 처리한 결과)
                if (authMode === "header" || authMode === "header_cookie") {
                    if (result.accessToken) TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header" && result.refreshToken) {
                        TokenMemory.refreshToken = result.refreshToken;
                    }
                }
                showToast("로그인 성공!", "success");
                logClientSide("로그인 성공. Redirect URL: " + (result.redirectUrl || "/"));
                setTimeout(() => {
                    window.location.href = result.redirectUrl || "/"; // 서버 응답에 redirectUrl이 있으면 사용, 없으면 홈으로
                }, 1000);

            } else {
                // 로그인 실패 (HTTP 상태 코드가 2xx가 아님)
                const message = result.message || (response.status === 401 ? "아이디 또는 비밀번호가 잘못되었습니다." : "로그인에 실패했습니다. (" + response.status + ")");
                displayLoginMessage(message, "error");
                logClientSide("로그인 실패: " + message);
            }
        } catch (error) {
            console.error("Login request processing error:", error);
            displayLoginMessage("로그인 요청 중 오류가 발생했습니다. 네트워크 연결을 확인하거나 잠시 후 다시 시도해주세요.", "error");
            logClientSide("로그인 요청 중 예외 발생: " + error.message);
        }
    });

    // Device ID 생성 또는 가져오기 (localStorage 사용)
    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
            logClientSide("New Device ID created: " + deviceId);
        }
        return deviceId;
    }

    // 클라이언트 사이드 로깅 함수 (디버깅용)
    function logClientSide(message) {
        console.log("[Client FormLogin] " + message);
    }
});