document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const messageDiv = document.getElementById("loginFormMessage");

    if (!loginForm) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

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
            "X-Device-Id": getOrCreateDeviceId() // Device ID 추가
        };

        if (authMode !== "header" && csrfToken && csrfHeader) { // 'cookie' 또는 'header_cookie' 모드 + CSRF 토큰 존재 시
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch("/api/auth/login", { // 1차 인증 요청 URL
                method: "POST",
                credentials: "same-origin", // 쿠키 방식 인증 시 필요
                headers: headers,
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (response.ok) {
                if (result.status === "MFA_REQUIRED") {
                    // MFA 필요: 서버에서 mfaSessionId와 다음 단계 URL(select-factor 페이지)을 받아야 함
                    sessionStorage.setItem("mfaSessionId", result.mfaSessionId);
                    sessionStorage.setItem("mfaUsername", username); // 다음 MFA 단계에서 사용자 식별자로 사용
                    displayLoginMessage("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info");
                    showToast("MFA 인증이 필요합니다. 2차 인증 페이지로 이동합니다.", "info", 2000);
                    setTimeout(() => {
                        window.location.href = result.nextStepUrl || "/mfa/select-factor";
                    }, 1500);
                    return;
                }

                // MFA가 필요 없는 일반 로그인 성공 또는 모든 MFA 단계 완료 후 토큰 발급
                if (authMode === "header" || authMode === "header_cookie") {
                    TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header" && result.refreshToken) { // 'header' 모드이고 refreshToken이 응답에 있을 때만 저장
                        TokenMemory.refreshToken = result.refreshToken;
                    }
                }
                showToast("로그인 성공!", "success");
                setTimeout(() => {
                    window.location.href = result.redirectUrl || "/"; // 서버 응답에 redirectUrl이 있으면 사용
                }, 1000);

            } else {
                const message = result.message || (response.status === 401 ? "아이디 또는 비밀번호가 잘못되었습니다." : "로그인에 실패했습니다.");
                displayLoginMessage(message, "error");
            }
        } catch (error) {
            console.error("Login request error:", error);
            displayLoginMessage("로그인 요청 중 오류가 발생했습니다. 네트워크 연결을 확인해주세요.", "error");
        }
    });

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
});