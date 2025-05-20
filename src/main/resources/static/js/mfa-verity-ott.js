// onjsdnjs/spring-security-6x/spring-security-6x-IdentityPlatform_0.0.4/src/main/resources/static/js/mfa-verify-ott.js
document.addEventListener("DOMContentLoaded", () => {
    const ottVerifyForm = document.getElementById("mfaVerifyOttForm");
    const ottCodeInput = document.getElementById("mfaOttCode");
    const messageDiv = document.getElementById("ottVerifyMessage");
    const resendButton = document.getElementById("resendMfaOttCode");
    const userIdentifierDisplay = document.getElementById("userIdentifier");

    if (!ottVerifyForm || !ottCodeInput) {
        console.warn("MFA OTT verification form elements not found.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 1차 인증 시 저장된 username (이메일)
    // currentMfaFactor는 MfaContinuationFilter가 이 페이지로 안내하기 전에 sessionStorage에 저장했을 수 있음
    // 또는 서버에서 이 페이지를 렌더링할 때 모델 어트리뷰트로 전달할 수도 있음
    const currentFactorType = "OTT"; // 이 페이지는 OTT 전용이므로 하드코딩 또는 서버로부터 전달받아 설정

    if (userIdentifierDisplay && username) {
        userIdentifierDisplay.textContent = username;
    }

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 없습니다. 다시 로그인해주세요.", "error");
        showToast("MFA 세션 정보가 없습니다. 다시 로그인해주세요.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 2000);
        return;
    }
    logClientSideMfaVerify(`OTT Verification page loaded for user: ${username}, mfaSessionId: ${mfaSessionId}`);

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        }
        showToast(message, type);
    }

    async function requestNewOttCode() {
        if (resendButton) resendButton.disabled = true;
        displayMessage("새로운 인증 코드를 요청 중입니다...", "info");

        const headers = {
            "Content-Type": "application/json",
            "X-MFA-Session-Id": mfaSessionId,
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;

        try {
            const response = await fetch(`/api/mfa/request-ott-code`, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ username: username, factorType: "OTT" })
            });

            const result = await response.json();
            if (response.ok) {
                displayMessage(result.message || `새로운 인증 코드가 ${username}(으)로 발송되었습니다.`, "success");
            } else {
                displayMessage(`코드 재전송 실패: ${result.message || response.statusText}`, "error");
            }
        } catch (error) {
            console.error("Error resending OTT code:", error);
            displayMessage("코드 재전송 중 네트워크 오류 발생", "error");
        } finally {
            if (resendButton) {
                setTimeout(() => { resendButton.disabled = false; }, 30000); // 30초 후 재전송 가능
            }
        }
    }

    if (resendButton) {
        resendButton.addEventListener("click", requestNewOttCode);
    }

    ottVerifyForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const ottCode = ottCodeInput.value;
        if (!ottCode || ottCode.length !== 6 || !/^\d{6}$/.test(ottCode)) {
            displayMessage("6자리 숫자로 된 인증 코드를 입력해주세요.", "error");
            ottCodeInput.focus();
            return;
        }
        displayMessage("OTT 코드 검증 중...", "info");

        // Spring Security의 OneTimeTokenAuthenticationFilter는 기본적으로 x-www-form-urlencoded를 기대하며,
        // 파라미터 이름은 'username'과 'token'임.
        const formData = new URLSearchParams();
        formData.append('username', username); // FactorContext의 username 사용
        formData.append('token', ottCode);    // 사용자가 입력한 OTT 코드

        const headers = {
            // "Content-Type": "application/json", // Spring Security OTT 필터는 기본적으로 form-urlencoded
            "Content-Type": "application/x-www-form-urlencoded",
            "X-MFA-Session-Id": mfaSessionId, // FactorContext 로드 및 검증을 위해 필요
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            // MFA DSL에서 .ott().loginProcessingUrl()에 설정된 경로로 POST 요청
            // 예: "/login/mfa-ott" (PlatformSecurityConfig의 mfa.ott.loginProcessingUrl 값)
            const loginProcessingUrl = document.body.dataset.mfaOttProcessingUrl || "/login/mfa-ott"; // HTML에 경로 설정 권장
            logClientSideMfaVerify(`Submitting OTT code to: ${loginProcessingUrl}`);

            const response = await fetch(loginProcessingUrl, {
                method: "POST",
                headers: headers,
                body: formData.toString() // x-www-form-urlencoded 형식으로 전송
            });

            // MfaStepBasedSuccessHandler 또는 MfaAuthenticationFailureHandler가 JSON 응답을 반환한다고 가정
            const result = await response.json();
            logClientSideMfaVerify(`OTT verification response status: ${response.status}, body: ${JSON.stringify(result)}`);


            if (response.ok) {
                if (result.status === "MFA_COMPLETE") {
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayMessage("MFA 인증 성공!", "success");
                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor"); // 현재 Factor 정보도 제거
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) {
                    displayMessage("OTT 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType); // 다음 Factor 타입 저장
                    // 다음 stepId도 서버에서 내려주면 sessionStorage에 저장 가능
                    if (result.nextStepId) sessionStorage.setItem("currentMfaStepId", result.nextStepId);
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else {
                    // result.status가 예상과 다른 경우 (예: MFA_REQUIRED 등)
                    displayMessage(result.message || "인증 처리 중 알 수 없는 상태입니다.", "error");
                }
            } else { // 응답 코드가 2xx가 아닌 경우 (인증 실패 등)
                const message = result.message || (response.status === 401 ? "인증 코드가 잘못되었거나 만료되었습니다." : "코드 검증에 실패했습니다.");
                displayMessage(message, "error");
                ottCodeInput.focus();
                ottCodeInput.select();
                // 실패 시 추가 정보 (예: 남은 시도 횟수)가 있다면 result에서 사용
                if (result.remainingAttempts === 0) {
                    showToast("최대 인증 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.", "error", 5000);
                    // 서버 MfaAuthenticationFailureHandler에서 nextStepUrl을 내려줄 수 있음
                    if (result.nextStepUrl) {
                        setTimeout(() => { window.location.href = result.nextStepUrl; }, 2000);
                    } else {
                        setTimeout(() => { window.location.href = "/mfa/failure"; }, 2000); // 기본 실패 페이지
                    }
                }
            }
        } catch (error) {
            console.error("Error verifying OTT code:", error);
            displayMessage("OTT 코드 검증 중 오류가 발생했습니다. 네트워크 연결을 확인해주세요.", "error");
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

    function logClientSideMfaVerify(message) {
        console.log("[Client MFA OTT Verify] " + message);
    }

    // 페이지 로드 시, MfaContinuationFilter에서 OTT 코드가 이미 발송되었다는 안내를 할 수 있음.
    // 또는 mfa-select-factor.js에서 OTT 선택 시 발송 요청 후 이 페이지로 왔을 수 있음.
    if (username) {
        showToast(`이메일(${username})로 인증 코드가 발송되었을 것입니다. 확인 후 입력해주세요.`, "info", 5000);
    }
});