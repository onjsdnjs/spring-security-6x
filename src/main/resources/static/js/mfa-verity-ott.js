document.addEventListener("DOMContentLoaded", () => {
    const ottVerifyForm = document.getElementById("mfaVerifyOttForm");
    const ottCodeInput = document.getElementById("mfaOttCode");
    const messageDiv = document.getElementById("ottVerifyMessage");
    const resendButton = document.getElementById("resendMfaOttCode");
    const userIdentifierDisplay = document.getElementById("userIdentifier");

    if (!ottVerifyForm || !ottCodeInput) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 이메일 주소
    const currentFactor = sessionStorage.getItem("currentMfaFactor"); // "OTT" 여야 함

    if (userIdentifierDisplay && username) {
        userIdentifierDisplay.textContent = username; // 이메일 표시
    }

    if (!mfaSessionId || !username || currentFactor !== "OTT") {
        displayMessage("잘못된 접근입니다. MFA 세션을 다시 시작해주세요.", "error");
        if (typeof showToast === 'function') showToast("잘못된 접근입니다. MFA 세션을 확인해주세요.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 3000);
        return;
    }

    function displayMessage(message, type = 'error') { // 기본값을 error로
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
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
            // 서버 API: MFA OTT 챌린지 재요청
            const response = await fetch(`/api/mfa/request-ott-code`, { // PlatformSecurityConfig의 .mfa().ott()에 설정된 API 경로와 일치해야함
                method: "POST",
                headers: headers,
                body: JSON.stringify({ username: username, factorType: "OTT" }) // 서버가 username을 필요로 함
            });

            if (response.ok) {
                const result = await response.json();
                displayMessage(result.message || `새로운 인증 코드가 ${username} (으)로 발송되었습니다.`, "success");
                showToast(result.message || `새로운 인증 코드가 ${username} (으)로 발송되었습니다.`, "success", 4000);
            } else {
                const errorData = await response.json().catch(() => ({ message: "코드 재전송 요청 실패" }));
                displayMessage(`코드 재전송 실패: ${errorData.message || response.statusText}`, "error");
            }
        } catch (error) {
            console.error("Error resending OTT code:", error);
            displayMessage("코드 재전송 중 오류 발생", "error");
        } finally {
            if (resendButton) {
                setTimeout(() => { resendButton.disabled = false; }, 30000); // 30초 후 재전송 가능
            }
        }
    }

    if (resendButton) {
        resendButton.addEventListener("click", requestNewOttCode);
        // 페이지 로드 시 자동으로 코드 발송 요청 (선택 사항)
        // 일반적으로는 mfa-select-factor -> ott 선택 시 서버에서 1차 발송, 여기는 재전송만 담당
        showToast(`이메일(${username})로 인증 코드가 발송되었을 것입니다. 확인해주세요.`, "info", 5000);
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

        const headers = {
            "Content-Type": "application/json",
            "X-MFA-Session-Id": mfaSessionId,
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;

        try {
            // 서버 API: MFA OTT 코드 검증
            // 실제 제출은 Spring Security Filter가 처리하는 경로로 해야 함.
            // PlatformSecurityConfig에서 .mfa().ott().loginProcessingUrl()에 설정된 값. 예: "/login/mfa-ott"
            const response = await fetch(`/login/mfa-ott`, { // 실제 필터 처리 경로로 변경
                method: "POST",
                headers: headers, // Content-Type은 application/json이 아닐 수도 있음 (Spring Security Filter 스펙 확인)
                                  // 일반적으로 Filter는 x-www-form-urlencoded를 기대할 수 있음.
                                  // 여기서는 JSON으로 보내고 서버 필터가 이를 처리한다고 가정. 만약 안되면 form-data로 변경 필요.
                body: JSON.stringify({ token: ottCode, username: username }) // Spring Security 필터가 받을 파라미터명 확인 필요 (보통 token 또는 code)
                                                                             // username도 필요시 전달
            });

            // Spring Security Filter는 성공/실패 시 리다이렉션 또는 특정 HTTP 상태 코드를 반환할 수 있음.
            // 여기서는 성공 시 JSON 응답을 기대하고 처리 (서버 SuccessHandler 설정에 따름)
            if (response.redirected && response.url.includes('/mfa/select-factor')) {
                // 예: 시도 횟수 초과 등으로 다른 요인 선택 화면으로 리다이렉션 된 경우
                const urlParams = new URLSearchParams(new URL(response.url).search);
                const errorMsg = urlParams.get('error_ott_verify') || "OTT 코드 인증에 실패하여 다른 인증 수단을 선택합니다.";
                displayMessage(errorMsg, "error");
                showToast(errorMsg, "error");
                setTimeout(() => { window.location.href = response.url; }, 1500);
                return;
            }
            if (response.redirected && response.url.includes('/mfa/failure')) {
                const urlParams = new URLSearchParams(new URL(response.url).search);
                const errorMsg = urlParams.get('error_mfa_terminal') || "MFA 인증에 최종 실패했습니다.";
                displayMessage(errorMsg, "error");
                showToast(errorMsg, "error");
                setTimeout(() => { window.location.href = response.url; }, 1500);
                return;
            }


            const result = await response.json(); // MfaStepBasedSuccessHandler 또는 MfaCapableRestSuccessHandler가 JSON 반환 가정

            if (response.ok) {
                if (result.status === "MFA_COMPLETE") {
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    showToast("MFA 인증 성공!", "success");
                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor");
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) {
                    showToast("OTT 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType);
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else {
                    displayMessage(result.message || "인증 처리 중 알 수 없는 상태입니다.", "error");
                }
            } else {
                const message = result.message || (response.status === 401 ? "인증 코드가 잘못되었거나 만료되었습니다." : "코드 검증 실패");
                displayMessage(message, "error");
                ottCodeInput.focus();
                ottCodeInput.select();
                if (result.remainingAttempts === 0) {
                    showToast("최대 인증 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.", "error", 5000);
                    setTimeout(() => { window.location.href = "/mfa/failure"; }, 2000);
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
});