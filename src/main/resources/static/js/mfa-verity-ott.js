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
    const username = sessionStorage.getItem("mfaUsername"); // 이메일 주소 (또는 사용자 식별자)
    const currentFactor = sessionStorage.getItem("currentMfaFactor");

    if (userIdentifierDisplay && username) {
        userIdentifierDisplay.textContent = username;
    }

    if (!mfaSessionId || currentFactor !== "OTT") {
        displayMessage("잘못된 접근입니다. MFA 세션을 다시 시작해주세요.", "error");
        if (typeof showToast === 'function') showToast("잘못된 접근입니다.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 3000);
        return;
    }

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="${type === 'error' ? 'text-red-600' : 'text-green-600'}">${message}</p>`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    async function requestNewOttCode() {
        if (resendButton) resendButton.disabled = true;
        displayMessage("새로운 인증 코드를 요청 중입니다...", "info");

        const headers = { "Content-Type": "application/json" };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;
        headers["X-MFA-Session-Id"] = mfaSessionId;
        headers["X-Device-Id"] = getOrCreateDeviceId();

        try {
            // 서버 API: MFA OTT 챌린지 재요청 (예: `/api/mfa/challenge?factorType=OTT`)
            // 이전 `mfa-login.js`의 `requestOttChallenge` 함수와 유사하게 구현
            const response = await fetch(`/api/mfa/challenge`, { // 서버 엔드포인트 확인
                method: "POST",
                headers: headers,
                body: JSON.stringify({ factorType: "OTT", username: username, event: "REQUEST_CHALLENGE" }) // 서버가 username을 필요로 할 수 있음
            });

            if (response.ok) {
                const result = await response.json(); // 서버 응답 구조에 따라 다름
                displayMessage(`새로운 인증 코드가 ${username} (으)로 발송되었습니다.`, "success");
            } else {
                const errorData = await response.json().catch(() => ({ message: "코드 재전송 실패" }));
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
        // 페이지 로드 시 바로 코드 발송 요청 (선택 사항, 이미 이전 단계에서 발송했을 수 있음)
        // requestNewOttCode();
        showToast(`이메일(${username})로 인증 코드가 발송되었습니다.`, "info", 5000);

    }


    ottVerifyForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const ottCode = ottCodeInput.value;
        displayMessage("OTT 코드 검증 중...", "info");

        const headers = { "Content-Type": "application/json" };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;
        headers["X-MFA-Session-Id"] = mfaSessionId;
        headers["X-Device-Id"] = getOrCreateDeviceId();

        try {
            // 서버 API: MFA OTT 코드 검증 (예: `/api/mfa/verify`)
            const response = await fetch(`/api/mfa/verify`, { // 서버 엔드포인트 확인
                method: "POST",
                headers: headers,
                body: JSON.stringify({ factorType: "OTT", token: ottCode, event: "SUBMIT_CREDENTIAL" })
            });

            const result = await response.json();

            if (response.ok) {
                if (result.status === "MFA_COMPLETE") { // 최종 성공
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header") TokenMemory.refreshToken = result.refreshToken;
                    }
                    showToast("MFA 인증 성공!", "success");
                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor");
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) { // 다른 MFA 단계가 남은 경우
                    showToast("OTT 인증 성공. 다음 단계로 이동합니다.", "info");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType); // 다음 팩터 타입 저장
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else { // 예상치 못한 성공 응답
                    displayMessage(result.message || "인증 처리 중 알 수 없는 상태입니다.", "error");
                }
            } else {
                // 실패 시 서버에서 남은 시도 횟수 등을 반환할 수 있음
                const message = result.message || (response.status === 401 ? "인증 코드가 잘못되었거나 만료되었습니다." : "코드 검증 실패");
                displayMessage(message, "error");
                ottCodeInput.focus();
                ottCodeInput.select();
                if (result.remainingAttempts === 0) { // 예시: 시도 횟수 초과
                    showToast("최대 인증 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.", "error", 5000);
                    setTimeout(() => { window.location.href = "/mfa/failure"; }, 2000); // 실패 페이지로
                }
            }
        } catch (error) {
            console.error("Error verifying OTT code:", error);
            displayMessage("OTT 코드 검증 중 오류 발생", "error");
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