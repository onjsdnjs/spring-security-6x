document.addEventListener("DOMContentLoaded", () => {
    const factorSelectionContainer = document.getElementById("mfaFactorSelectionForm"); // ID 변경 가능성 고려
    const messageDiv = document.getElementById("factorSelectionMessage");

    if (!factorSelectionContainer) {
        console.warn("MFA Factor Selection container/form not found.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 1차 인증 시 저장된 사용자 이름

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error");
        if (typeof showToast === 'function') showToast("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error", 3000);
        // setTimeout(() => { window.location.href = "/loginForm"; }, 2000); // 자동 리다이렉션은 UI/UX에 따라 결정
        return;
    }
    logClientSideMfa("Select Factor page loaded. SessionId: " + mfaSessionId + ", User: " + username);

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
        else alert(message);
    }

    const factorButtons = document.querySelectorAll("#mfaFactorSelectionForm .mfa-factor-button");

    factorButtons.forEach(button => {
        button.addEventListener("click", async () => {
            factorButtons.forEach(btn => btn.disabled = true);
            const selectedFactor = button.dataset.factor;
            // data-target-url은 이 JS가 직접 API를 호출하고 그 결과를 바탕으로 페이지를 이동하므로,
            // 이 JS 에서는 MfaApiController를 호출하는 것으로 통일. 서버가 nextStepUrl을 내려줌.
            const targetUiPageAfterApi = button.dataset.targetUrl; // 예비용 또는 서버 응답 없을 시 사용

            displayMessage("선택한 인증 수단(" + selectedFactor + ")으로 진행합니다...", "info");

            const headers = createApiHeaders(true); // createApiHeaders는 mfaSessionId 등을 포함하여 생성

            try {
                const response = await fetch(`/api/mfa/select-factor`, {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify({
                        factorType: selectedFactor,
                        username: username
                    })
                });
                const result = await response.json();

                if (response.ok && result.status === "FACTOR_SELECTED_PROCEED_TO_CHALLENGE_UI" && result.nextStepUrl) {
                    showToast(`${selectedFactor} 인증 페이지로 이동합니다.`, "success");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType || selectedFactor);
                    if (result.nextStepId) sessionStorage.setItem("currentMfaStepId", result.nextStepId);

                    // 서버가 알려준 nextStepUrl (GET 요청용 UI 페이지 URL)로 이동
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else {
                    displayMessage(result.message || `인증 수단 처리 중 오류: ${response.statusText}`, "error");
                    factorButtons.forEach(btn => btn.disabled = false);
                }
            } catch (error) { /* ... (오류 처리) ... */ }
        });
    });

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
    function logClientSideMfa(message) {
        console.log("[Client MFA SelectFactor] " + message);
    }
});