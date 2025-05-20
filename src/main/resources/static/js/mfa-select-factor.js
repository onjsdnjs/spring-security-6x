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

    const factorButtons = factorSelectionContainer.querySelectorAll(".mfa-factor-button");

    factorButtons.forEach(button => {
        button.disabled = false; // 페이지 로드 시 버튼 활성화
        button.addEventListener("click", async () => {
            factorButtons.forEach(btn => btn.disabled = true); // 모든 버튼 비활성화
            const selectedFactor = button.dataset.factor; // 예: "OTT", "PASSKEY"
            displayMessage("선택한 인증 수단(" + selectedFactor + ")으로 진행합니다...", "info");

            const headers = {
                "Content-Type": "application/json",
                "X-MFA-Session-Id": mfaSessionId,
                "X-Device-Id": getOrCreateDeviceId()
            };
            if (csrfToken && csrfHeader) {
                headers[csrfHeader] = csrfToken;
            }

            try {
                // 서버 API: 선택된 Factor로 MFA 진행 요청 (MfaApiController가 처리)
                const response = await fetch(`/api/mfa/select-factor`, {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify({
                        factorType: selectedFactor, // 대문자로 서버에 전달
                        username: username // 서버에서 FactorContext의 사용자와 일치하는지 검증용
                    })
                });

                const result = await response.json();
                logClientSideMfa(`Select Factor API response: Status=${response.status}, Body=${JSON.stringify(result)}`);

                if (response.ok && result.status === "FACTOR_SELECTED_PROCEED_TO_CHALLENGE" && result.nextStepUrl) {
                    if (typeof showToast === 'function') showToast(`${selectedFactor} 인증 페이지로 이동합니다.`, "success");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType || selectedFactor); // 서버에서 내려준 Factor 타입 사용
                    if (result.nextStepId) { // 서버가 다음 단계의 stepId를 내려준다면 저장
                        sessionStorage.setItem("currentMfaStepId", result.nextStepId);
                        logClientSideMfa("Next MFA Step ID set: " + result.nextStepId);
                    } else {
                        sessionStorage.removeItem("currentMfaStepId"); // 없으면 제거
                    }
                    // 서버가 반환한 nextStepUrl은 GET 요청으로 접근 가능한 UI 페이지 URL이어야 함.
                    setTimeout(() => {
                        window.location.href = result.nextStepUrl;
                    }, 1000);
                } else {
                    displayMessage(result.message || `선택한 인증 수단(${selectedFactor}) 처리 중 오류가 발생했습니다: ${response.statusText}`, "error");
                    factorButtons.forEach(btn => btn.disabled = false); // 오류 시 버튼 다시 활성화
                }
            } catch (error) {
                console.error("Error selecting MFA factor:", error);
                displayMessage("인증 수단 선택 중 네트워크 오류가 발생했습니다.", "error");
                factorButtons.forEach(btn => btn.disabled = false); // 오류 시 버튼 다시 활성화
            }
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