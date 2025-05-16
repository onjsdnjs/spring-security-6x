document.addEventListener("DOMContentLoaded", () => {
    const factorSelectionForm = document.getElementById("mfaFactorSelectionForm");
    const messageDiv = document.getElementById("factorSelectionMessage");

    if (!factorSelectionForm) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    // sessionStorage에서 mfaSessionId와 username 가져오기
    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 1차 또는 단일 인증 시 저장된 사용자 이름

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error");
        showToast("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error", 3000);
        setTimeout(() => { window.location.href = "/loginForm"; }, 2000);
        return;
    }

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    const factorButtons = factorSelectionForm.querySelectorAll(".mfa-factor-button");

    factorButtons.forEach(button => {
        button.addEventListener("click", async () => {
            const selectedFactor = button.dataset.factor; // 예: "OTT", "PASSKEY"
            displayMessage("선택한 인증 수단을 처리 중입니다...", "info");

            const headers = {
                "Content-Type": "application/json",
                "X-MFA-Session-Id": mfaSessionId, // MFA 세션 ID 헤더에 추가
                "X-Device-Id": getOrCreateDeviceId()
            };
            if (csrfToken && csrfHeader) { // CSRF 토큰이 있다면 헤더에 추가
                headers[csrfHeader] = csrfToken;
            }


            try {
                // 서버 API: 선택된 Factor로 MFA 진행 요청
                // PlatformSecurityConfig에서 MFA 플로우의 각 Factor에 대한 loginProcessingUrl이 실제로 사용됨.
                // 이 API는 클라이언트가 다음으로 이동할 UI 페이지 URL을 반환해야 함.
                const response = await fetch(`/api/mfa/select-factor`, { // 서버 엔드포인트 확인
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify({
                        factorType: selectedFactor, // 대문자로 보내고 서버에서 enum으로 변환
                        username: username // 서버에서 사용자 식별 및 추가 검증에 필요할 수 있음
                    })
                });

                const result = await response.json();

                if (response.ok && result.nextStepUrl) {
                    showToast(`${selectedFactor} 인증을 시작합니다.`, "success");
                    sessionStorage.setItem("currentMfaFactor", selectedFactor); // 현재 진행 중인 팩터 저장
                    setTimeout(() => {
                        window.location.href = result.nextStepUrl; // 예: /mfa/verify/ott, /mfa/verify/passkey
                    }, 1000);
                } else {
                    displayMessage(result.message || `선택한 인증 수단(${selectedFactor}) 처리 중 오류 발생`, "error");
                }
            } catch (error) {
                console.error("Error selecting MFA factor:", error);
                displayMessage("인증 수단 선택 중 오류가 발생했습니다.", "error");
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
});