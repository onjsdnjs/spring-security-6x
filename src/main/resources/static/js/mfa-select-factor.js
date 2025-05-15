document.addEventListener("DOMContentLoaded", () => {
    const factorSelectionForm = document.getElementById("mfaFactorSelectionForm");
    const messageDiv = document.getElementById("factorSelectionMessage");

    if (!factorSelectionForm) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 1차 인증 시 저장된 사용자 이름

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error");
        setTimeout(() => { window.location.href = "/loginForm"; }, 2000);
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

    // 서버에서 사용 가능한 factor 목록을 가져와 버튼을 동적으로 생성하거나,
    // HTML에 미리 정의된 버튼에 이벤트 리스너를 연결합니다.
    // 이 예시에서는 HTML에 버튼이 미리 정의되어 있다고 가정합니다.
    const factorButtons = factorSelectionForm.querySelectorAll(".mfa-factor-button");

    factorButtons.forEach(button => {
        button.addEventListener("click", async () => {
            const selectedFactor = button.dataset.factor; // 예: "OTT", "PASSKEY"
            displayMessage("선택한 인증 수단을 처리 중입니다...", "info");

            const headers = { "Content-Type": "application/json" };
            if (csrfToken && csrfHeader) {
                headers[csrfHeader] = csrfToken;
            }
            headers["X-MFA-Session-Id"] = mfaSessionId; // MFA 세션 ID 헤더에 추가
            headers["X-Device-Id"] = getOrCreateDeviceId();


            try {
                // 서버 API: 선택된 Factor로 MFA 진행 요청 (예: `/api/mfa/select-factor`)
                // 이 API는 선택된 Factor에 따른 다음 페이지 URL을 반환해야 함
                const response = await fetch(`/api/mfa/select-factor`, { // 서버 엔드포인트 확인
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify({
                        factorType: selectedFactor,
                        username: username // 서버에서 사용자 식별에 필요할 수 있음
                    })
                });

                const result = await response.json();

                if (response.ok && result.nextStepUrl) {
                    // 서버가 알려준 다음 단계 URL로 이동
                    // (예: /mfa/verify/ott, /mfa/verify/passkey)
                    // 또는 result.challengeData 등을 받아 다음 단계 UI를 직접 구성할 수도 있음
                    showToast(`${selectedFactor} 인증을 시작합니다.`, "success");
                    sessionStorage.setItem("currentMfaFactor", selectedFactor); // 현재 진행 중인 팩터 저장
                    setTimeout(() => {
                        window.location.href = result.nextStepUrl;
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