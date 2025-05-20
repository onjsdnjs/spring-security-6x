// static/js/mfa-ott-request-code.js
document.addEventListener("DOMContentLoaded", () => {
    const requestCodeForm = document.getElementById("mfaOttRequestCodeForm"); // Form ID는 유지
    const emailInput = document.getElementById("mfaUsername"); // Thymeleaf 모델에서 username 바인딩
    const messageDiv = document.getElementById("mfaOttRequestMessage");
    const sendButton = document.getElementById("sendMfaOttCodeBtn");

    if (!requestCodeForm || !emailInput || !sendButton) {
        console.warn("MFA OTT Request Code form elements not found.");
        return;
    }

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    // username은 HTML 렌더링 시 Thymeleaf 모델 (th:value="${username}")에서 가져오거나, sessionStorage에서 가져올 수 있음.
    // 여기서는 emailInput.value를 신뢰.
    const username = emailInput.value;


    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 또는 사용자 정보가 없습니다. 다시 로그인해주세요.", "error");
        sendButton.disabled = true;
        return;
    }

    // Thymeleaf 모델에서 mfaSessionId를 hidden input으로 가져오도록 변경.
    // const mfaSessionIdHiddenInput = requestCodeForm.querySelector('input[name="mfaSessionId"]');
    // const mfaSessionIdFromInput = mfaSessionIdHiddenInput ? mfaSessionIdHiddenInput.value : null;
    // if (mfaSessionIdFromInput !== mfaSessionId) {
    //     displayMessage("MFA 세션 ID 불일치. 페이지를 새로고침하거나 다시 로그인해주세요.", "error");
    //     sendButton.disabled = true;
    //     return;
    // }


    function displayMessage(message, type = 'info') { // type 기본값을 info로 변경
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-500' : 'text-blue-500')}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    // HTML form의 기본 제출을 막고 AJAX로 처리
    requestCodeForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        sendButton.disabled = true;
        displayMessage("인증 코드를 요청 중입니다...", "info");

        const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
        const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

        const headers = {
            "Content-Type": "application/json",
            "X-MFA-Session-Id": mfaSessionId,
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            // MfaApiController의 /api/mfa/request-ott-code 호출
            const response = await fetch('/api/mfa/request-ott-code', {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ username: username }) // 서버에서 username은 FactorContext 것을 사용하므로, 이 username은 검증용.
            });

            const result = await response.json();

            if (response.ok && result.status === "MFA_OTT_CODE_SENT" && result.nextStepUrl) {
                displayMessage(result.message || "코드가 발송되었습니다. 코드 입력 페이지로 이동합니다.", "success");
                showToast(result.message || "코드가 발송되었습니다.", "success", 2000);
                setTimeout(() => {
                    window.location.href = result.nextStepUrl; // 예: /mfa/challenge/ott
                }, 1500);
            } else {
                displayMessage(result.message || "코드 요청에 실패했습니다.", "error");
                sendButton.disabled = false;
            }
        } catch (error) {
            console.error("Error requesting MFA OTT code:", error);
            displayMessage("코드 요청 중 네트워크 오류가 발생했습니다.", "error");
            sendButton.disabled = false;
        }
    });

    logClientSideMfaOttRequest(`MFA OTT Code Request UI loaded for ${username}.`);
    function getOrCreateDeviceId() { let d = localStorage.getItem("deviceId"); if(!d){d=crypto.randomUUID();localStorage.setItem("deviceId",d);} return d;}
});

function logClientSideMfaOttRequest(message) {
    console.log("[Client MFA OTT Request Code] " + message);
}