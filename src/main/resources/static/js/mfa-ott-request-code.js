// static/js/mfa-ott-request-code.js
document.addEventListener("DOMContentLoaded", () => {
    const requestCodeForm = document.getElementById("mfaOttRequestCodeForm");
    const emailInput = document.getElementById("mfaOttEmail");
    const messageDiv = document.getElementById("mfaOttRequestMessage");
    const sendButton = document.getElementById("sendMfaOttCodeBtn");

    if (!requestCodeForm || !emailInput || !sendButton) {
        console.warn("MFA OTT Request Code form elements not found.");
        return;
    }

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername"); // 1차 인증 시 저장된 username (이메일)

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 없습니다. 다시 로그인해주세요.", "error");
        sendButton.disabled = true;
        return;
    }

    emailInput.value = username; // 사용자 이메일을 읽기 전용 필드에 표시

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : 'text-green-500'}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    // 이 JS는 폼의 기본 제출(action="/mfa/ott/generate", method="POST")을 사용하므로,
    // 별도의 fetch 로직은 필요 없을 수 있습니다.
    // Spring Security의 GenerateOneTimeTokenFilter가 폼 제출을 직접 처리하고,
    // 성공 시 MagicLinkHandler (OneTimeTokenGenerationSuccessHandler)에 의해
    // /ott/sent 페이지로 리다이렉션합니다.
    // 만약 AJAX로 처리하고 싶다면, 아래와 같이 fetch 사용.
    /*
    requestCodeForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        sendButton.disabled = true;
        displayMessage("인증 코드를 요청 중입니다...", "info");

        const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
        const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded", // GenerateOneTimeTokenFilter는 form data 기대
            "X-MFA-Session-Id": mfaSessionId, // 이 헤더는 GenerateOneTimeTokenFilter가 직접 사용하지 않음
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        const formData = new URLSearchParams();
        formData.append('username', username); // Spring Security 필터가 username 파라미터로 이메일 기대
        if (csrfToken) formData.append(csrfHeaderMeta.getAttribute("name"), csrfToken);


        try {
            const response = await fetch('/mfa/ott/generate', { // 서버의 GenerateOneTimeTokenFilter 처리 경로
                method: "POST",
                headers: headers,
                body: formData.toString()
            });

            // GenerateOneTimeTokenFilter 성공 시 MagicLinkHandler가 리다이렉션하므로,
            // 클라이언트에서 response.ok 등을 체크하기 전에 페이지가 이동될 것임.
            // 만약 JSON 응답을 받도록 커스터마이징했다면 아래 로직 유효.
            if (response.ok) { // 보통은 302 Redirect 후 /ott/sent 로 감
                 // const result = await response.json(); // 서버가 JSON을 반환한다면
                 // displayMessage(result.message || "코드가 발송되었습니다.", "success");
                 // window.location.href = "/ott/sent?email=" + encodeURIComponent(username);
            } else {
                const errorText = await response.text();
                displayMessage("코드 요청 실패: " + errorText, "error");
                sendButton.disabled = false;
            }
        } catch (error) {
            console.error("Error requesting MFA OTT code:", error);
            displayMessage("코드 요청 중 네트워크 오류가 발생했습니다.", "error");
            sendButton.disabled = false;
        }
    });
    */
    logClientSideMfaOttRequest(`OTT Code Request UI loaded for ${username}. Form action: ${requestCodeForm.action}`);
    // getOrCreateDeviceId 함수는 다른 JS 파일에서 복사 또는 공통 유틸로 분리
    function getOrCreateDeviceId() { let d = localStorage.getItem("deviceId"); if(!d){d=crypto.randomUUID();localStorage.setItem("deviceId",d);} return d;}
});

function logClientSideMfaOttRequest(message) {
    console.log("[Client MFA OTT Request Code] " + message);
}