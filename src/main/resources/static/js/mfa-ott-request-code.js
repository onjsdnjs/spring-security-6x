// static/js/mfa-ott-request-code.js
document.addEventListener("DOMContentLoaded", () => {
    const requestCodeForm = document.getElementById("mfaOttRequestCodeForm");
    const emailInput = document.getElementById("mfaUsername"); // 서버에서 전달된 username (readonly)
    const messageDiv = document.getElementById("mfaOttRequestMessage");
    const sendButton = requestCodeForm ? requestCodeForm.querySelector("button[type='submit']") : null;

    if (!requestCodeForm || !emailInput || !sendButton) {
        console.warn("MFA OTT Request Code form elements not found. Ensure form ID is 'mfaOttRequestCodeForm', email input ID is 'mfaUsername', and there is a submit button.");
        const mainMessageDiv = document.getElementById("mfaOttRequestMessage") || document.body;
        if (mainMessageDiv) {
            mainMessageDiv.innerHTML = '<p class="text-error font-medium">페이지 구성 오류. 관리자에게 문의하세요.</p>';
            if(typeof showToast === 'function') showToast("페이지 구성 오류", "error");
        }
        return;
    }

    // 폼의 action URL은 LoginController 에서 모델을 통해 전달받아 th:action에 설정됩니다.
    // 이 URL은 Spring Security의 GenerateOneTimeTokenFilter가 처리할 경로입니다.
    const formActionUrl = requestCodeForm.getAttribute("action");

    if (!formActionUrl) {
        displayMessage("코드 생성 요청 URL이 설정되지 않았습니다. 관리자에게 문의하세요.", "error");
        sendButton.disabled = true;
        return;
    }
    logClientSideMfaOttRequest(`MFA OTT Code Request UI loaded. Form will POST to: ${formActionUrl} for user: ${emailInput.value}`);

    function displayMessage(message, type = 'info', clearAfter = 0) {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-500' : 'text-blue-500')}">${message}</p>`;
            messageDiv.classList.remove('hidden');
            if (clearAfter > 0) {
                setTimeout(() => {
                    messageDiv.innerHTML = '';
                    messageDiv.classList.add('hidden');
                }, clearAfter);
            }
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    requestCodeForm.addEventListener("submit", (event) => {
        // 폼 제출 시 버튼 비활성화 및 로딩 메시지 표시
        sendButton.disabled = true;
        sendButton.classList.add("opacity-50", "cursor-not-allowed");
        sendButton.innerHTML = `
            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            처리 중...
        `;
        displayMessage("인증 코드를 요청 중입니다...", "info");
        logClientSideMfaOttRequest("Form is being submitted to " + formActionUrl + " for OTT code generation.");
        // 폼은 기본 동작으로 서버에 제출됩니다 (Spring Security Filter Chain으로).
        // event.preventDefault(); // 주석 처리하여 폼이 제출되도록 합니다.
    });

    // username은 서버에서 FactorContext를 통해 가져와서 hidden input 등으로 제공하거나,
    // GenerateOneTimeTokenFilter가 Principal에서 가져오도록 설정.
    // 여기서는 login-mfa-ott-request-code.html 에서 <input type="hidden" name="username" th:value="${username}" /> 가 있다고 가정.
    const usernameFromModel = emailInput.value;
    if (!usernameFromModel) {
        displayMessage("사용자 정보를 가져올 수 없습니다. 다시 로그인해주세요.", "error");
        if(typeof showToast === 'function') showToast("사용자 정보 없음", "error");
        sendButton.disabled = true;
    }

    // URL 파라미터에 에러가 있는 경우 (예: GenerateOneTimeTokenFilter의 FailureHandler가 리다이렉션한 경우)
    const urlParams = new URLSearchParams(window.location.search);
    const errorParam = urlParams.get('error'); // LoginController 또는 핸들러에서 error 파라미터로 전달
    const messageParam = urlParams.get('message'); // 또는 message 파라미터

    if (errorParam || messageParam) {
        let displayErrorMessage = messageParam || "코드 발송에 실패했습니다. 잠시 후 다시 시도해주세요.";
        if (errorParam === 'token_generation_failed') {
            displayErrorMessage = "인증 코드 생성에 실패했습니다. 입력 정보를 확인하거나 잠시 후 다시 시도해주세요.";
        } else if (errorParam === 'invalid_ott_request_ui_context') {
            displayErrorMessage = "잘못된 OTT 코드 요청입니다. 인증을 다시 시작해주세요.";
        }
        // 다른 특정 에러 코드에 대한 처리 추가 가능
        displayMessage(displayErrorMessage, "error");
        if(sendButton) { // sendButton이 null이 아닐 때만 접근
            sendButton.disabled = false;
            sendButton.classList.remove("opacity-50", "cursor-not-allowed");
            sendButton.innerHTML = '인증 코드 발송';
        }
    }
});

function logClientSideMfaOttRequest(message) {
    console.log("[Client MFA OTT Request Code] " + message);
}