document.addEventListener("DOMContentLoaded", () => {
    const ottForm = document.getElementById("ottForm");
    const emailInput = document.getElementById("email");
    const messageContainer = document.getElementById("messageContainer"); // 메시지 표시 영역

    if (!ottForm || !emailInput) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    function displayMessage(message, type = 'info') {
        if (messageContainer) {
            messageContainer.innerHTML = `<p class="text-sm ${type === 'error' ? 'text-red-600' : 'text-green-600'}">${message}</p>`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    ottForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const email = emailInput.value;
        if (!email) {
            displayMessage("이메일을 입력해주세요.", "error");
            return;
        }

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded" // 서버가 x-www-form-urlencoded를 기대
        };
        if (csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            // 서버의 `/ott/generate`는 username 파라미터를 기대
            const response = await fetch("/ott/generate", {
                method: "POST",
                credentials: "same-origin",
                headers: headers,
                body: new URLSearchParams({ username: email })
            });

            if (response.ok) {
                // 성공 시 서버에서 /ott/sent?email=... 로 리다이렉션 하거나,
                // 클라이언트가 직접 이동. 현재 서버 코드는 sendRedirect를 사용.
                // 여기서는 MagicLinkHandler가 sendRedirect를 하므로 별도 처리 불필요.
                // 만약 서버가 JSON 응답을 주고 클라이언트가 리다이렉트해야 한다면 아래와 같이 처리:
                // window.location.href = `/ott/sent?email=${encodeURIComponent(email)}`;
                // MagicLinkHandler가 이미 리다이렉션을 처리하므로, 이 JS 에서는 특별한 성공 후 작업이 없을 수 있음.
                // 서버가 리다이렉션 하지 않는 경우를 대비하여 아래 메시지 추가 (실제로는 서버 리다이렉션에 의해 도달하지 않을 수 있음)
                displayMessage("인증 메일 요청이 전송되었습니다. 메일함을 확인해주세요.", "success");
                // 실제로는 서버의 MagicLinkHandler 에서 redirect 하므로 아래 라인은 실행되지 않을 가능성이 높음
                setTimeout(() => {
                    if (!window.location.pathname.includes('/ott/sent')) { // 이미 이동하지 않았다면
                        window.location.href = `/ott/sent?email=${encodeURIComponent(email)}`;
                    }
                }, 500);


            } else {
                const errorData = await response.json().catch(() => ({ message: "토큰 요청에 실패했습니다." }));
                console.error("OTT request failed:", errorData);
                displayMessage(`오류: ${errorData.message || response.statusText}`, "error");
            }
        } catch (error) {
            console.error("OTT request error:", error);
            displayMessage("토큰 요청 중 오류가 발생했습니다.", "error");
        }
    });
});