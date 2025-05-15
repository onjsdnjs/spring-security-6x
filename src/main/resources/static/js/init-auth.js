(async function initAuthFlow() {
    const authMode = localStorage.getItem("authMode") || "header"; // 기본값을 header로 설정

    // CSRF 토큰 가져오기 (모든 페이지에 CSRF 메타 태그가 있다고 가정)
    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    function updateLoginUi() {
        const loginLink = document.getElementById("loginLink");
        const registerLink = document.getElementById("registerLink");
        const logoutLink = document.getElementById("logoutLink");

        // authMode가 'cookie' 가 아닐 때 (즉, 'header' 또는 'header_cookie') UI를 JS로 제어
        if (authMode === "header" || authMode === "header_cookie") {
            const accessToken = TokenMemory.accessToken;
            const isLoggedIn = !!(accessToken && accessToken.trim());

            if (loginLink) loginLink.style.display = isLoggedIn ? "none" : "inline-block";
            if (registerLink) registerLink.style.display = isLoggedIn ? "none" : "inline-block";
            if (logoutLink) logoutLink.style.display = isLoggedIn ? "inline-block" : "none";
        } else { // 'cookie' 모드일 경우, Thymeleaf sec:authorize에 의해 UI가 제어되므로 JS 에서는 숨김/표시를 강제하지 않음
            if (loginLink) loginLink.style.display = ""; // 기본값으로 되돌림 (Thymeleaf가 제어하도록)
            if (registerLink) registerLink.style.display = "";
            if (logoutLink) logoutLink.style.display = "";
        }
    }

    // 쿠키 방식이 아닐 경우에만 리프레시 시도
    if (authMode === "header" || authMode === "header_cookie") {
        const headers = { "Content-Type": "application/json" };
        if (authMode !== "header" && csrfToken && csrfHeader) { // header_cookie 모드이고 CSRF 토큰이 있다면 헤더에 추가 (쿠키는 브라우저가 자동 전송)
            headers[csrfHeader] = csrfToken;
        }
        // 'header' 모드에서는 Refresh Token을 요청 본문에 포함해야 할 수 있음 (서버 구현에 따라 다름)
        // 현재 코드는 본문 없이 /api/auth/refresh를 호출하고, 서버가 쿠키의 Refresh Token을 사용하거나
        // 헤더 방식일 경우 별도 처리를 기대함. 명확한 서버 스펙에 따라 수정 필요.

        try {
            const response = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin", // 쿠키 전송을 위해 필요 (header_cookie 모드)
                headers: headers
            });

            if (response.status === 204) { // No Content: 유효한 리프레시 토큰 없음 (로그아웃 상태)
                console.log("Refresh: No active session (204). User is likely logged out.");
                TokenMemory.accessToken = null;
                TokenMemory.refreshToken = null; // 명시적 클리어
            } else if (response.status === 401) { // Unauthorized: 리프레시 토큰 만료 또는 무효
                console.warn("Refresh: Session expired or invalid (401). Clearing tokens.");
                TokenMemory.accessToken = null;
                TokenMemory.refreshToken = null;
            } else if (response.ok) {
                const data = await response.json();
                TokenMemory.accessToken = data.accessToken;
                if (authMode === "header") { // 'header' 모드에서만 refreshToken을 JS 메모리에 저장
                    TokenMemory.refreshToken = data.refreshToken;
                }
                console.log("Access token refreshed successfully.");
            } else {
                console.warn(`Refresh: Failed to refresh token. Status: ${response.status}`);
                TokenMemory.accessToken = null; // 실패 시 토큰 클리어
                TokenMemory.refreshToken = null;
            }
        } catch (error) {
            console.error("Refresh: Error during token refresh:", error);
            TokenMemory.accessToken = null;
            TokenMemory.refreshToken = null;
        }
    }
    updateLoginUi();
})();