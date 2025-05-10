(async function initAuthFlow() {
    const authMode = localStorage.getItem("authMode");
    if (!authMode) return;

    let csrfToken = null;
    let csrfHeader = null;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    if (csrfTokenMeta && csrfHeaderMeta) {
        csrfToken = csrfTokenMeta.getAttribute("content");
        csrfHeader = csrfHeaderMeta.getAttribute("content");
    }

    const headers = {
        "Content-Type": "application/json"
    };

    if (authMode !== "header" && csrfHeader && csrfToken) {
        headers[csrfHeader] = csrfToken;
    }

    function updateLoginUi() {
        const loginLink  = document.getElementById("loginLink");
        const registerLink = document.getElementById("registerLink");
        const logoutLink = document.getElementById("logoutLink");

        if (authMode === "header" || authMode === "header_cookie") {
            const access = TokenMemory.accessToken;
            const isLoggedIn = !!access?.trim();

            if (loginLink)  loginLink.style.display  = isLoggedIn ? "none" : "inline-block";
            if (registerLink)  registerLink.style.display  = isLoggedIn ? "none" : "inline-block";
            if (logoutLink) logoutLink.style.display = isLoggedIn ? "inline-block" : "none";
        }
    }

    if (authMode === "cookie") {
        updateLoginUi();
        return;
    }

    try {
        const res = await fetch("/api/auth/refresh", {
            method: "POST",
            credentials: "same-origin",
            headers
        });

        if (res.status === 204) {
            console.log("리프레시 토큰 없음: 로그인 상태 아님");

        } else if (res.status === 401) {
            console.warn("리프레시 토큰 만료 또는 위조로 서버에서 로그아웃됨");
            handleClientLogout();
            return;
        } else if (res.ok) {
            const data = await res.json();
            TokenMemory.accessToken = data.accessToken;
            if (authMode === "header") {
                TokenMemory.refreshToken = data.refreshToken;
            }
            console.log("AccessToken 복원 완료");
        }
    } catch (err) {
        console.warn("토큰 복원 실패:", err);
        handleClientLogout();
        return;
    }

    updateLoginUi();

    function handleClientLogout() {
        TokenMemory.accessToken = null;
        TokenMemory.refreshToken = null;
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");

        if (authMode === "header" || authMode === "header_cookie") {
            const loginLink = document.getElementById("loginLink");
            const registerLink = document.getElementById("registerLink");
            const logoutLink = document.getElementById("logoutLink");
            if (logoutLink) logoutLink.style.display = "none";
            if (loginLink)  loginLink.style.display = "inline-block";
            if (registerLink)  registerLink.style.display = "inline-block";
        }

        window.location.href = "/loginForm";
    }
})();