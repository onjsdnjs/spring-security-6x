(async function initAuthFlow() {
    const authMode = localStorage.getItem("authMode");
    if (!authMode || authMode === "cookie") return;
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

    try {
        const res = await fetch("/api/auth/refresh", {
            method: "POST",
            credentials: "same-origin",
            headers
        });

        if (res.ok) {
            if (res.status === 204) {
                console.log("리프레시 토큰 생성 전 상태");

            } else if (res.status === 401) {
                console.log("리프레시 토큰 만료 및 변조 등의 오류");
                TokenMemory.accessToken = null;
                TokenMemory.refreshToken = null;
                localStorage.removeItem("accessToken");
                localStorage.removeItem("refreshToken");

                updateLoginUi();
                window.location.href = "/loginForm";
                return;
            }else {
                const data = await res.json();
                TokenMemory.accessToken = data.accessToken;
                if (authMode === "header") {
                    TokenMemory.refreshToken = data.refreshToken;
                }
                console.log("AccessToken 복원 완료");
            }
        }
    } catch (err) {
        console.warn("토큰 복원 실패:", err);
    }

    updateLoginUi();
})();
