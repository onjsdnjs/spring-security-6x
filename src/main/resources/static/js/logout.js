document.addEventListener("DOMContentLoaded", () => {
    const logoutLink = document.getElementById("logoutLink");
    const loginLink  = document.getElementById("loginLink");
    const registerLink  = document.getElementById("registerLink");
    if (!logoutLink) return;

    const authMode = localStorage.getItem("authMode");
    let csrfToken = null;
    let csrfHeader = null;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    if (csrfTokenMeta && csrfHeaderMeta) {
        csrfToken = csrfTokenMeta.getAttribute("content");
        csrfHeader = csrfHeaderMeta.getAttribute("content");
    }

    logoutLink.addEventListener("click", async (e) => {
        e.preventDefault();

        const headers = {};
        if (authMode !== "header" && csrfHeader && csrfToken) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            await fetch("/api/auth/logout", {
                method: "POST",
                credentials: "same-origin",
                headers
            });
        } catch (err) {
            console.warn("서버 로그아웃 실패 (무시):", err);
        }

        TokenMemory.accessToken = null;
        TokenMemory.refreshToken = null;
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");

        // JS 기반 인증 UI 갱신
        if (authMode === "header" || authMode === "header_cookie") {
            if (logoutLink) logoutLink.style.display = "none";
            if (loginLink)  loginLink.style.display = "inline-block";
            if (registerLink)  registerLink.style.display = "inline-block";
        }

        window.location.href = "/loginForm";
    });
});

