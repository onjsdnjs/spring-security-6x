// CSRF 토큰 헬퍼 그대로
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    return parts.length === 2
        ? parts.pop().split(';').shift()
        : null;
}

document.addEventListener("DOMContentLoaded", () => {
    const logoutLink = document.getElementById("logoutLink");
    if (logoutLink) {
        logoutLink.addEventListener("click", async (e) => {
            e.preventDefault();                       // 기본 a 태그 이동 막고
            const csrfToken = getCookie("XSRF-TOKEN");
            await fetch("/logout", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "X-XSRF-TOKEN": csrfToken
                }
            });
            window.location.href = "/loginForm";
        });
    }
});
