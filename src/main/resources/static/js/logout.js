document.addEventListener("DOMContentLoaded", () => {
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    // 헤더 링크
    const logoutLink = document.getElementById("logoutLink");
    if (logoutLink) {
        logoutLink.addEventListener("click", async (e) => {
            e.preventDefault();
            await fetch("/logout", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    [csrfHeader]: csrfToken
                }
            });
            window.location.href = "/loginForm";
        });
    }
});