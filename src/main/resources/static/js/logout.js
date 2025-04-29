document.addEventListener("DOMContentLoaded", () => {
    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    const logoutLink = document.getElementById("logoutLink");
    if (!logoutLink) return;

    logoutLink.addEventListener("click", async (e) => {
        e.preventDefault();

        const response = await fetch("/logout", {
            method:      "POST",
            credentials: "same-origin",             // 쿠키 전송
            headers: {
                [csrfHeader]: csrfToken,            // CSRF 헤더
                "Accept": "application/json"        // JSON 응답 명시(Optional)
            }
        });

        if (response.ok) {
            const data = await response.json();
            alert(data.message);
            window.location.href = "/loginForm";
        } else {
            console.error("로그아웃 실패:", response.status);
            alert("로그아웃에 실패했습니다.");
        }
    });
});