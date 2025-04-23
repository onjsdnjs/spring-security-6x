document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("loginForm");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const data = {
            username: form.username.value,
            password: form.password.value
        };

        try {
            const res = await fetch("/api/auth/login", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    [csrfHeader]:    csrfToken
                },
                body: JSON.stringify(data)
            });

            if (res.ok) {
                window.location.href = "/";
            } else {
                const error = await res.json().catch(() => null);
                alert("로그인 실패: " + (error?.message || res.statusText));
            }
        } catch (err) {
            console.error("로그인 요청 중 오류:", err);
            alert("로그인 중 오류가 발생했습니다.");
        }
    });
});