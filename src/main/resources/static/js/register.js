document.addEventListener("DOMContentLoaded", () => {
    const form       = document.getElementById("registerForm");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const data = {
            username: form.username.value,
            email:    form.email.value,
            password: form.password.value,
            roles:    form.roles.value
        };

        try {
            const res = await fetch("/api/register", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    [csrfHeader]:    csrfToken
                },
                body: JSON.stringify(data)
            });

            if (res.ok) {
                alert("회원가입 성공!");
                window.location.href = "/loginForm";
            } else {
                alert("회원가입 실패");
            }
        } catch (err) {
            console.error("회원가입 요청 중 오류:", err);
            alert("회원가입 중 오류가 발생했습니다.");
        }
    });
});