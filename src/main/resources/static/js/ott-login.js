document.addEventListener("DOMContentLoaded", () => {
    const form       = document.getElementById("ottForm");
    const msg        = document.getElementById("message");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').getAttribute("content");
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').getAttribute("content");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("email").value;

        try {
            const res = await fetch("/ott/generate", {
                method:      "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    [csrfHeader]:    csrfToken
                },
                body: new URLSearchParams({ email })
            });

            msg.innerText = res.ok
                ? "로그인 링크가 전송되었습니다 (시뮬레이션)."
                : "전송에 실패했습니다.";
        } catch {
            msg.innerText = "서버 오류가 발생했습니다.";
        }
        msg.style.display = "block";
    });
});
