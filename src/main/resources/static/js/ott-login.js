document.addEventListener("DOMContentLoaded", () => {
    const form       = document.getElementById("ottForm");
    const msg        = document.getElementById("message");
    const csrfToken  = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    form.addEventListener("submit", async e => {
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
                body: new URLSearchParams({ username: email }) // 'username' 키로 전달
            });
            if (res.ok) {
                // 성공 시 발송 완료 페이지로 이동
                window.location.href = `/ott/sent?email=${encodeURIComponent(email)}`;
            } else {
                throw new Error();
            }
        } catch {
            msg.innerText = "토큰 요청에 실패했습니다.";
            msg.style.display = "block";
        }
    });
});