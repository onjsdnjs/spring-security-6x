document.getElementById("ottForm").addEventListener("submit", async e => {
    e.preventDefault();
    const email = document.getElementById("email").value;
    const msg   = document.getElementById("message");
    try {
        const res = await fetch("/ott/generate", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
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