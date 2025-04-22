document.getElementById("ottRequestForm").addEventListener("submit", async function (event) {
    event.preventDefault();
    const email = document.getElementById("email").value;

    const response = await fetch("/ott/send-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
    });

    const message = await response.text();
    const msgBox = document.getElementById("ottMessage");
    msgBox.innerText = message;
    msgBox.style.display = "block";
});
