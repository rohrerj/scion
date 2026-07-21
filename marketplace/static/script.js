function editBalance(id, name) {
    editingAccountId = id;
    mainAccountId = document.getElementById("main-account-id").textContent;
    document.getElementById("balance-editor").style.display = "block";
    document.getElementById("balance-user-name").textContent = name;
    document.getElementById("balance-value").value = 0;
}
async function saveBalance() {
    const balance = document.getElementById("balance-value").value;

    const response = await fetch(`/account/balance`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "from=" + encodeURIComponent(mainAccountId) + "&to=" + encodeURIComponent(editingAccountId) + "&amount=" + encodeURIComponent(balance)
    });

    if (!response.ok) {
        if (response.status == 401) {
            location.reload();
            return;
        }
        document.getElementById("error").textContent = await response.text();
        return;
    }

    location.reload();
}
async function requestJWT(id, name) {
    const response = await fetch("/account/token", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "id=" + encodeURIComponent(id)
    });

    if (!response.ok) {
        if (response.status == 401) {
            location.reload();
            return;
        }
        document.getElementById("error").textContent = await response.text()
        return;
    }

    const token = await response.text();

    document.getElementById("jwt-token").innerText = token;
    document.getElementById("jwt-container").style.display = "block";
    document.getElementById("jwt-user-name").textContent = name;
}
async function deleteAccount(id, name) {
    if (!confirm(`Delete account "${name}"?`)) {
        return;
    }

    const response = await fetch("/account/delete", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "id=" + encodeURIComponent(id)
    });

    if (!response.ok) {
        if (response.status == 401) {
            location.reload();
            return;
        }
        document.getElementById("error").textContent = await response.text();
        return;
    }

    location.reload();
}
async function resetJWT(id, name) {
    if (!confirm(`Reset JWT token for account "${name}"?`)) {
        return;
    }

    const response = await fetch("/account/resetjwt", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "id=" + encodeURIComponent(id)
    });

    if (!response.ok) {
        if (response.status == 401) {
            location.reload();
            return;
        }
        document.getElementById("error").textContent = await response.text();
        return;
    }
    location.reload();
}
function copyJWT() {
    const token = document.getElementById("jwt-token").innerText;

    navigator.clipboard.writeText(token)
        .then(() => {
            const element = document.getElementById("jwt-token");
            const oldText = element.dataset.originalText || token;

            element.dataset.originalText = oldText;
            element.innerText = "Copied!";

            setTimeout(() => {
                element.innerText = oldText;
            }, 500);
        })
        .catch(err => {
            document.getElementById("error").textContent = "Could not copy token: " + err;
        });
}