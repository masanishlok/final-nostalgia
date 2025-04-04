document.getElementById("register-form").addEventListener("submit", async function (event) {
    event.preventDefault();

    const name = document.getElementById("name").value;
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const phone = document.getElementById("phone").value;
    const dob = document.getElementById("dob").value;
    const address = document.getElementById("address").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirm_password").value;

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return;
    }

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, username, email, phone, dob, address, password }),
        });

        const data = await response.json();
        if (response.ok) {
            alert("Registration successful! You can now log in.");
            window.location.href = "/login";
        } else {
            alert("Registration failed: " + data.error);
        }
    } catch (error) {
        console.error("Error during registration:", error);
        alert("An error occurred. Please try again.");
    }
});
