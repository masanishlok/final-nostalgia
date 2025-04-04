document.getElementById("login-form").addEventListener("submit", async function (event) {
    event.preventDefault(); // Prevent form refresh

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const role = document.getElementById("role").value; // Ensure the role field exists in the form

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password, role }),
        });

        const data = await response.json();
        if (response.ok) {
            alert("Login successful!");
            if (data.role === "admin") {
                window.location.href = "/admin_panel";
            } else {
                window.location.href = "/dashboard";
            }
        } else {
            alert("Login failed: " + data.error);
        }
    } catch (error) {
        console.error("Error during login:", error);
        alert("An error occurred. Please try again.");
    }
});
