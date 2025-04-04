document.addEventListener("DOMContentLoaded", function () {
    console.log("Auth Script Loaded!");

    // --- Login Form Submission ---
    document.getElementById("login-form").addEventListener("submit", async function (event) {
        event.preventDefault(); // Prevent page reload

        const email = document.querySelector("#login-form input[type='email']").value;
        const password = document.querySelector("#login-form input[type='password']").value;

        try {
            const response = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();
            if (response.ok) {
                console.log("Login successful!", data);
                window.location.href = "/dashboard"; // Redirect on success
            } else {
                alert("Login failed: " + data.error);
            }
        } catch (error) {
            console.error("Error during login:", error);
        }
    });

    // --- Signup Form Submission ---
    document.getElementById("signup-form").addEventListener("submit", async function (event) {
        event.preventDefault(); // Prevent page reload

        const fullName = document.querySelector("#signup-form input[type='text']").value;
        const email = document.querySelector("#signup-form input[type='email']").value;
        const password = document.querySelector("#signup-form input[type='password']").value;

        try {
            const response = await fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: fullName, email, password }),
            });

            const data = await response.json();
            if (response.ok) {
                alert("Signup successful! Please log in.");
                document.getElementById("show-login").click(); // Switch to login
            } else {
                alert("Signup failed: " + data.error);
            }
        } catch (error) {
            console.error("Error during signup:", error);
        }
    });
});
