document.addEventListener("DOMContentLoaded", function () {
    console.log("Script Loaded!");

    // Redirect buttons to login page
    const buttons = document.querySelectorAll(".join-btn, .primary-btn");

    if (buttons.length > 0) {
        buttons.forEach(button => {
            button.addEventListener("click", function () {
                console.log("Button clicked! Redirecting...");
                window.location.href = "/login"; // Flask route
            });
        });
    } else {
        console.log("No buttons found!");
    }

    // Smooth scrolling for Testimonials link
    const testimonialLink = document.querySelector("a[href='#testimonials']");
    if (testimonialLink) {
        testimonialLink.addEventListener("click", function (event) {
            event.preventDefault();
            document.querySelector(".testimonial-section").scrollIntoView({ behavior: "smooth" });
        });
    }

    // Auto-Sliding Testimonials
    const testimonials = document.querySelectorAll(".testimonial-card");
    const dots = document.querySelectorAll(".testimonial-dot");
    let currentIndex = 0;
    const intervalTime = 5000; // 5 seconds

    function showTestimonial(index) {
        testimonials.forEach((testimonial, i) => {
            testimonial.classList.toggle("active", i === index);
            dots[i].classList.toggle("active", i === index);
        });
    }

    function nextTestimonial() {
        currentIndex = (currentIndex + 1) % testimonials.length;
        showTestimonial(currentIndex);
    }

    let autoSlide = setInterval(nextTestimonial, intervalTime);

    dots.forEach((dot, i) => {
        dot.addEventListener("click", () => {
            clearInterval(autoSlide);
            showTestimonial(i);
            currentIndex = i;
            autoSlide = setInterval(nextTestimonial, intervalTime);
        });
    });

    showTestimonial(currentIndex);

    // --- ADMIN PANEL SCRIPT ---
    const userTable = document.getElementById("user-table");
    const addUserForm = document.getElementById("add-user-form");
    const yearSelect = document.getElementById("year-select");
    const logoutBtn = document.getElementById("logout-btn");

    if (userTable && addUserForm && yearSelect) {
        console.log("Admin Panel Script Loaded!");

        async function fetchUsers() {
            const response = await fetch("/get_users");
            const users = await response.json();
            userTable.innerHTML = "";
            users.forEach(user => {
                userTable.innerHTML += `
                    <tr>
                        <td>${user._id}</td>
                        <td>${user.username}</td>
                        <td>${user.email}</td>
                        <td><button onclick="deleteUser('${user._id}')">Delete</button></td>
                    </tr>
                `;
            });
        }

        async function deleteUser(userId) {
            await fetch(`/delete_user/${userId}`, { method: "DELETE" });
            fetchUsers();
        }

        addUserForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const username = document.getElementById("username").value;
            const email = document.getElementById("email").value;

            await fetch("/add_user", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, email })
            });

            fetchUsers();
        });

        if (logoutBtn) {
            logoutBtn.addEventListener("click", function () {
                window.location.href = "/logout";
            });
        }

        for (let year = 1950; year <= 2025; year++) {
            yearSelect.innerHTML += `<option value="${year}">${year}</option>`;
        }

        document.getElementById("save-year").addEventListener("click", function () {
            alert(`Selected Year: ${yearSelect.value}`);
        });

        fetchUsers();
    }
});
