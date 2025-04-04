document.addEventListener("DOMContentLoaded", function () {
    console.log("User Dashboard Loaded!");

    const userGreeting = document.getElementById("user-greeting");
    const yearSelect = document.getElementById("year-select");
    const saveYearBtn = document.getElementById("save-year");
    const logoutBtn = document.getElementById("logout-btn");
    const nostalgiaContent = document.getElementById("nostalgia-content");

    // --- Fetch User Details ---
    async function fetchUserDetails() {
        try {
            const response = await fetch("/get_user_data"); // Flask backend route
            const data = await response.json();

            if (data.username) {
                userGreeting.innerText = `Welcome, ${data.username}!`;
            } else {
                window.location.href = "/login"; // Redirect if user not logged in
            }
        } catch (error) {
            console.error("Error fetching user data:", error);
        }
    }

    // --- Populate Year Selection (1950-2025) ---
    function populateYears() {
        for (let year = 1950; year <= 2025; year++) {
            const option = document.createElement("option");
            option.value = year;
            option.textContent = year;
            yearSelect.appendChild(option);
        }
    }

    // --- Fetch Nostalgia Data Based on Year ---
    async function fetchNostalgiaData(selectedYear) {
        try {
            const response = await fetch(`/get_nostalgia_data/${selectedYear}`);
            const data = await response.json();

            nostalgiaContent.innerHTML = `
                <h3>Memories from ${selectedYear}</h3>
                <p>🎵 Music: ${data.music}</p>
                <p>🎬 Movies: ${data.movies}</p>
                <p>📺 TV Shows: ${data.tv_shows}</p>
                <p>📰 Headlines: ${data.headlines}</p>
            `;
        } catch (error) {
            console.error("Error fetching nostalgia data:", error);
        }
    }

    // --- Save Selected Year ---
    saveYearBtn.addEventListener("click", function () {
        const selectedYear = yearSelect.value;
        fetchNostalgiaData(selectedYear);
    });

    // --- Logout User ---
    logoutBtn.addEventListener("click", function () {
        window.location.href = "/logout";
    });

    // --- Initialize Dashboard ---
    fetchUserDetails();
    populateYears();
});
