document.getElementById('year-selector').addEventListener('change', function() {
    alert("Year Selected: " + this.value);
});

function editUser(userId) {
    alert("Edit user: " + userId);
}

function deleteUser(userId) {
    if (confirm("Are you sure you want to delete this user?")) {
        fetch(`/delete_user/${userId}`, { method: 'DELETE' })
            .then(response => response.json())
            .then(data => alert(data.message))
            .catch(error => console.error("Error:", error));
    }
}
