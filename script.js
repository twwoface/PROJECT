document.addEventListener("DOMContentLoaded", function() {
    const formTitle = document.getElementById("form-title");
    const submitBtn = document.getElementById("submit-btn");
    const toggleForm = document.getElementById("toggle-form");

    let isLogin = true;

    toggleForm.addEventListener("click", function(event) {
        event.preventDefault();
        isLogin = !isLogin;

        formTitle.textContent = isLogin ? "Login" : "Sign Up";
        submitBtn.textContent = isLogin ? "Login" : "Sign Up";
        toggleForm.innerHTML = isLogin
            ? "Don't have an account? <a href='#'>Sign Up</a>"
            : "Already have an account? <a href='#'>Login</a>";
    });

    document.getElementById("auth-form").addEventListener("submit", function(event) {
        event.preventDefault();

        const college = document.getElementById("college").value;
        const admission = document.getElementById("admission").value;
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        if (!college || !admission || !email || !password) {
            alert("Please fill all fields!");
            return;
        }

        if (isLogin) {
            alert(`Logging in with ${email}`);
        } else {
            alert(`Signing up with ${email}`);
        }
    });
});



document.addEventListener("DOMContentLoaded", function() {
    const loginForm = document.getElementById("login-form");
    const signupForm = document.getElementById("signup-form");

    if (loginForm) {
        loginForm.addEventListener("submit", function(event) {
            event.preventDefault();
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            if (!email || !password) {
                alert("Please fill all fields!");
                return;
            }

            alert(`Logging in with ${email}`);
        });
    }

    if (signupForm) {
        signupForm.addEventListener("submit", function(event) {
            event.preventDefault();
            const fullName = document.getElementById("full-name").value;
            const college = document.getElementById("college").value;
            const admission = document.getElementById("admission").value;
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            if (!fullName || !college || !admission || !email || !password) {
                alert("Please fill all fields!");
                return;
            }

            alert(`Signing up with ${email}`);
        });
    }
});
