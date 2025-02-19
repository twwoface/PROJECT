// Redirect to Sign Up or Login page
document.addEventListener("DOMContentLoaded", function () {
    const signUpButton = document.querySelector(".btn-signup");
    const loginButton = document.querySelector(".btn-login");

    if (signUpButton) {
        signUpButton.addEventListener("click", function (event) {
            event.preventDefault();
            window.location.href = "signup.html";
        });
    }

    if (loginButton) {
        loginButton.addEventListener("click", function (event) {
            event.preventDefault();
            window.location.href = "login.html";
        });
    }
});