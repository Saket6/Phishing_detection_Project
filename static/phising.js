const modal = document.querySelector("#modal");
const loginButtons = document.querySelectorAll(`[data-js="loginButton"]`);

for (const loginButton of loginButtons) {
	loginButton.addEventListener("click", () => {
		modal.showModal();
	});
}
window.onclick = function (e) {
	if (e.target == modal) {
		modal.close();
	}
};

// Modal inside logic
const signUpGhostButton = document.getElementById("signUp");
const signInGhostButton = document.getElementById("signIn");
const container = document.getElementById("container");

signUpGhostButton.addEventListener("click", () => {
	container.classList.add("right-panel-active");
});

signInGhostButton.addEventListener("click", () => {
	container.classList.remove("right-panel-active");
});