let before = document.getElementById("before");
let after = document.getElementById("after");

$(window).scroll(function () {
  if ($(this).scrollTop() > 50) {
    after.style.display = "block"
    before.style.display = 'none'
  } else {
    after.style.display = "none"
    before.style.display = 'block'
  }
});