$(".delete-btn").click(function (e) {
    e.preventDefault();

    let url = $(this).attr("href");


    Swal.fire({
        title: "Are you sure?",
        text: "You won't be able to revert this!",
        icon: "warning",
        showCancelButton: true,
        confirmButtonColor: "#3085d6",
        cancelButtonColor: "#d33",
        confirmButtonText: "Yes, delete it!"
    }).then((result) => {
        if (result.isConfirmed) {

            fetch(url)
                .then(response => {
                    if (response.ok) {
                        Swal.fire({
                            title: "Deleted!",
                            text: "Your file has been deleted.",
                            icon: "success"
                        }).then(() => {
                            window.location.reload();
                        })
                    }
                    else {
                        Swal.fire({
                            title: "Sorry!",
                            text: "Something went wrong",
                            icon: "error"
                        })
                    }
                })
        }
    });
});




function previewImage(input) {
    if (input.files && input.files[0]) {
        var reader = new FileReader();
        reader.onload = function (e) {
            var imgElement = document.getElementById("previewImg")
            imgElement.setAttribute("src",e.target.result)
           
                    }
reader.readAsDataURL(input.files[0]);
    }
}


                            ﻿
/*document.addEventListener("DOMContentLoaded", function () {
    var imgInputs = document.querySelectorAll(".imgInput");
    imgInputs.forEach(function (input) {
        input.addEventListener("change", function (e) {
            var box = this.parentElement.querySelector(".preview-box");
            box.innerHTML = "";

            for (var i = 0; i < e.target.files.length; i++) {
                var img = document.createElement("img");
                img.style.width = "200px";
                img.classList.add("previewImg");

                var reader = new FileReader();
                reader.readAsDataURL(e.target.files[i]);
                reader.onload = (function (img) {
                    return function (event) {
                        img.setAttribute("src", event.target.result);
                        box.appendChild(img);
                    };
                })(img);
            }
        });
    });
});*/

$(document).ready(function () {
    $(".imgInput").change(function (e) {
        let box = $(this).parent().find(".preview-box");
        $(box).find(".previewImg").remove();

        if ($(this).hasClass("create")) {
            for (var i = 0; i < e.target.files.length; i++) {
                let img = document.createElement("img");
                img.style.width = "200px";
                img.classList.add("previewImg");

                let reader = new FileReader();
                reader.readAsDataURL(e.target.files[i]);
                reader.onload = () => {
                    img.setAttribute("src", reader.result);
                    $(box).append(img);
                }
            }
        }
        else {
            for (var i = 0; i < e.target.files.length; i++) {
                let img = document.createElement("img");
                img.style.width = "200px";
                img.classList.add("previewImg");

                let reader = new FileReader();
                reader.readAsDataURL(e.target.files[i]);
                reader.onload = () => {
                    img.setAttribute("src", reader.result);
                    $(box).append(img);
                }
            }
        }
    })
});



    $(".remove-img-icon").click(function () {
        $(this).parent().remove();
    })

document.querySelectorAll(".remove-img-btn").addEventListener("click", function () {
    this.parentElement().remove();
})