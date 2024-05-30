$(document).ready(function () {

    $(".book-modal").click(function (e) {
        e.preventDefault();
        let url = this.getAttribute("href");

        fetch(url)
            .then(response => response.text())
            .then(data => {
                $("#quickModal .modal-dialog").html(data)
            })

        $("#quickModal").modal('show');
    })
})

$(document).on("click", ".load-comments", function (e) {
    e.preventDefault();

    var nextPage = $(this).attr("data-nextpage");
    var url = $(this).attr("href") + "?page=" + nextPage;

    fetch(url)
        .then(response => response.text())
        .then(data => {
            $(".reviews").append(data);
        });

    var totalPage = +$(this).data("totalpage");
    nextPage++;

    if (nextPage > totalPage) {
        $(this).remove();
    }
    $(this).attr("data-nextpage", nextPage);
});



$(".order-detail-view").click(function (e) {
    e.preventDefault();
    let url = this.getAttribute("href");

    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        })
        .then(data => {
            $("#orderDetailModal .modal-dialog").html(data);
            $("#orderDetailModal").modal('show');
        })
        .catch(error => {
            console.error('Fetch Error:', error);
            alert('There was an error loading the order details!');
        });
});



$(".add-to-basket").click(function (e) {
    e.preventDefault();

    let url = this.getAttribute("href");

    fetch(url)
        .then(response => response.text())
        .then(data => {
            $(".cart-widget .cart-block").remove()
            $(".cart-widget").append(data)
        })
})


