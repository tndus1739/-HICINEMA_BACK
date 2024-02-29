document.addEventListener('DOMContentLoaded', function() {
    // 사용자 정보 설정
    var username = "김설";
    var userGrade = "VIP"; // 등급: 일반회원, 실버, 골드, VIP
    var paymentHistory = "결제내역 없음";
    var bookingInfo = "예매 정보 없음";
    let points = 1000;
    
    // 사용자 정보 업데이트
    document.getElementById('username').textContent = username;
    document.getElementById('user-grade').textContent = userGrade;
    document.getElementById('payment-history').textContent = paymentHistory;
    document.getElementById('booking-info').textContent = bookingInfo;
    document.querySelector('#point').textContent = points;

    // 등급에 따른 색상 변경
    userGradeColor(userGrade);
});

function userGradeColor(userGrade) {
    const colors = document.querySelectorAll("#user-grade");

    colors.forEach(color => {
        if(userGrade === "일반회원"){
            color.style.color = "white";
        }else if(userGrade === "실버"){
            color.style.color = "silver";
        }else if(userGrade === "골드"){
            color.style.color = "#DAA520";
        }else{
            color.style.color = "#98b7fa";
        }
    });
}

function viewPaymentHistory() {
    // 결제내역 상세 페이지로 이동
    window.location.href = "payment-history.html";
}

function viewBookingInfo() {
    // 예매정보 상세 페이지로 이동
    window.location.href = "booking-info.html";
}
