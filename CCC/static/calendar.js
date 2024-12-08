// calendar.js

document.addEventListener('DOMContentLoaded', function() {
    var calendarEl = document.getElementById('calendar');

    var calendar = new FullCalendar.Calendar(calendarEl, {
        plugins: ['dayGrid', 'timeGrid'],
        initialView: 'dayGridMonth',
        events: [
            {% for event in events %}
                {
                    title: "{{ event[1] }}",  // 제목
                    start: "{{ event[2] }}",  // 날짜
                    description: "{{ event[3] }}",  // 설명
                },
            {% endfor %}
        ],
        dateClick: function(info) {
            showEventModal(info.dateStr);  // 날짜 클릭 시 모달 창 띄우기
        }
    });

    calendar.render();
});

// 모달 창 열기
function showEventModal(date) {
    document.getElementById('event-modal').style.display = "flex";
    document.getElementById('date').value = date;
}

// 모달 창 닫기
function closeModal() {
    document.getElementById('event-modal').style.display = "none";
}
