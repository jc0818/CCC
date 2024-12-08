from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
from flask_apscheduler import APScheduler
import pytz

app = Flask(__name__)
app.secret_key = "your_secret_key"  # 보안 키

# 데이터베이스 초기화 함수
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # 사용자 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )''')
    
    # 이벤트 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    start TEXT NOT NULL,
                    end TEXT,
                    description TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # 게시글 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # 댓글 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (post_id) REFERENCES posts (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # 친구 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    status TEXT NOT NULL, -- 요청 상태: "pending", "accepted", "rejected"
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )''')
    
    # 채팅 메시지 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )''')
    
    conn.commit()
    conn.close()


# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', (email, username, password))
            conn.commit()
            conn.close()
            flash('회원가입이 완료되었습니다!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('이미 존재하는 이메일입니다.', 'danger')

    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[2]
            flash(f'환영합니다, {user[2]}님!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('로그인 정보가 일치하지 않습니다.', 'danger')

    return render_template('login.html')

# 대시보드
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    # 현재 시간 가져오기 (offset-aware)
    now = datetime.now(pytz.timezone('Asia/Seoul'))

    # 사용자 이름 가져오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()  # 사용자 이름을 가져옵니다.
    conn.close()

    # 사용자 ID로 다음 일정 5개를 가져오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT title, start, description FROM events 
                 WHERE user_id = ? AND start > ? 
                 ORDER BY start ASC LIMIT 5''', (session['user_id'], now))
    events = c.fetchall()
    conn.close()

    # 남은 시간 계산
    event_list = []
    for event in events:
        event_title = event[0]
        event_start_str = event[1]  # '2025-03-12 06:00' 형태로 들어오는 값
        event_desc = event[2]

        # 시간 파싱 (offset-naive)
        try:
            event_start = datetime.strptime(event_start_str, '%Y-%m-%d %H:%M')  # 초를 제외한 형식
        except ValueError:
            continue  # 만약 시간이 잘못된 형식이라면 해당 일정을 넘기고 계속 진행

        # event_start를 offset-aware로 변환
        event_start = pytz.timezone('Asia/Seoul').localize(event_start)

        # 남은 시간 계산
        time_diff = event_start - now
        remaining_time = str(time_diff).split('.')[0]  # 시:분:초 형식으로 변환
        
        event_list.append({
            'title': event_title,
            'start': event_start.strftime('%Y-%m-%d %H:%M'),  # 표시할 날짜 형식
            'description': event_desc,
            'remaining_time': remaining_time
        })
    
    return render_template('dashboard.html', username=user[0], events=event_list)


scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

@app.template_filter('to_local_time')
def to_local_time(utc_time_str):
    # UTC 문자열을 datetime 객체로 변환
    utc_time = datetime.strptime(utc_time_str, '%Y-%m-%d %H:%M:%S')
    # UTC -> KST 변환
    local_time = utc_time.replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Seoul'))
    return local_time.strftime('%Y-%m-%d %H:%M:%S')

# 알림 작업
def send_notification(user_id, event_title, event_time):
    # 일정의 시간보다 10분 전 알림 전송
    current_time = datetime.now()
    if current_time >= event_time - timedelta(minutes=10):
        print(f"알림! 사용자 {user_id}님께: '{event_title}' 일정 시간이 다가왔습니다!")
        
#게시판 부분        
@app.route('/board')
def board():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT posts.id, posts.title, users.username, posts.created_at FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC')
    posts = c.fetchall()

    # 로그인한 사용자의 이름 가져오기
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None

    conn.close()
    
    # 템플릿에 사용자 이름과 게시글 데이터 전달
    return render_template('board.html', posts=posts, username=username)


@app.route('/board/new', methods=['GET', 'POST'])
def new_post():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    # 로그인한 사용자 이름 가져오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    username = user[0] if user else None  # 사용자 이름을 가져옵니다.

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        created_at = datetime.now(pytz.timezone('Asia/Seoul')).strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)', 
                  (session['user_id'], title, content, created_at))
        conn.commit()
        conn.close()

        flash('게시글이 작성되었습니다!', 'success')
        return redirect(url_for('board'))

    # GET 요청 시 사용자 이름을 템플릿으로 전달
    return render_template('new_post.html', username=username)


@app.route('/board/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))
        
        content = request.form['comment']
        created_at = datetime.now(pytz.timezone('Asia/Seoul')).strftime('%Y-%m-%d %H:%M:%S')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)', 
                  (post_id, session['user_id'], content, created_at))
        conn.commit()
        conn.close()

        flash('댓글이 작성되었습니다!', 'success')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None
    # 게시글 정보 가져오기
    c.execute('''
        SELECT posts.title, posts.content, users.username, posts.created_at, posts.user_id
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    ''', (post_id,))
    post = c.fetchone()
    post_user_id = post[4]  # 게시글 작성자 ID

    # 댓글 정보 가져오기
    c.execute('''
        SELECT comments.id, comments.content, users.username, comments.created_at, comments.user_id
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.created_at ASC
    ''', (post_id,))
    comments = c.fetchall()

    
    # 댓글 작성자 ID와 댓글 ID 리스트 생성
    comment_user_ids = [comment[4] for comment in comments]
    comment_ids = [comment[0] for comment in comments]

    conn.close()

    return render_template(
        'post_detail.html', 
        post=post, 
        comments=comments, 
        post_user_id=post_user_id, 
        comment_user_ids=comment_user_ids, 
        comment_ids=comment_ids, 
        post_id=post_id,  # 템플릿에 post_id 전달
        username=username
    )


@app.route('/board/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None
        
    if request.method == 'POST':
        # 수정 처리
        new_title = request.form['title']
        new_content = request.form['content']
        c.execute('UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?',
                  (new_title, new_content, post_id, session['user_id']))
        conn.commit()
        conn.close()

        flash('게시글이 수정되었습니다!', 'success')
        return redirect(url_for('post_detail', post_id=post_id))

    # 기존 게시글 내용 가져오기
    c.execute('SELECT title, content FROM posts WHERE id = ? AND user_id = ?', (post_id, session['user_id']))
    post = c.fetchone()
    conn.close()

    if not post:
        flash('수정할 권한이 없습니다.', 'danger')
        return redirect(url_for('board'))

    return render_template('edit_post.html', post=post,username = username)


@app.route('/board/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM posts WHERE id = ? AND user_id = ?', (post_id, session['user_id']))
    conn.commit()
    conn.close()

    flash('게시글이 삭제되었습니다!', 'info')
    return redirect(url_for('board'))


@app.route('/board/<int:post_id>/comment/edit/<int:comment_id>', methods=['GET', 'POST'])
def edit_comment(post_id, comment_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # 로그인한 사용자의 이름 가져오기
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None

    if request.method == 'POST':
        # 수정 처리
        new_content = request.form['content']
        c.execute('UPDATE comments SET content = ? WHERE id = ? AND user_id = ?',
                  (new_content, comment_id, session['user_id']))
        conn.commit()
        conn.close()

        flash('댓글이 수정되었습니다!', 'success')
        return redirect(url_for('post_detail', post_id=post_id))

    # 기존 댓글 내용과 작성자 이름 가져오기
    c.execute('''
        SELECT content, users.username 
        FROM comments 
        JOIN users ON comments.user_id = users.id 
        WHERE comments.id = ? AND comments.user_id = ?
    ''', (comment_id, session['user_id']))
    comment = c.fetchone()
    conn.close()

    if not comment:
        flash('수정할 권한이 없습니다.', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))

    # 댓글 내용과 작성자 이름 가져오기
    comment_content = comment[0]
    comment_username = comment[1]

    # 템플릿에 전달할 데이터
    return render_template('edit_comment.html', comment=comment,username=username)


@app.route('/board/<int:post_id>/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(post_id, comment_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM comments WHERE id = ? AND user_id = ?', (comment_id, session['user_id']))
    conn.commit()
    conn.close()

    flash('댓글이 삭제되었습니다!', 'info')
    return redirect(url_for('post_detail', post_id=post_id))
       

# 일정 추가 시 알림 스케줄 추가
# 캘린더 메인 페이지
@app.route('/')
def calendar():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    # 사용자 이름 가져오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()  # 사용자 이름을 가져옵니다.
    conn.close()

    # 사용자 이름을 calendar.html로 전달
    return render_template('calendar.html', username=user[0])


# 일정 조회 API
@app.route('/api/events', methods=['GET'])
def get_events():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # 데이터를 딕셔너리 형태로 반환
    c = conn.cursor()
    c.execute('SELECT id, title, start, end, description FROM events WHERE user_id = ?', (session['user_id'],))
    rows = c.fetchall()
    conn.close()

    # 데이터가 없을 경우 빈 리스트 반환
    if not rows:
        return jsonify([])

    # 데이터가 있을 경우 FullCalendar 포맷으로 변환
    events = [
        {
            "id": row[0],
            "title": row[1],
            "start": row[2],
            "end": row[3],
            "description": row[4]  # 설명 데이터 추가
        }
        for row in rows
    ]
    return jsonify(events)


@app.route('/api/events/<int:event_id>', methods=['PUT'])
def update_event(event_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    title = data.get('title')
    start = data.get('start')
    end = data.get('end')
    description = data.get('description')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        UPDATE events
        SET title = ?, start = ?, end = ?, description = ?
        WHERE id = ? AND user_id = ?
    ''', (title, start, end, description, event_id, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'message': '일정이 수정 되었습니다.'})


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM events WHERE id = ? AND user_id = ?', (event_id, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'message': '일정 삭제가 되었습니다.'})

# 일정 추가 API
@app.route('/calendar/add', methods=['GET', 'POST'])
def add_event():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    # 사용자 이름 가져오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()  # 사용자 이름을 가져옵니다.
    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        start_date = request.form['start_date']
        start_time = request.form['start_time']
        end_date = request.form.get('end_date')
        end_time = request.form.get('end_time')

        start = f"{start_date} {start_time}"
        end = f"{end_date} {end_time}" if end_date and end_time else None

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO events (user_id, title, start, end, description) VALUES (?, ?, ?, ?, ?)',
                  (session['user_id'], title, start, end, description))
        conn.commit()
        conn.close()

        flash('일정이 추가되었습니다!', 'success')
        return redirect(url_for('calendar'))

    return render_template('add_event.html', username=user[0])


@app.route('/friends/request', methods=['GET', 'POST'])
def send_friend_request():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        receiver_username = request.form['receiver_username']  # 친구로 추가할 닉네임
        sender_id = session['user_id']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            # 닉네임으로 사용자 ID 조회
            c.execute('SELECT id FROM users WHERE username = ?', (receiver_username,))
            receiver = c.fetchone()

            if not receiver:
                flash('입력한 닉네임을 가진 사용자가 존재하지 않습니다.', 'danger')
            elif receiver[0] == sender_id:
                flash('자기 자신에게 친구 요청을 보낼 수 없습니다.', 'danger')
            else:
                receiver_id = receiver[0]

                # 이미 요청이 있는지 확인
                c.execute('''
                    SELECT * FROM friends 
                    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                ''', (sender_id, receiver_id, receiver_id, sender_id))
                existing_request = c.fetchone()

                if existing_request:
                    flash('이미 친구 요청이 존재합니다.', 'danger')
                else:
                    # 새로운 친구 요청 추가
                    c.execute('INSERT INTO friends (sender_id, receiver_id, status) VALUES (?, ?, ?)', 
                              (sender_id, receiver_id, 'pending'))
                    conn.commit()
                    flash('친구 요청이 전송되었습니다!', 'success')
        except Exception as e:
            flash('친구 요청 전송 중 오류가 발생했습니다.', 'danger')
        finally:
            conn.close()

        return redirect(url_for('dashboard'))
    
    # GET 요청 시 처리 (예: 친구 요청 페이지 렌더링)
    return render_template('friend_request.html')




@app.route('/friends/respond', methods=['POST'])
def respond_friend_request():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    request_id = request.form['request_id']
    response = request.form['response']  # "accept" or "reject"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    try:
        if response == 'accept':
            c.execute('UPDATE friends SET status = ? WHERE id = ?', ('accepted', request_id))
            flash('친구 요청을 수락했습니다.', 'success')
        elif response == 'reject':
            c.execute('UPDATE friends SET status = ? WHERE id = ?', ('rejected', request_id))
            flash('친구 요청을 거절했습니다.', 'info')
        conn.commit()
    except Exception as e:
        flash('친구 요청 처리 중 오류가 발생했습니다.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/friends')
def friends_list():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None
    c.execute('''
        SELECT users.id, users.username 
        FROM friends
        JOIN users ON (users.id = friends.sender_id OR users.id = friends.receiver_id)
        WHERE friends.status = 'accepted' AND (friends.sender_id = ? OR friends.receiver_id = ?)
        AND users.id != ?
    ''', (user_id, user_id, user_id))
    friends = c.fetchall()
    conn.close()

    return render_template('friends_list.html', friends=friends, username=username)

@app.route('/chat/<int:friend_id>', methods=['GET', 'POST'])
def chat(friend_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None
    # 상대방 이름 가져오기
    c.execute('SELECT username FROM users WHERE id = ?', (friend_id,))
    friend = c.fetchone()
    if not friend:
        flash('해당 사용자를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('friends_list'))
    friend_name = friend[0]

    if request.method == 'POST':
        content = request.form['content']
        c.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                  (user_id, friend_id, content))
        conn.commit()

    # 이전 메시지 로드
    c.execute('''
        SELECT messages.sender_id, messages.receiver_id, messages.content, messages.timestamp
        FROM messages
        WHERE (messages.sender_id = ? AND messages.receiver_id = ?)
           OR (messages.sender_id = ? AND messages.receiver_id = ?)
        ORDER BY messages.timestamp ASC
    ''', (user_id, friend_id, friend_id, user_id))
    messages = c.fetchall()
    conn.close()

    return render_template('chat.html', messages=messages, friend_id=friend_id, friend_name=friend_name,username=username)


@app.route('/friends/requests')
def view_friend_requests():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if 'user_id' in session:
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        username = user[0] if user else None
    else:
        username = None
    # 받은 친구 요청 조회
    c.execute('''
        SELECT friends.id, users.username
        FROM friends
        JOIN users ON friends.sender_id = users.id
        WHERE friends.receiver_id = ? AND friends.status = 'pending'
    ''', (user_id,))
    friend_requests = [{'id': row[0], 'username': row[1]} for row in c.fetchall()]
    conn.close()

    return render_template('friends_requests.html', friend_requests=friend_requests,username=username)





# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)