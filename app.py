from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

# Add custom template filters
app.jinja_env.filters['chr'] = chr

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    attempts = db.relationship('Attempt', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_published = db.Column(db.Boolean, nullable=False, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    questions = db.relationship('Question', backref='quiz', cascade='all, delete-orphan')
    creator = db.relationship('User', backref='created_quizzes')


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    # store choices as JSON list, and the index of correct answer
    choices_json = db.Column(db.Text, nullable=False)
    correct_index = db.Column(db.Integer, nullable=False)

    def choices(self):
        return json.loads(self.choices_json)


class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    answers_json = db.Column(db.Text, nullable=False)


def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        # Create an admin user
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

# Initialize database on startup
init_db()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('list_quizzes'))
        
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/toggle-admin')
@login_required
def toggle_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    current_user.is_admin = not current_user.is_admin
    db.session.commit()
    flash(f'Switched to {"admin" if current_user.is_admin else "regular user"} mode', 'success')
    return redirect(url_for('list_quizzes'))


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('list_quizzes'))
    return redirect(url_for('login'))


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('list_quizzes'))
    
    # Show list of published and draft quizzes
    draft_quizzes = Quiz.query.filter_by(created_by=current_user.id, is_published=False).all()
    published_quizzes = Quiz.query.filter_by(created_by=current_user.id, is_published=True).all()
    return render_template('admin/dashboard.html', draft_quizzes=draft_quizzes, published_quizzes=published_quizzes)

@app.route('/admin/quiz/new', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('list_quizzes'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        if not title:
            flash('Quiz title is required', 'error')
            return render_template('admin/create_quiz.html')
        
        quiz = Quiz(title=title, created_by=current_user.id)
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz created! Now add some questions.', 'success')
        return redirect(url_for('edit_quiz', quiz_id=quiz.id))
    
    return render_template('admin/create_quiz.html')

@app.route('/admin/quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('list_quizzes'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != current_user.id:
        flash('You can only edit your own quizzes', 'error')
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'publish':
            if not quiz.questions:
                flash('Cannot publish quiz without questions', 'error')
            else:
                quiz.is_published = True
                db.session.commit()
                flash('Quiz published!', 'success')
                return redirect(url_for('admin'))
        elif action == 'unpublish':
            quiz.is_published = False
            db.session.commit()
            flash('Quiz unpublished', 'success')
            return redirect(url_for('admin'))
        elif action == 'delete':
            db.session.delete(quiz)
            db.session.commit()
            flash('Quiz deleted', 'success')
            return redirect(url_for('admin'))
    
    return render_template('admin/edit_quiz.html', quiz=quiz)

@app.route('/admin/quiz/<int:quiz_id>/question/add', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('list_quizzes'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != current_user.id:
        flash('You can only edit your own quizzes', 'error')
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        text = request.form.get('text', '').strip()
        choices = [request.form.get(f'choice_{i}', '').strip() for i in range(4)]
        correct = request.form.get('correct', type=int)
        
        if not text or not all(choices) or correct is None:
            flash('All fields are required', 'error')
        else:
            question = Question(
                quiz_id=quiz.id,
                text=text,
                choices_json=json.dumps(choices),
                correct_index=correct
            )
            db.session.add(question)
            db.session.commit()
            flash('Question added!', 'success')
            return redirect(url_for('edit_quiz', quiz_id=quiz.id))
    
    return render_template('admin/add_question.html', quiz=quiz)


@app.route('/quizzes')
def list_quizzes():
    quizzes = Quiz.query.filter_by(is_published=True).order_by(Quiz.id.desc()).all()
    return render_template('quiz_list.html', quizzes=quizzes)


@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz.id).all()

    if request.method == 'POST':
        answers = {}
        correct_count = 0
        for q in questions:
            key = f'question_{q.id}'
            val = request.form.get(key)
            # user may not submit an answer for a question
            if val is None or val == '':
                answers[str(q.id)] = None
                continue
            try:
                idx = int(val)
            except ValueError:
                idx = None
            answers[str(q.id)] = idx
            if idx is not None and idx == q.correct_index:
                correct_count += 1

        attempt = Attempt(
            quiz_id=quiz.id,
            user_id=current_user.id,
            score=correct_count,
            total=len(questions),
            answers_json=json.dumps(answers),
        )
        db.session.add(attempt)
        db.session.commit()
        return redirect(url_for('result', attempt_id=attempt.id))

    return render_template('take_quiz.html', quiz=quiz, questions=questions)


@app.route('/result/<int:attempt_id>')
@login_required
def result(attempt_id):
    attempt = Attempt.query.get_or_404(attempt_id)
    quiz = Quiz.query.get_or_404(attempt.quiz_id)
    answers = json.loads(attempt.answers_json)
    # construct a helpful result view
    detail = []
    questions = Question.query.filter_by(quiz_id=quiz.id).all()
    for q in questions:
        user_idx = answers.get(str(q.id))
        correct = q.correct_index
        detail.append({
            'text': q.text,
            'choices': q.choices(),
            'user': user_idx,
            'correct': correct,
        })

    return render_template('result.html', attempt=attempt, quiz=quiz, detail=detail)


@app.route('/attempts')
@login_required
def attempts():
    if current_user.is_admin:
        atts = Attempt.query.order_by(Attempt.id.desc()).limit(50).all()
    else:
        atts = Attempt.query.filter_by(user_id=current_user.id).order_by(Attempt.id.desc()).all()
    return render_template('attempts.html', attempts=atts)


if __name__ == '__main__':
    # allow running with `python app.py` for quick local dev
    app.run(debug=True)
