from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, SubmitField, SelectField, IntegerField, RadioField
from wtforms.validators import InputRequired, Email, Length, DataRequired, Regexp, ValidationError

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.mysql import LONGTEXT
from flask_marshmallow import Marshmallow

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from flask_socketio import SocketIO, emit

import os
from dotenv import load_dotenv


app = Flask(__name__)
socketio = SocketIO(app)

bootstrap = Bootstrap5(app)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('URI_HOME') #uri home
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(8), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(LONGTEXT)

class HistoriaClinica(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo_documento = db.Column(db.String(50), nullable=False)
    dni = db.Column(db.String(50), unique=True, nullable=False)
    apellidos = db.Column(db.String(150), nullable=False)
    nombres = db.Column(db.String(150), nullable=False)
    direccion = db.Column(db.String(150), nullable=False)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    sexo = db.Column(db.String(10), nullable=False)
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.now)
    fecha_modificacion = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    estado = db.Column(db.String(10), nullable=False, default='activo')

class LoginForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[InputRequired(), Length(min=1, max=50)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Recuerdame')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message="Correo electronico invalido") , Length(max=50)])
    username = StringField('Nombre de Usuario', validators=[InputRequired(), Length(min=8, max=50)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=8, max=50)])

class HistoriaClinicaForm(FlaskForm):
    id = IntegerField('ID')
    id_new = IntegerField('Numero de historia', validators=[DataRequired()])
    tipo_documento = SelectField('Tipo de Documento',
                                choices=[('DNI', 'DNI'), 
                                          ('Carnet de Extranjería', 'Carnet de Extranjería'), 
                                          ('DNI Extranjera', 'DNI Extranjera')],
                                validators=[DataRequired()])
    dni = StringField('Número de documento', validators=[DataRequired()])
    apellidos = StringField('Apellidos', validators=[DataRequired()])
    nombres = StringField('Nombres', validators=[DataRequired()])
    direccion = StringField('Dirección', validators=[DataRequired()])
    fecha_nacimiento = DateField('Fecha de Nacimiento', validators=[DataRequired()])
    sexo = RadioField('Sexo', choices=[('M','Masculino'),('F','Femenino')], validators=[DataRequired()])
    submit = SubmitField('Guardar')

    def validate_n_documento(form, field):
        tipo_doc = form.tipo_documento.data
        n_documento = field.data

        if tipo_doc == 'DNI':
            if not n_documento.isdigit() or len(n_documento) != 8:
                raise ValidationError('El DNI debe tener 8 dígitos numéricos.')
        elif tipo_doc == 'Carnet de Extranjería':
            if not n_documento.isalnum() or len(n_documento) > 12:
                raise ValidationError('El Carnet de Extranjería debe ser alfanumérico y tener hasta 12 caracteres.')
        elif tipo_doc == 'DNI Extranjera':
            if not n_documento.isalnum() or len(n_documento) > 15:
                raise ValidationError('El DNI Extranjera debe ser alfanumérico y tener hasta 15 caracteres.')


@app.context_processor
def inject_user():
    return dict(user=current_user)


@app.route('/')
@login_required
def index():
    print(current_user.username)
    return render_template('index.html', user = current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'warning')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/historias', methods=['GET', 'POST'])
@login_required
def historias():
    search_query = ''
    search_column = 'dni'
    historias = HistoriaClinica.query.filter_by(estado="activo").all()

    form = HistoriaClinicaForm()

    if request.method == 'POST':
        if 'search_query' in request.form:
            search_query = request.form['search_query']
            search_column = request.form['search_column']
        
            if search_column and search_query:
                filter_dict = {
                    'dni': HistoriaClinica.dni,
                    'apellidos': HistoriaClinica.apellidos,
                    'nombres': HistoriaClinica.nombres,
                    'direccion': HistoriaClinica.direccion,
                    'fecha_nacimiento': HistoriaClinica.fecha_nacimiento,
                    'sexo': HistoriaClinica.sexo
                }
                
                if search_column in filter_dict:
                    search_filter = filter_dict[search_column].like(f'%{search_query}%')
                    historias = HistoriaClinica.query.filter(search_filter, HistoriaClinica.estado=="activo").all()
                else:
                    flash('Columna de búsqueda no válida')
                    historias = HistoriaClinica.query.filter_by(estado="activo").all()
        
        elif 'nueva_historia' in request.form:
            if form.validate_on_submit():
                historia_inactiva = HistoriaClinica.query.filter_by(estado='inactivo').first()
                if historia_inactiva:
                    historia_inactiva.dni = form.dni.data
                    historia_inactiva.tipo_documento=form.tipo_documento.data,
                    historia_inactiva.apellidos = form.apellidos.data
                    historia_inactiva.nombres = form.nombres.data
                    historia_inactiva.direccion = form.direccion.data
                    historia_inactiva.fecha_nacimiento = form.fecha_nacimiento.data
                    historia_inactiva.sexo = form.sexo.data
                    historia_inactiva.estado = 'activo'
                    historia_inactiva.fecha_modificacion = datetime.now()
                    db.session.commit()

                    socketio.emit('update_historia', {'message': 'Historia reutilizada'})
                    
                    flash(f'Historia clínica {historia_inactiva.id} reutilizada con éxito', 'success')
                else:
                    validate = HistoriaClinica.query.filter_by(id=form.id_new.data).first()
                    if validate:
                        flash(f'El número de historia {validate.id} ya existe, le pertenece al paciente con DNI {validate.dni}', 'danger')
                    else:
                        validateDni = HistoriaClinica.query.filter_by(dni=form.dni.data).first()
                        if validateDni:
                            flash(f'El paciente ingresado ya cuenta con el número de historia: {validateDni.id}', 'danger')
                        else:
                            nueva_historia = HistoriaClinica(
                                id = form.id_new.data,
                                tipo_documento = form.tipo_documento.data,
                                dni=form.dni.data,
                                apellidos=form.apellidos.data,
                                nombres=form.nombres.data,
                                direccion=form.direccion.data,
                                fecha_nacimiento=form.fecha_nacimiento.data,
                                sexo=form.sexo.data
                            )
                            db.session.add(nueva_historia)
                            db.session.commit()

                            socketio.emit('update_historia', {'message': 'Nueva historia creada'})
                            flash('Historia clínica agregada con éxito', 'success')
                return redirect(url_for('historias'))
            return render_template('historias.html', form=form, historias=historias)
        
        elif 'editar_historia' in request.form:
            form = HistoriaClinicaForm()
            if form.validate_on_submit():
                historia = HistoriaClinica.query.get(form.id.data)
                print(historia)
                if historia:
                    hcIdExistente = HistoriaClinica.query.filter(HistoriaClinica.id == form.id_new.data, HistoriaClinica.id != historia.id).first()
                    print(hcIdExistente)
                    if hcIdExistente:
                        flash(f'El número de historia {hcIdExistente.id} ya existe, le pertenece al paciente con DNI {hcIdExistente.dni}', 'danger')
                    else:
                        hcDniExistente = HistoriaClinica.query.filter(HistoriaClinica.dni == form.dni.data, HistoriaClinica.id != historia.id).first()
                        if hcDniExistente:
                            flash(f'El DNI ingresado ya pertenece a la historia {hcDniExistente.id}', 'danger')
                        else:
                            historia.tipo_documento = form.tipo_documento.data
                            historia.dni = form.dni.data
                            historia.apellidos = form.apellidos.data
                            historia.nombres = form.nombres.data
                            historia.direccion = form.direccion.data
                            historia.fecha_nacimiento = form.fecha_nacimiento.data
                            historia.sexo = form.sexo.data
                            historia.id = form.id_new.data
                            db.session.commit()

                            socketio.emit('update_historia', {'message': 'Historia actualizada'})

                            flash('Historia clínica actualizada con éxito', 'warning')
                            return redirect(url_for('historias'))
                else:
                    flash('Error al actualizar la historia clínica. No se encontró el registro.')

    return render_template('historias.html', historias=historias, search_query=search_query, form=form, search_column=search_column, user=current_user)

@app.route('/historias/liberar/<int:id>', methods=['GET', 'POST'])
@login_required
def liberar_historia(id):
    historia = HistoriaClinica.query.get_or_404(id)
    historia.estado = 'inactivo'
    historia.fecha_modificacion = datetime.utcnow()
    db.session.commit()

    socketio.emit('update_historia', {'message': f'Historia clínica {id} liberada'})
    flash(f'Historia clínica con número {id} liberada con éxito', 'success')
    return redirect(url_for('historias'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)