# === VERSIÓN FINAL Y FUNCIONAL1 ===
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from packaging.version import parse as parse_version, InvalidVersion
import pdfplumber
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Carga de Entorno y Configuración Inicial ---
load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# --- Configuración de la Base de Datos ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'planos_database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Configuración de Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"

# --- Configuración de Cloudflare R2 ---
R2_BUCKET_NAME = os.getenv('R2_BUCKET_NAME')
R2_ACCOUNT_ID = os.getenv('R2_ACCOUNT_ID')
R2_ACCESS_KEY_ID = os.getenv('R2_ACCESS_KEY_ID')
R2_SECRET_ACCESS_KEY = os.getenv('R2_SECRET_ACCESS_KEY')
R2_ENDPOINT_URL = os.getenv('R2_ENDPOINT_URL')
if not R2_ENDPOINT_URL and R2_ACCOUNT_ID:
    R2_ENDPOINT_URL = f'https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com'
R2_CONFIG_MISSING = not all([R2_BUCKET_NAME, R2_ENDPOINT_URL, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY])
R2_OBJECT_PREFIX = 'planos/'


# --- Modelos de Base de Datos ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='consultor')
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def __repr__(self): return f'<User {self.username} ({self.role})>'

class Plano(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo_plano = db.Column(db.String(200), nullable=False)
    revision = db.Column(db.String(50), nullable=False)
    area = db.Column(db.String(100), nullable=False)
    nombre_archivo_original = db.Column(db.String(255), nullable=True)
    r2_object_key = db.Column(db.String(500), unique=True, nullable=False)
    fecha_subida = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    descripcion = db.Column(db.Text, nullable=True)
    __table_args__ = (db.UniqueConstraint('codigo_plano', 'revision', name='uq_codigo_plano_revision'),)
    def __repr__(self): return f'<Plano {self.codigo_plano} Rev: {self.revision}>'


# --- Funciones Auxiliares ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_s3_client():
    if R2_CONFIG_MISSING:
        app.logger.error("Faltan variables de configuración para R2. No se puede crear el cliente S3.")
        return None
    try:
        client = boto3.client(
            's3',
            endpoint_url=R2_ENDPOINT_URL,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            config=Config(signature_version='s3v4'),
            region_name='auto'
        )
        return client
    except Exception as e:
        app.logger.error(f"Error al crear el cliente S3 para R2: {e}", exc_info=True)
        return None

def clean_for_path(text):
    if not text: return "sin_especificar"
    text = re.sub(r'[^\w\s-]', '', text).strip()
    text = re.sub(r'[-\s]+', '_', text)
    return text if text else "sin_especificar"

def es_revision_mas_nueva(rev_nueva_str, rev_vieja_str):
    if rev_nueva_str == rev_vieja_str: return False
    rev_nueva_str = str(rev_nueva_str).strip().upper()
    rev_vieja_str = str(rev_vieja_str).strip().upper()
    try:
        return parse_version(rev_nueva_str) > parse_version(rev_vieja_str)
    except InvalidVersion:
        app.logger.warning(f"Comparación de revisión no estándar: '{rev_nueva_str}' vs '{rev_vieja_str}'.")
        return rev_nueva_str > rev_vieja_str

def extraer_area_del_pdf(pdf_file_stream):
    # (Tu lógica de extracción de área aquí, sin cambios)
    pass

def extraer_texto_completo_pdf(pdf_file_stream):
    # (Tu lógica de extracción de texto aquí, sin cambios)
    pass
    
def inicializar_fts():
    # (Tu lógica de inicialización de FTS aquí, sin cambios)
    pass

def actualizar_indice_fts_session(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_pdf_val):
    # (Tu lógica de actualización de FTS aquí, sin cambios)
    pass

def eliminar_del_indice_fts_session(plano_id_val):
    # (Tu lógica de eliminación de FTS aquí, sin cambios)
    pass


# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember_me'))
            flash('Inicio de sesión exitoso.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))


# --- Rutas Principales de la Aplicación ---
@app.route('/')
def index():
    if R2_CONFIG_MISSING:
        flash("ADVERTENCIA: La configuración para el almacenamiento de archivos (R2) no está completa. Algunas funciones pueden no estar disponibles.", "danger")
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])

@login_required

def upload_pdf():

  if current_user.role not in ['admin', 'cargador']:
        flash('No tienes permiso.', 'danger')
        return redirect(url_for('index'))

  if R2_CONFIG_MISSING: flash("Subida deshabilitada.", "danger"); return redirect(url_for('index'))

  if request.method == 'POST':

    pdf_file = request.files.get('pdf_file'); codigo_plano_form = request.form.get('codigo_plano', '').strip()

    revision_form = request.form.get('revision', '').strip(); area_form = request.form.get('area', '').strip()

    descripcion_form = request.form.get('descripcion', '').strip()

    if not pdf_file or not codigo_plano_form or not revision_form: flash('Campos obligatorios: Archivo, Código, Revisión.', 'warning'); return redirect(request.url)

    if not pdf_file.filename.lower().endswith('.pdf'): flash('Sólo PDF.', 'warning'); return redirect(request.url)

    area_final_determinada = None; es_mr = codigo_plano_form.upper().startswith("K484-0000-0000-MR-")

    if es_mr:

      if area_form: area_final_determinada = area_form; app.logger.info(f"MR. Área manual: '{area_final_determinada}'")

      else:

        app.logger.info(f"MR '{codigo_plano_form}' sin área. Extrayendo...");

        if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)

        area_extraida = extraer_area_del_pdf(pdf_file.stream)

        if area_extraida: area_final_determinada = area_extraida; flash(f"Área '{area_final_determinada}' detectada de PDF.", "info")

        else: area_final_determinada = "Area_MR_Pendiente"; flash(f"No se extrajo área. Usando '{area_final_determinada}'.", "warning")

    else:

      if area_form: area_final_determinada = area_form

      else: flash('Campo "Área" obligatorio.', 'warning'); return redirect(request.url)

    if area_final_determinada is None: flash('Error: No se pudo determinar Área.', 'danger'); app.logger.error("CRÍTICO: area_final es None."); return redirect(request.url)

   

    original_filename_secure = secure_filename(pdf_file.filename)

    cleaned_area = clean_for_path(area_final_determinada); cleaned_codigo = clean_for_path(codigo_plano_form)

    cleaned_revision = clean_for_path(revision_form)

    r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision}.pdf"; r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"

    s3 = get_s3_client()

    if not s3: flash("Error R2.", "danger"); return redirect(request.url)

    try:

      planos_existentes_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_form).all()

      plano_para_actualizar_o_crear = None; eliminar_objetos_r2_y_db = []

      if not planos_existentes_mismo_codigo:

        app.logger.info(f"Creando primer plano: {codigo_plano_form} Rev {revision_form}")

        plano_para_actualizar_o_crear = Plano(codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada, nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo, descripcion=descripcion_form)

      else:

        revision_actual_mas_alta_db_str = None; plano_con_revision_ingresada = None

        for p_existente in planos_existentes_mismo_codigo:

          if p_existente.revision == revision_form: plano_con_revision_ingresada = p_existente

          if revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(p_existente.revision, revision_actual_mas_alta_db_str):

            revision_actual_mas_alta_db_str = p_existente.revision

        if plano_con_revision_ingresada:

          plano_para_actualizar_o_crear = plano_con_revision_ingresada; app.logger.info(f"Actualizando: {codigo_plano_form} Rev {revision_form}")

          if plano_para_actualizar_o_crear.r2_object_key != r2_object_key_nuevo and plano_para_actualizar_o_crear.r2_object_key: app.logger.info(f"Clave R2 cambiará.")

        elif revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(revision_form, revision_actual_mas_alta_db_str):

          app.logger.info(f"Nueva rev '{revision_form}' > '{revision_actual_mas_alta_db_str or 'ninguna'}'. Eliminando anteriores.")

          for p_antiguo in planos_existentes_mismo_codigo: eliminar_objetos_r2_y_db.append(p_antiguo)

          plano_para_actualizar_o_crear = Plano(codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada, nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo, descripcion=descripcion_form)

        else:

          flash(f"Revisión '{revision_form}' no es más reciente. Rev más alta: '{revision_actual_mas_alta_db_str}'. No procesado.", "warning"); return redirect(request.url)

      if not plano_para_actualizar_o_crear: raise Exception("Error determinando plano a crear/actualizar.")

      plano_para_actualizar_o_crear.area = area_final_determinada; plano_para_actualizar_o_crear.r2_object_key = r2_object_key_nuevo

      plano_para_actualizar_o_crear.nombre_archivo_original = original_filename_secure; plano_para_actualizar_o_crear.descripcion = descripcion_form

      plano_para_actualizar_o_crear.fecha_subida = datetime.now(timezone.utc)

      if plano_para_actualizar_o_crear not in db.session: db.session.add(plano_para_actualizar_o_crear)

      db.session.flush(); plano_id_actual = plano_para_actualizar_o_crear.id

      if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)

      texto_completo_pdf = extraer_texto_completo_pdf(pdf_file.stream)

      actualizar_indice_fts_session(plano_id_actual, plano_para_actualizar_o_crear.codigo_plano, plano_para_actualizar_o_crear.area, plano_para_actualizar_o_crear.descripcion, texto_completo_pdf)

      if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)

      s3.upload_fileobj(pdf_file.stream, R2_BUCKET_NAME, r2_object_key_nuevo); app.logger.info(f"Archivo subido a R2: {r2_object_key_nuevo}")

      for plano_a_borrar_obj_db in eliminar_objetos_r2_y_db:

        if plano_a_borrar_obj_db.r2_object_key and plano_a_borrar_obj_db.r2_object_key != r2_object_key_nuevo:

          try: s3.delete_object(Bucket=R2_BUCKET_NAME, Key=plano_a_borrar_obj_db.r2_object_key); app.logger.info(f"Objeto R2 antiguo '{plano_a_borrar_obj_db.r2_object_key}' eliminado.")

          except Exception as e_del: app.logger.error(f"Error borrando objeto R2 antiguo '{plano_a_borrar_obj_db.r2_object_key}': {e_del}")

        eliminar_del_indice_fts_session(plano_a_borrar_obj_db.id)

        db.session.delete(plano_a_borrar_obj_db); app.logger.info(f"Registro DB plano ID {plano_a_borrar_obj_db.id} Rev '{plano_a_borrar_obj_db.revision}' eliminado.")

      db.session.commit()

      flash(f"Plano '{codigo_plano_form}' Rev '{revision_form}' (Área: {area_final_determinada}) procesado e indexado.", "success"); return redirect(url_for('list_pdfs'))

    except Exception as e:

      db.session.rollback(); flash(f"Error procesando archivo: {str(e)}", "danger")

      app.logger.error(f"Error en subida/DB: {e}", exc_info=True); return redirect(request.url)

  return render_template('upload_pdf.html')

@app.route('/pdfs')
@login_required
def list_pdfs():
    # (Tu lógica de la ruta /pdfs aquí, sin cambios)
    pass

@app.route('/pdfs/view/<path:object_key>')
@login_required
def view_pdf(object_key):
    # (Tu lógica de la ruta /pdfs/view aquí, sin cambios)
    pass

@app.route('/plano/edit/<int:plano_id>', methods=['GET', 'POST'])
@login_required
def edit_plano(plano_id):
    # (Tu lógica de la ruta /plano/edit aquí, sin cambios)
    pass

@app.route('/pdfs/delete/<int:plano_id>', methods=['POST'])
@login_required
def delete_pdf(plano_id):
    # (Tu lógica de la ruta /pdfs/delete aquí, sin cambios)
    pass


# --- Bloque de Inicialización de la Aplicación ---
with app.app_context():
    db.create_all()
    inicializar_fts()
    
    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username='admin').first():
        try:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123')) # Es mejor usar variables de entorno
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario 'admin' por defecto creado (o ya existía).")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al crear usuario admin por defecto: {e}")

    # Crear usuario consultor por defecto si no existe
    if not User.query.filter_by(username='usuario').first():
        try:
            consultor_user = User(username='usuario', role='consultor')
            consultor_user.set_password(os.getenv('CONSULTOR_PASSWORD', 'eimisa'))
            db.session.add(consultor_user)
            db.session.commit()
            app.logger.info("Usuario 'usuario' (consultor) por defecto creado (o ya existía).")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al crear usuario 'usuario' por defecto: {e}")
    
    app.logger.info("Contexto de aplicación inicializado: BD, FTS y usuarios por defecto verificados.")

# --- Punto de Entrada para Desarrollo Local ---
if __name__ == '__main__':
    if R2_CONFIG_MISSING:
        print("ADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.")
    print("Iniciando servidor de desarrollo Flask local en http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)