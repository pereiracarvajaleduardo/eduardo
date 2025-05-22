import os
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timezone # Import timezone for UTC
import re
import pdfplumber
from packaging.version import parse as parse_version, InvalidVersion

load_dotenv()

# --- Definición de BASE_DIR ---
# Esta variable representa el directorio absoluto donde se encuentra este archivo app.py
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# --- Configuración de la Base de Datos SQLite ---
# Ahora se usa la variable BASE_DIR que ya fue definida
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

# --- Loader para Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Funciones Auxiliares ---
def get_s3_client():
    if R2_CONFIG_MISSING: app.logger.error("Faltan config R2."); return None
    try: return boto3.client('s3', endpoint_url=R2_ENDPOINT_URL, aws_access_key_id=R2_ACCESS_KEY_ID, aws_secret_access_key=R2_SECRET_ACCESS_KEY, region_name='auto')
    except Exception as e: app.logger.error(f"Error cliente S3: {e}"); return None

def clean_for_path(text):
    if not text: return "sin_especificar"
    text = re.sub(r'[^\w\s-]', '', text).strip(); text = re.sub(r'[-\s]+', '_', text)
    return text if text else "sin_especificar"

def es_revision_mas_nueva(rev_nueva_str, rev_vieja_str):
    if rev_nueva_str == rev_vieja_str: return False
    rev_nueva_str = str(rev_nueva_str).strip().upper(); rev_vieja_str = str(rev_vieja_str).strip().upper()
    try: return parse_version(rev_nueva_str) > parse_version(rev_vieja_str)
    except InvalidVersion: app.logger.warning(f"Comparación no estándar: '{rev_nueva_str}' vs '{rev_vieja_str}'."); return rev_nueva_str > rev_vieja_str

def extraer_area_del_pdf(pdf_file_stream):
    area_encontrada = None
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek): pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            if not pdf.pages: app.logger.warning("PDF sin páginas."); return None
            page = pdf.pages[0]; pw, ph = page.width, page.height
            bbox = (pw * 0.40, ph * 0.65, pw * 0.98, ph * 0.98) 
            if bbox[0] >= bbox[2] or bbox[1] >= bbox[3]: app.logger.error(f"BBox inválido: {bbox}"); return None
            app.logger.info(f"Extrayendo Área - BBox: {bbox}"); region = page.crop(bbox); texto = region.extract_text(x_tolerance=2,y_tolerance=2, layout=False)
            if texto:
                txt_upper = texto.upper()
                if "WSA" in txt_upper: area_encontrada = "WSA"
                elif "SWS" in txt_upper: area_encontrada = "SWS"
                log_msg = f"Área extraída: {area_encontrada}" if area_encontrada else "No SWS/WSA en cajetín"
                app.logger.info(f"{log_msg}. Texto(500c): {texto[:500]}...")
            else: app.logger.info("No se extrajo texto de cajetín para Área.")
    except Exception as e: app.logger.error(f"Error extrayendo área: {e}", exc_info=True)
    if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek): pdf_file_stream.seek(0)
    return area_encontrada

def inicializar_fts():
    inspector = db.inspect(db.engine)
    if 'plano_fts' not in inspector.get_table_names():
        try:
            with db.engine.connect() as connection:
                connection.execute(db.text("""
                CREATE VIRTUAL TABLE plano_fts USING fts5(
                    plano_id UNINDEXED, codigo_plano, area, descripcion, contenido_pdf,
                    tokenize = "unicode61 remove_diacritics 2" 
                );"""))
                connection.commit()
            app.logger.info("Tabla virtual 'plano_fts' creada exitosamente.")
        except Exception as e:
            app.logger.error(f"Error al crear la tabla virtual 'plano_fts': {e}", exc_info=True)
    else:
        app.logger.info("Tabla virtual 'plano_fts' ya existe.")

def extraer_texto_completo_pdf(pdf_file_stream):
    texto_completo = []
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek): pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            for i, page in enumerate(pdf.pages):
                texto_pagina = page.extract_text(x_tolerance=2, y_tolerance=2)
                if texto_pagina: texto_completo.append(texto_pagina)
                app.logger.debug(f"Texto FTS p{i+1} (100c): {texto_pagina[:100] if texto_pagina else 'Nada'}")
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek): pdf_file_stream.seek(0)
        return "\n".join(texto_completo)
    except Exception as e:
        app.logger.error(f"Error extrayendo texto completo PDF: {e}", exc_info=True)
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek): pdf_file_stream.seek(0)
        return ""

def actualizar_indice_fts_session(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_pdf_val):
    try:
        db.session.execute(db.text("DELETE FROM plano_fts WHERE plano_id = :plano_id;"), {"plano_id": plano_id_val})
        db.session.execute(db.text("""
            INSERT INTO plano_fts (plano_id, codigo_plano, area, descripcion, contenido_pdf)
            VALUES (:plano_id, :codigo_plano, :area, :descripcion, :contenido_pdf);
        """), {
            "plano_id": plano_id_val, "codigo_plano": codigo_plano_val or "",
            "area": area_val or "", "descripcion": descripcion_val or "",
            "contenido_pdf": contenido_pdf_val or ""
        })
        app.logger.info(f"Operaciones FTS para plano_id: {plano_id_val} añadidas a la sesión.")
    except Exception as e:
        app.logger.error(f"Error preparando FTS para plano_id {plano_id_val}: {e}", exc_info=True); raise

def eliminar_del_indice_fts_session(plano_id_val):
    try:
        db.session.execute(db.text("DELETE FROM plano_fts WHERE plano_id = :plano_id;"), {"plano_id": plano_id_val})
        app.logger.info(f"Operación de eliminación FTS para plano_id: {plano_id_val} añadida a la sesión.")
    except Exception as e:
        app.logger.error(f"Error preparando eliminación FTS para plano_id {plano_id_val}: {e}", exc_info=True); raise

# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember_me'))
            flash('Inicio de sesión exitoso.', 'success'); next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else: flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Has cerrado sesión.', 'info'); return redirect(url_for('login'))

# --- Rutas Principales de la Aplicación ---
@app.route('/')
def index():
    if R2_CONFIG_MISSING: flash("Error config R2.", "danger")
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso.', 'danger'); return redirect(url_for('index'))
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
    try:
        query_codigo = request.args.get('q_codigo', '').strip(); query_area = request.args.get('q_area', '').strip()
        query_contenido = request.args.get('q_contenido', '').strip()
        app.logger.info(f"Buscando con Código: '{query_codigo}', Área: '{query_area}', Contenido: '{query_contenido}'")
        final_query = Plano.query
        if query_codigo: app.logger.info(f"Filtro código: %{query_codigo}%"); final_query = final_query.filter(Plano.codigo_plano.ilike(f'%{query_codigo}%'))
        if query_area: app.logger.info(f"Filtro área: %{query_area}%"); final_query = final_query.filter(Plano.area.ilike(f'%{query_area}%'))
        if query_contenido:
            terminos_fts = " ".join([f"{palabra.strip()}*" for palabra in query_contenido.split() if palabra.strip()])
            if not terminos_fts: app.logger.info("Término FTS vacío.")
            else:
                app.logger.info(f"Término FTS: '{terminos_fts}'")
                sql_fts = db.text("SELECT plano_id FROM plano_fts WHERE plano_fts MATCH :termino ORDER BY rank")
                with db.engine.connect() as conn: result = conn.execute(sql_fts, {"termino": terminos_fts})
                ids = [row[0] for row in result]
                if not ids: planos_db = []; app.logger.info("FTS no devolvió IDs.")
                else: app.logger.info(f"IDs FTS: {ids}"); final_query = final_query.filter(Plano.id.in_(ids)); planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
        else: planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
        app.logger.info(f"Planos finales: {len(planos_db)}")
        if planos_db: app.logger.info(f"Primer plano: {planos_db[0].codigo_plano}")
    except Exception as e:
        flash(f"Error BD: {str(e)}", "danger"); app.logger.error(f"Error BD: {e}", exc_info=True)
        planos_db = []
    return render_template('list_pdfs.html', planos=planos_db, R2_OBJECT_PREFIX=R2_OBJECT_PREFIX)

@app.route('/pdfs/view/<path:object_key>')
@login_required
def view_pdf(object_key):
    if R2_CONFIG_MISSING: flash("Visualización deshabilitada.", "danger"); return redirect(url_for('index'))
    s3 = get_s3_client();
    if not s3: flash("Error R2.", "danger"); return redirect(url_for('list_pdfs'))
    try: presigned_url = s3.generate_presigned_url('get_object', Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key}, ExpiresIn=3600); return redirect(presigned_url)
    except Exception as e: flash(f"Error enlace: {str(e)}", "danger"); app.logger.error(f"Error URL: {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))

@app.route('/plano/edit/<int:plano_id>', methods=['GET', 'POST'])
@login_required
def edit_plano(plano_id):
    if current_user.role not in ['admin', 'cargador']:
        flash('No tienes permiso para editar planos.', 'danger')
        return redirect(url_for('list_pdfs'))

    plano_a_editar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client() 

    if request.method == 'POST':
        nueva_revision_form = request.form.get('revision', '').strip()
        nueva_area_form = request.form.get('area', '').strip()
        nueva_descripcion_form = request.form.get('descripcion', '').strip()

        if not nueva_revision_form or not nueva_area_form:
            flash('Los campos Revisión y Área son obligatorios.', 'warning')
            return render_template('edit_plano.html', plano=plano_a_editar)

        antigua_r2_object_key = plano_a_editar.r2_object_key
        
        nueva_area_limpia = clean_for_path(nueva_area_form)
        nueva_revision_limpia = clean_for_path(nueva_revision_form)
        codigo_plano_limpio = clean_for_path(plano_a_editar.codigo_plano)

        nuevo_r2_filename = f"{codigo_plano_limpio}_Rev{nueva_revision_limpia}.pdf"
        nueva_r2_object_key = f"{R2_OBJECT_PREFIX}{nueva_area_limpia}/{nuevo_r2_filename}"
        
        if nueva_revision_form != plano_a_editar.revision:
            conflicto_revision = Plano.query.filter(
                Plano.codigo_plano == plano_a_editar.codigo_plano,
                Plano.revision == nueva_revision_form,
                Plano.id != plano_id ).first()
            if conflicto_revision:
                flash(f"Error: Ya existe un plano con código '{plano_a_editar.codigo_plano}' y revisión '{nueva_revision_form}'.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)
        
        if nueva_r2_object_key != antigua_r2_object_key:
            conflicto_r2_key = Plano.query.filter( Plano.r2_object_key == nueva_r2_object_key, Plano.id != plano_id ).first()
            if conflicto_r2_key:
                flash(f"Error: La ruta de archivo generada '{nueva_r2_object_key}' ya está en uso.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)

        try:
            if nueva_r2_object_key != antigua_r2_object_key and antigua_r2_object_key and s3:
                app.logger.info(f"Moviendo en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}'")
                copy_source = {'Bucket': R2_BUCKET_NAME, 'Key': antigua_r2_object_key}
                s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                app.logger.info("Archivo movido en R2.")
            
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.r2_object_key = nueva_r2_object_key
            plano_a_editar.fecha_subida = datetime.now(timezone.utc)
            
            contenido_pdf_actual = ""
            try:
                with db.engine.connect() as conn: 
                    result_fts = conn.execute(db.text("SELECT contenido_pdf FROM plano_fts WHERE plano_id = :pid"), {"pid": plano_id}).fetchone()
                    if result_fts and result_fts[0]:
                        contenido_pdf_actual = result_fts[0]
                    else:
                        app.logger.warning(f"No se encontró contenido FTS previo para plano_id {plano_id} al editar.")
            except Exception as e_fetch_fts:
                app.logger.error(f"No se pudo recuperar contenido_pdf de FTS para plano {plano_id}: {e_fetch_fts}")

            actualizar_indice_fts_session(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano,
                area_val=plano_a_editar.area,
                descripcion_val=plano_a_editar.descripcion,
                contenido_pdf_val=contenido_pdf_actual)
            
            db.session.commit()
            flash(f"Plano '{plano_a_editar.codigo_plano}' actualizado.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar el plano: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)
            plano_recargado = db.session.get(Plano, plano_id) if db.session.get(Plano, plano_id) else plano_a_editar
            return render_template('edit_plano.html', plano=plano_recargado)

    return render_template('edit_plano.html', plano=plano_a_editar)

@app.route('/pdfs/delete/<int:plano_id>', methods=['POST'])
@login_required
def delete_pdf(plano_id):
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso.', 'danger'); return redirect(url_for('list_pdfs'))
    if R2_CONFIG_MISSING: flash("Eliminación deshabilitada.", "danger"); return redirect(url_for('list_pdfs'))
    plano_a_eliminar = Plano.query.get_or_404(plano_id); s3 = get_s3_client()
    if not s3: flash("Error R2.", "danger"); return redirect(url_for('list_pdfs'))
    r2_key_a_eliminar = plano_a_eliminar.r2_object_key; plano_id_eliminado = plano_a_eliminar.id
    codigo_plano_eliminado = plano_a_eliminar.codigo_plano; revision_eliminada = plano_a_eliminar.revision
    try:
        if r2_key_a_eliminar:
            app.logger.info(f"Eliminando '{r2_key_a_eliminar}' de R2."); s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key_a_eliminar)
            app.logger.info(f"Objeto '{r2_key_a_eliminar}' eliminado/no encontrado en R2.")
        db.session.delete(plano_a_eliminar); eliminar_del_indice_fts_session(plano_id_eliminado)
        db.session.commit()
        flash(f"Plano '{codigo_plano_eliminado}' Rev '{revision_eliminada}' eliminado.", "success")
        app.logger.info(f"Plano ID {plano_id_eliminado} eliminado de DB e FTS.")
    except Exception as e:
        db.session.rollback(); flash(f"Error eliminando: {str(e)}", "danger")
        app.logger.error(f"Error eliminando plano ID {plano_id}: {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))

if __name__ == '__main__':
    if R2_CONFIG_MISSING: print("ADVERTENCIA: Faltan configuraciones R2.")
    with app.app_context():
        db.create_all()
        inicializar_fts()
        if not User.query.filter_by(username='admin').first():
            try: admin_user = User(username='admin', role='admin'); admin_user.set_password('admin123'); db.session.add(admin_user); db.session.commit(); print("Admin creado.")
            except Exception as e: db.session.rollback(); print(f"Error creando admin: {e}")
        if not User.query.filter_by(username='usuario').first():
            try: consultor_user = User(username='usuario', role='consultor'); consultor_user.set_password('eimisa'); db.session.add(consultor_user); db.session.commit(); print("Usuario 'usuario' creado.")
            except Exception as e: db.session.rollback(); print(f"Error creando 'usuario': {e}")
        print("Tablas de BD verificadas/creadas (incluyendo FTS).")
    app.run(debug=True, host='0.0.0.0', port=5000)