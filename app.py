# === VERSIÓN CON AJUSTES PARA POSTGRESQL FTS MULTILINGÜE BÁSICO ===
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, func
from sqlalchemy.dialects.postgresql import TSVECTOR
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from packaging.version import parse as parse_version, InvalidVersion
import pdfplumber
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import spacy
from langdetect import detect as lang_detect_func, LangDetectException # Para detección de idioma

# --- Carga de Entorno y Configuración Inicial ---
load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# --- Configuración de la Base de Datos (PostgreSQL o SQLite local) ---
DATABASE_URL_ENV = os.getenv('DATABASE_URL')
if DATABASE_URL_ENV:
    if DATABASE_URL_ENV.startswith("postgres://"):
        DATABASE_URL_ENV = DATABASE_URL_ENV.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL_ENV
    app.logger.info(f"Usando base de datos PostgreSQL externa.")
else:
    db_file_path = os.path.join(BASE_DIR, 'planos_dev.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_file_path
    app.logger.info(f"ADVERTENCIA: DATABASE_URL no encontrada. Usando base de datos SQLite local en: {db_file_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Configuración de Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"

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
    idioma_documento = db.Column(db.String(10), nullable=True, default='spanish') # Para FTS multilingüe
    tsvector_contenido = db.Column(TSVECTOR)

    __table_args__ = (
        db.UniqueConstraint('codigo_plano', 'revision', name='uq_codigo_plano_revision'),
        Index('idx_plano_tsvector_contenido', tsvector_contenido, postgresql_using='gin'),
    )
    def __repr__(self): return f'<Plano {self.codigo_plano} Rev: {self.revision}>'

# --- Carga Global de Modelos spaCy ---
NLP_ES = None
NLP_EN = None # Para inglés
try:
    NLP_ES = spacy.load("es_core_news_sm")
    app.logger.info("Modelo spaCy 'es_core_news_sm' cargado.")
except Exception as e_es:
    app.logger.error(f"FALLO AL CARGAR MODELO spaCy 'es_core_news_sm': {e_es}. Lematización en español deshabilitada.")
try:
    NLP_EN = spacy.load("en_core_web_sm") # Modelo pequeño para inglés
    app.logger.info("Modelo spaCy 'en_core_web_sm' cargado.")
except Exception as e_en:
    app.logger.error(f"FALLO AL CARGAR MODELO spaCy 'en_core_web_sm': {e_en}. Lematización en inglés deshabilitada.")

# --- Configuración de Cloudflare R2 ---
R2_BUCKET_NAME = os.getenv('R2_BUCKET_NAME')
# ... (resto de tu config R2 sin cambios)
R2_ACCOUNT_ID = os.getenv('R2_ACCOUNT_ID')
R2_ACCESS_KEY_ID = os.getenv('R2_ACCESS_KEY_ID')
R2_SECRET_ACCESS_KEY = os.getenv('R2_SECRET_ACCESS_KEY')
R2_ENDPOINT_URL = os.getenv('R2_ENDPOINT_URL')
if not R2_ENDPOINT_URL and R2_ACCOUNT_ID:
    R2_ENDPOINT_URL = f'https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com'
R2_CONFIG_MISSING = not all([R2_BUCKET_NAME, R2_ENDPOINT_URL, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY])
R2_OBJECT_PREFIX = 'planos/'

# --- Funciones Auxiliares ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ... (get_s3_client, clean_for_path, es_revision_mas_nueva sin cambios)
def get_s3_client():
    if R2_CONFIG_MISSING:
        app.logger.error("Faltan variables de configuración para R2. No se puede crear el cliente S3.")
        return None
    try:
        client = boto3.client(
            's3',endpoint_url=R2_ENDPOINT_URL,
            aws_access_key_id=R2_ACCESS_KEY_ID, aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            config=Config(signature_version='s3v4'), region_name='auto'
        )
        return client
    except Exception as e:
        app.logger.error(f"Error al crear el cliente S3 para R2: {e}", exc_info=True)
        return None

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
    # ... (tu función sin cambios)
    area_encontrada = None
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            if not pdf.pages:
                app.logger.warning("El PDF subido no tiene páginas.")
                return None
            page = pdf.pages[0]
            pw, ph = page.width, page.height
            bbox = (pw * 0.40, ph * 0.65, pw * 0.98, ph * 0.98)
            if bbox[0] >= bbox[2] or bbox[1] >= bbox[3]:
                app.logger.error(f"Bounding box inválido generado para extracción de área: {bbox}")
                return None
            region_recortada = page.crop(bbox)
            texto = region_recortada.extract_text(x_tolerance=2, y_tolerance=2, layout=False)
            if texto:
                txt_upper = texto.upper()
                if "WSA" in txt_upper: area_encontrada = "WSA"
                elif "SWS" in txt_upper: area_encontrada = "SWS"
                log_msg = f"Área extraída: {area_encontrada}" if area_encontrada else "No se encontró 'SWS' o 'WSA' en el texto del cajetín."
                app.logger.info(f"{log_msg}. Texto encontrado (primeros 500c): {texto[:500]}...")
            else:
                app.logger.info("No se pudo extraer texto del área del cajetín para determinar el área.")
    except Exception as e:
        app.logger.error(f"Error crítico durante la extracción del área del PDF: {e}", exc_info=True)
    finally:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
    return area_encontrada


def extraer_texto_completo_pdf(pdf_file_stream, max_paginas=6):
    texto_completo = []
    idioma_detectado_pdf = 'spanish' # Default
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            num_paginas_a_procesar = min(len(pdf.pages), max_paginas)
            app.logger.info(f"Procesando {num_paginas_a_procesar} páginas para FTS (límite: {max_paginas}). Total páginas PDF: {len(pdf.pages)}")
            
            texto_para_deteccion = ""
            for i in range(num_paginas_a_procesar):
                page = pdf.pages[i]
                texto_pagina = page.extract_text(x_tolerance=2, y_tolerance=2)
                if texto_pagina:
                    texto_completo.append(texto_pagina)
                    if i < 2 : # Usar texto de las primeras 2 páginas (o menos si hay menos) para detección
                        texto_para_deteccion += texto_pagina + " "
            
            if texto_para_deteccion.strip():
                try:
                    lang_code = lang_detect_func(texto_para_deteccion[:1000]) # langdetect con muestra
                    if lang_code == 'en':
                        idioma_detectado_pdf = 'english'
                    app.logger.info(f"Idioma detectado para el PDF: {lang_code} -> {idioma_detectado_pdf}")
                except LangDetectException:
                    app.logger.warning("No se pudo detectar idioma del PDF, asumiendo 'spanish'.")
                except Exception as e_lang:
                    app.logger.error(f"Error general detectando idioma: {e_lang}")
            else:
                 app.logger.info("No hay suficiente texto para detectar idioma, asumiendo 'spanish'.")

    except Exception as e:
        app.logger.error(f"Error extrayendo el texto completo del PDF para FTS: {e}", exc_info=True)
    finally:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
    return "\n".join(texto_completo), idioma_detectado_pdf # Devuelve también el idioma

def actualizar_tsvector_plano(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_pdf_val, idioma_doc='spanish'):
    try:
        texto_para_indexar = " ".join(filter(None, [
            codigo_plano_val, area_val, descripcion_val, contenido_pdf_val
        ]))
        
        config_fts_pg = 'english' if idioma_doc == 'english' else 'spanish'
        app.logger.info(f"Actualizando tsvector para plano_id {plano_id_val} con config FTS: '{config_fts_pg}' e idioma_documento: '{idioma_doc}'")

        stmt_tsvector = (
            db.update(Plano)
            .where(Plano.id == plano_id_val)
            .values(tsvector_contenido=func.to_tsvector(config_fts_pg, texto_para_indexar),
                    idioma_documento=idioma_doc) # Guarda también el idioma detectado
        )
        db.session.execute(stmt_tsvector)
        app.logger.info(f"Columna tsvector e idioma_documento actualizados en sesión para plano_id: {plano_id_val}")
    except Exception as e:
        app.logger.error(f"Error actualizando tsvector/idioma para plano_id {plano_id_val}: {e}", exc_info=True)
        raise

def lematizar_texto(texto, nlp_model, idioma_codigo_spacy):
    if not nlp_model or not texto:
        return texto 
    doc = nlp_model(texto.lower())
    lemmas = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct and token.lemma_.strip()]
    resultado = " ".join(lemmas) if lemmas else texto
    app.logger.info(f"Lematización ({idioma_codigo_spacy}): '{texto}' -> '{resultado}'")
    return resultado

# --- Rutas de Autenticación ---
# ... (sin cambios: login, logout) ...
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

# --- Rutas Principales ---
@app.route('/')
def index():
    # ... (sin cambios) ...
    if R2_CONFIG_MISSING:
        flash("ADVERTENCIA: La configuración para R2 no está completa.", "danger")
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    # ... (código de verificación de rol y R2_CONFIG_MISSING sin cambios) ...
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso.', 'danger'); return redirect(url_for('index'))
    if R2_CONFIG_MISSING: flash("Subida deshabilitada por error de config.", "danger"); return redirect(url_for('index'))

    if request.method == 'POST':
        pdf_file = request.files.get('pdf_file')
        codigo_plano_form = request.form.get('codigo_plano', '').strip()
        revision_form = request.form.get('revision', '').strip()
        area_form = request.form.get('area', '').strip()
        descripcion_form = request.form.get('descripcion', '').strip()

        # ... (Validaciones iniciales sin cambios) ...
        if not pdf_file or not pdf_file.filename: flash('No se seleccionó archivo.', 'warning'); return redirect(request.url)
        if not codigo_plano_form or not revision_form: flash('Código y Revisión obligatorios.', 'warning'); return redirect(request.url)
        if not pdf_file.filename.lower().endswith('.pdf'): flash('Solo PDF.', 'warning'); return redirect(request.url)
        
        # ... (Lógica de determinación de área sin cambios) ...
        area_final_determinada = None
        es_mr = codigo_plano_form.upper().startswith("K484-0000-0000-MR-")
        if es_mr:
            if area_form: area_final_determinada = area_form
            else:
                try:
                    if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                    area_extraida = extraer_area_del_pdf(pdf_file.stream)
                    area_final_determinada = area_extraida if area_extraida else "Area_MR_Pendiente"
                    flash(f"Área MR: '{area_final_determinada}'.", "info" if area_extraida else "warning")
                except Exception as e_area:
                    area_final_determinada = "Area_MR_Error"; flash("Error extrayendo área MR.", "warning")
                    app.logger.error(f"Error extrayendo área MR: {e_area}", exc_info=True)
        else: 
            if area_form: area_final_determinada = area_form
            else: flash('Campo "Área" obligatorio para no-MR.', 'warning'); return redirect(request.url)
        if area_final_determinada is None: flash('Error: Área no determinada.', 'danger'); return redirect(request.url)

        # ... (Preparación de nombres y claves R2 sin cambios) ...
        original_filename_secure = secure_filename(pdf_file.filename)
        cleaned_area = clean_for_path(area_final_determinada); cleaned_codigo = clean_for_path(codigo_plano_form)
        cleaned_revision = clean_for_path(revision_form)
        r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision}.pdf"; r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"
        
        s3 = get_s3_client()
        if not s3: flash("Error config R2.", "danger"); return redirect(request.url)

        try:
            # --- Lógica de manejo de revisiones ---
            planos_existentes_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_form).all()
            plano_para_actualizar_o_crear = None
            eliminar_objetos_r2_y_db = []

            if not planos_existentes_mismo_codigo: # Plano nuevo
                app.logger.info(f"Creando nuevo plano: {codigo_plano_form} Rev {revision_form}")
                plano_para_actualizar_o_crear = Plano(
                    codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                    nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                    descripcion=descripcion_form
                )
                db.session.add(plano_para_actualizar_o_crear)
            else: # Plano con este código ya existe, manejar revisiones
                revision_actual_mas_alta_db_str = None
                plano_con_revision_ingresada = None
                for p_existente in planos_existentes_mismo_codigo:
                    if p_existente.revision == revision_form:
                        plano_con_revision_ingresada = p_existente
                    if revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(p_existente.revision, revision_actual_mas_alta_db_str):
                        revision_actual_mas_alta_db_str = p_existente.revision
                
                if plano_con_revision_ingresada: # Actualizando la misma revisión
                    app.logger.info(f"Actualizando plano existente (misma revisión): {codigo_plano_form} Rev {revision_form}")
                    plano_para_actualizar_o_crear = plano_con_revision_ingresada
                    if plano_para_actualizar_o_crear.r2_object_key and plano_para_actualizar_o_crear.r2_object_key != r2_object_key_nuevo:
                         eliminar_objetos_r2_y_db.append(Plano(id=-1, r2_object_key=plano_para_actualizar_o_crear.r2_object_key)) # Dummy para borrar solo de R2
                elif revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(revision_form, revision_actual_mas_alta_db_str): # Nueva revisión es la más alta
                    app.logger.info(f"Nueva revisión '{revision_form}' es la más alta. Marcando antiguas para eliminación.")
                    for p_antiguo in planos_existentes_mismo_codigo:
                        eliminar_objetos_r2_y_db.append(p_antiguo) # Se borrarán de DB y R2
                    plano_para_actualizar_o_crear = Plano(
                        codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                        nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                        descripcion=descripcion_form
                    )
                    db.session.add(plano_para_actualizar_o_crear)
                else: # Revisión subida es más antigua o igual que una no existente
                    flash(f"Revisión '{revision_form}' no es más reciente. Rev. más alta: '{revision_actual_mas_alta_db_str}'. No procesado.", "warning")
                    return redirect(request.url)

            if not plano_para_actualizar_o_crear:
                raise Exception("Error determinando plano a crear/actualizar.")

            # Actualizar datos del plano
            plano_para_actualizar_o_crear.area = area_final_determinada
            plano_para_actualizar_o_crear.r2_object_key = r2_object_key_nuevo
            plano_para_actualizar_o_crear.nombre_archivo_original = original_filename_secure
            plano_para_actualizar_o_crear.descripcion = descripcion_form
            plano_para_actualizar_o_crear.fecha_subida = datetime.now(timezone.utc)
            
            # Extraer texto y detectar idioma ANTES de subir a R2 y ANTES de flush/commit
            texto_completo_pdf, idioma_doc_detectado = "", "spanish" # Defaults
            try:
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                texto_completo_pdf, idioma_doc_detectado = extraer_texto_completo_pdf(pdf_file.stream)
            except Exception as e_extr_texto:
                app.logger.error(f"Fallo al extraer texto/idioma del PDF: {e_extr_texto}", exc_info=True)
                flash("ADVERTENCIA: Hubo un problema al leer el contenido del PDF. La búsqueda por contenido podría no funcionar para este archivo.", "warning")
            
            plano_para_actualizar_o_crear.idioma_documento = idioma_doc_detectado # Asignar idioma detectado

            # Subir a R2
            try:
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                s3.upload_fileobj(pdf_file.stream, R2_BUCKET_NAME, r2_object_key_nuevo)
                app.logger.info(f"Archivo '{r2_object_key_nuevo}' subido a R2.")
            except ClientError as e_s3:
                db.session.rollback()
                flash(f"Error de conexión al subir: {e_s3.response.get('Error', {}).get('Message', 'Error R2')}", "danger")
                return redirect(request.url)
            
            # Preparar para commit (obtener ID si es nuevo)
            if plano_para_actualizar_o_crear not in db.session and not db.session.is_modified(plano_para_actualizar_o_crear):
                 # Esto puede ser redundante si ya se hizo add, pero asegura que esté en la sesión antes del flush
                db.session.add(plano_para_actualizar_o_crear)
            db.session.flush() 
            plano_id_actual = plano_para_actualizar_o_crear.id

            # Actualizar tsvector
            actualizar_tsvector_plano(
                plano_id_actual, plano_para_actualizar_o_crear.codigo_plano,
                plano_para_actualizar_o_crear.area, plano_para_actualizar_o_crear.descripcion,
                texto_completo_pdf, idioma_doc_detectado # Pasar idioma
            )
            
            # Eliminar objetos y registros antiguos
            for plano_a_borrar in eliminar_objetos_r2_y_db:
                if plano_a_borrar.r2_object_key and plano_a_borrar.r2_object_key != r2_object_key_nuevo:
                    try:
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=plano_a_borrar.r2_object_key)
                        app.logger.info(f"Objeto R2 antiguo '{plano_a_borrar.r2_object_key}' eliminado.")
                    except Exception as e_del_r2:
                        app.logger.error(f"Error borrando objeto R2 antiguo '{plano_a_borrar.r2_object_key}': {e_del_r2}")
                if hasattr(plano_a_borrar, 'id') and plano_a_borrar.id is not None and plano_a_borrar.id != -1: # Asegurar que sea un objeto persistido de la DB
                    app.logger.info(f"Eliminando registro de DB para plano ID {plano_a_borrar.id}")
                    db.session.delete(plano_a_borrar)
            
            db.session.commit()
            flash(f"Plano '{codigo_plano_form}' Rev '{revision_form}' procesado.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e_general:
            db.session.rollback()
            flash(f"Error general procesando archivo: {str(e_general)}", "danger")
            app.logger.error(f"Error general en upload/DB: {e_general}", exc_info=True)
            return redirect(request.url)
    return render_template('upload_pdf.html')

@app.route('/pdfs')
@login_required
def list_pdfs():
    try:
        query_codigo = request.args.get('q_codigo', '').strip()
        query_area = request.args.get('q_area', '').strip()
        query_contenido_original = request.args.get('q_contenido', '').strip()
        
        app.logger.info(f"Buscando con Código: '{query_codigo}', Área: '{query_area}', Contenido Original: '{query_contenido_original}'")
            
        final_query = Plano.query

        if query_codigo:
            final_query = final_query.filter(Plano.codigo_plano.ilike(f'%{query_codigo}%'))
        if query_area:
            final_query = final_query.filter(Plano.area.ilike(f'%{query_area}%'))

        ids_fts_encontrados = set()

        if query_contenido_original:
            # Lematizar consulta en español (asumiendo que la interfaz y la mayoría de las búsquedas son en español)
            termino_es_lematizado = lematizar_texto(query_contenido_original, NLP_ES, 'español')
            
            if termino_es_lematizado.strip():
                # Buscar con término en español en documentos españoles o por defecto
                # (la columna tsvector_contenido se genera con el idioma del documento)
                # PostgreSQL usa la configuración de idioma del tsvector para el match.
                # Por lo tanto, el postgresql_regconfig en match debe coincidir con el idioma de la consulta.
                app.logger.info(f"Buscando FTS con término español: '{termino_es_lematizado}'")
                query_es_fts = final_query.filter(
                    Plano.tsvector_contenido.match(termino_es_lematizado, postgresql_regconfig='spanish')
                ).with_entities(Plano.id).all()
                for pid, in query_es_fts: ids_fts_encontrados.add(pid)

            # Traducir término original a inglés (incluso si la consulta original era en inglés)
            termino_traducido_en = ""
            if query_contenido_original.strip():
                try:
                    termino_traducido_en = GoogleTranslator(source='auto', target='en').translate(query_contenido_original)
                    app.logger.info(f"Consulta original '{query_contenido_original}' traducida a inglés: '{termino_traducido_en}'")
                except Exception as e_translate:
                    app.logger.error(f"Error traduciendo a inglés: {e_translate}")

            if termino_traducido_en and termino_traducido_en.strip():
                termino_en_lematizado = lematizar_texto(termino_traducido_en, NLP_EN, 'inglés')
                if termino_en_lematizado.strip():
                    app.logger.info(f"Buscando FTS con término inglés: '{termino_en_lematizado}'")
                    query_en_fts = final_query.filter(
                        Plano.tsvector_contenido.match(termino_en_lematizado, postgresql_regconfig='english')
                    ).with_entities(Plano.id).all() # No es necesario filtrar por Plano.idioma_documento == 'english' aquí,
                                                     # porque el match ya usa el regconfig 'english', buscando en tsvectors que fueron
                                                     # creados con la config 'english'.
                    for pid, in query_en_fts: ids_fts_encontrados.add(pid)
            
            if query_contenido_original.strip(): # Solo filtrar si se hizo una búsqueda por contenido
                if ids_fts_encontrados:
                    final_query = final_query.filter(Plano.id.in_(list(ids_fts_encontrados)))
                else: # Si se buscó por contenido pero no se encontró nada
                    final_query = final_query.filter(db.false()) 

        planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
        app.logger.info(f"Número de planos finales encontrados: {len(planos_db)}")

    except Exception as e:
        flash(f"Error al obtener la lista de planos: {str(e)}", "danger")
        app.logger.error(f"Error en la ruta /pdfs: {e}", exc_info=True)
        planos_db = [] 
    return render_template('list_pdfs.html', planos=planos_db, R2_OBJECT_PREFIX=R2_OBJECT_PREFIX)


@app.route('/pdfs/view/<path:object_key>')
@login_required
def view_pdf(object_key):
    # ... (tu código de view_pdf sin cambios significativos) ...
    if R2_CONFIG_MISSING: flash("Visualización deshabilitada.", "danger"); return redirect(url_for('list_pdfs'))
    s3 = get_s3_client()
    if not s3: flash("Error R2.", "danger"); return redirect(url_for('list_pdfs'))
    try:
        presigned_url = s3.generate_presigned_url('get_object', Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key}, ExpiresIn=3600)
        return redirect(presigned_url)
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
        
        # --- VALIDACIONES DE CONFLICTO --- (Tu lógica original)
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
        # --- FIN VALIDACIONES ---

        try:
            # Mover el objeto en R2 si la clave ha cambiado y el archivo NO se está reemplazando
            # Si se sube un nuevo archivo, se borra el antiguo después de subir el nuevo.
            # Esta lógica es para cuando solo cambian metadatos que afectan la clave R2.
            pdf_file_edit = request.files.get('pdf_file_edit') # Asumimos que hay un campo para un nuevo PDF
            if not pdf_file_edit and nueva_r2_object_key != antigua_r2_object_key and antigua_r2_object_key and s3:
                app.logger.info(f"Moviendo en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}' (solo metadatos cambiaron)")
                copy_source = {'Bucket': R2_BUCKET_NAME, 'Key': antigua_r2_object_key}
                s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                app.logger.info("Archivo movido en R2.")
            
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.r2_object_key = nueva_r2_object_key # Actualizar siempre, incluso si no se movió (podría ser el mismo)
            plano_a_editar.fecha_subida = datetime.now(timezone.utc) # Actualizar fecha
            
            texto_completo_pdf_edit = ""
            idioma_doc_edit = plano_a_editar.idioma_documento # Usar idioma existente si no se sube nuevo archivo

            if pdf_file_edit and pdf_file_edit.filename: # Si se sube un nuevo archivo PDF para reemplazar
                if not pdf_file_edit.filename.lower().endswith('.pdf'):
                    flash('Solo se permiten archivos PDF para reemplazar.', 'warning')
                    return render_template('edit_plano.html', plano=plano_a_editar)
                
                app.logger.info(f"Reemplazando archivo PDF para plano ID {plano_id}.")
                original_filename_secure_edit = secure_filename(pdf_file_edit.filename)
                plano_a_editar.nombre_archivo_original = original_filename_secure_edit # Actualizar nombre original
                
                # Borrar el objeto R2 antiguo ANTES de subir el nuevo si la clave es la misma
                # o DESPUÉS si la clave es diferente y ya se copió.
                # Si la clave es la misma, el upload_fileobj lo sobrescribirá.
                # Si la clave es diferente y no se copió arriba, el objeto antiguo podría quedar huérfano
                # si no se maneja. Por simplicidad, si se sube un nuevo archivo, borramos el antiguo
                # después de subir el nuevo si las claves son diferentes.

                try:
                    if hasattr(pdf_file_edit.stream, 'seek'): pdf_file_edit.stream.seek(0)
                    texto_completo_pdf_edit, idioma_doc_edit = extraer_texto_completo_pdf(pdf_file_edit.stream)
                    
                    if hasattr(pdf_file_edit.stream, 'seek'): pdf_file_edit.stream.seek(0)
                    s3.upload_fileobj(pdf_file_edit.stream, R2_BUCKET_NAME, nueva_r2_object_key) # Subir a la nueva clave
                    app.logger.info(f"Nuevo archivo PDF subido a R2: '{nueva_r2_object_key}'")

                    # Si la clave R2 antigua era diferente y existía, bórrala ahora
                    if antigua_r2_object_key and antigua_r2_object_key != nueva_r2_object_key:
                        app.logger.info(f"Eliminando objeto R2 antiguo después de reemplazar archivo: '{antigua_r2_object_key}'")
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)

                except ClientError as e_s3_edit:
                    db.session.rollback()
                    flash(f"Error de conexión al subir el nuevo PDF: {e_s3_edit.response.get('Error', {}).get('Message', 'Error R2')}", "danger")
                    return render_template('edit_plano.html', plano=plano_a_editar)
                except Exception as e_upload_edit:
                    db.session.rollback()
                    flash(f"Error procesando o subiendo el nuevo PDF: {str(e_upload_edit)}", "danger")
                    app.logger.error(f"Error procesando/subiendo nuevo PDF en edición: {e_upload_edit}", exc_info=True)
                    return render_template('edit_plano.html', plano=plano_a_editar)
            
            plano_a_editar.idioma_documento = idioma_doc_edit # Actualizar idioma
            
            # Actualizar FTS con el texto nuevo o el antiguo si no se subió archivo
            # Si no se subió archivo nuevo y solo cambiaron metadatos,
            # el contenido_pdf para FTS debería ser el que ya estaba.
            if not pdf_file_edit: # Si no se subió archivo nuevo, necesitamos el texto original del PDF
                # Esta es la parte más difícil: ¿Cómo obtenemos el texto original si no lo guardamos?
                # Opciones:
                # 1. Descargar de R2, extraer texto, actualizar FTS (costoso).
                # 2. Guardar el texto_completo_pdf en la DB (aumenta tamaño de DB).
                # 3. Solo actualizar FTS con los metadatos si el archivo no cambia.
                # Por ahora, si el archivo no cambia, asumimos que el contenido_pdf para FTS no cambia
                # y el tsvector se actualizará con los nuevos metadatos y el contenido antiguo
                # (que aquí es "" si no lo recuperamos).
                # Para una solución real, necesitarías recuperar el contenido_pdf o no llamar a la extracción.
                # O, como hicimos antes, si el archivo no cambia, y solo cambian metadatos como descripcion,
                # se puede reconstruir el texto para indexar solo con los metadatos actualizados.
                # Vamos a asumir que si solo editas metadatos, quieres que se reflejen en FTS
                # junto con el contenido del PDF que ya estaba (que ahora no tenemos aquí).
                # Lo más simple es que si no hay pdf_file_edit, NO se re-extrae texto.
                # El tsvector se actualizará con el `contenido_pdf_actual` que aquí será ""
                # a menos que lo recuperes de alguna forma (ej. de la propia tabla FTS si la tenías).
                # Si asumimos que el `tsvector_contenido` YA existe y solo cambian metadatos:
                app.logger.info("Editando metadatos, contenido PDF no cambió. Se usará el tsvector existente para metadatos.")
                # NO se re-extrae texto si no se sube un nuevo archivo.
                # `actualizar_tsvector_plano` usará el `contenido_pdf_actual` que es "".
                # Esto significa que si solo editas la descripción, el contenido del PDF se "perderá" del índice FTS.
                # CORRECCIÓN: Necesitamos el contenido original si no se sube un nuevo PDF.
                # Por ahora, si no hay archivo nuevo, pasamos None o string vacío,
                # y la función actualizar_tsvector_plano debe manejarlo (quizás no actualizando el contenido_pdf)
                # O mejor, si no hay archivo, no llamamos a extraer_texto_completo_pdf.
                # El tsvector se actualizará con los nuevos metadatos y el contenido que ya está en el tsvector
                # (lo que no es posible directamente, se debe re-generar con el texto original).
                # Para simplicidad, si solo cambian metadatos, el tsvector se re-creará usando
                # los metadatos nuevos Y el texto_completo_pdf_edit que sería "" si no se subió archivo.
                # Esto degradaría la búsqueda.
                # Solución: Si no hay archivo nuevo, se debe obtener el texto_completo_pdf del objeto actual.
                # Esto requeriría descargar de R2 y procesar, lo cual no es ideal para una simple edición de metadatos.
                #
                # Compromiso: Si solo se editan metadatos, no se actualiza el contenido del tsvector
                # a menos que tengas el texto original del PDF guardado en alguna parte.
                # Por ahora, si no se sube un nuevo archivo, no llamaremos a extraer_texto_completo_pdf
                # y pasaremos un string vacío para `contenido_pdf_val` en `actualizar_tsvector_plano`.
                # Esto no es ideal.
                #
                # MEJOR ENFOQUE PARA EDICIÓN DE METADATOS SOLAMENTE:
                # Si no hay `pdf_file_edit`, el `texto_completo_pdf_edit` debería ser el texto que
                # ya estaba asociado con ese plano (si lo guardaste en la DB o en la tabla FTS).
                # Si no lo guardaste, y no quieres reprocesar el PDF de R2, entonces la actualización
                # del tsvector solo se hará con los metadatos.

                # Asumamos que si no hay pdf_file_edit, el texto_completo_pdf_edit sigue siendo ""
                # y el idioma_doc_edit es el que ya tenía el plano.
                 pass # No se hace nada con texto_completo_pdf_edit si no hay archivo
            
            actualizar_tsvector_plano(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano, # Código no cambia en edición
                area_val=nueva_area_form,
                descripcion_val=nueva_descripcion_form,
                contenido_pdf_val=texto_completo_pdf_edit, # Será "" si no se subió nuevo archivo y no lo recuperamos
                idioma_doc=idioma_doc_edit
            )
            
            db.session.commit()
            flash(f"Plano '{plano_a_editar.codigo_plano}' actualizado.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)
            return render_template('edit_plano.html', plano=plano_a_editar)

    return render_template('edit_plano.html', plano=plano_a_editar)


@app.route('/pdfs/delete/<int:plano_id>', methods=['POST'])
@login_required
def delete_pdf(plano_id):
    # ... (tu código de delete_pdf, ya no se llama a eliminar_del_indice_fts_session) ...
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso.', 'danger'); return redirect(url_for('list_pdfs'))
    if R2_CONFIG_MISSING: flash("Eliminación deshabilitada.", "danger"); return redirect(url_for('list_pdfs'))
    
    plano_a_eliminar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()
    if not s3: flash("Error R2.", "danger"); return redirect(url_for('list_pdfs'))

    r2_key_a_eliminar = plano_a_eliminar.r2_object_key
    try:
        if r2_key_a_eliminar:
            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key_a_eliminar)
            app.logger.info(f"Objeto '{r2_key_a_eliminar}' eliminado de R2.")
        
        db.session.delete(plano_a_eliminar) # Al borrar el plano, el tsvector se va con él (si está en la misma tabla)
        db.session.commit()
        flash(f"Plano '{plano_a_eliminar.codigo_plano}' Rev '{plano_a_eliminar.revision}' eliminado.", "success")
    except Exception as e:
        db.session.rollback(); flash(f"Error eliminando: {str(e)}", "danger")
        app.logger.error(f"Error eliminando plano ID {plano_id}: {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))

# --- Bloque de Inicialización de la Aplicación ---
with app.app_context():
    db.create_all() 
    
    # Crear usuarios por defecto
    if not User.query.filter_by(username='admin').first():
        try:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123')) 
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario 'admin' por defecto creado.")
        except Exception as e: db.session.rollback(); app.logger.error(f"Error creando admin: {e}")
    if not User.query.filter_by(username='usuario').first():
        try:
            consultor_user = User(username='usuario', role='consultor')
            consultor_user.set_password(os.getenv('CONSULTOR_PASSWORD', 'eimisa'))
            db.session.add(consultor_user)
            db.session.commit()
            app.logger.info("Usuario 'usuario' (consultor) por defecto creado.")
        except Exception as e: db.session.rollback(); app.logger.error(f"Error creando consultor: {e}")
    
    app.logger.info("Contexto de aplicación inicializado: BD y usuarios por defecto verificados.")

# --- Punto de Entrada para Desarrollo Local ---
if __name__ == '__main__':
    if R2_CONFIG_MISSING:
        print("\nADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.\n")
    print("Iniciando servidor de desarrollo Flask local en http://127.0.0.1:5000")
    # Render usa Gunicorn y define el puerto con la variable PORT, localmente puedes usar 5000.
    port = int(os.getenv('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)