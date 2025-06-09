# === clave de acceso ===
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
from langdetect import detect as lang_detect_func, LangDetectException
from deep_translator import GoogleTranslator
import io

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

# ... (otras configuraciones)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- NUEVO: Opciones para el motor de la base de datos para manejar timeouts ---
engine_options = {
    "pool_recycle": 280,    # Refresca conexiones que tienen más de 280 segundos (4.6 minutos)
    "pool_pre_ping": True   # Verifica si la conexión está viva antes de usarla
}

db = SQLAlchemy(app, engine_options=engine_options)

# --- Configuración de Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"

# --- Constantes ---
VALID_REVISION_PATTERN = r"^[a-zA-Z0-9_.\-]{1,10}$"
REVISION_FORMAT_ERROR_MSG = ("El formato de la revisión no es válido. "
                             "Debe tener entre 1 y 10 caracteres (letras, números, '_', '.', '-'). "
                             "No se permiten espacios.")
# --- NUEVO: Definir extensiones permitidas ---
ALLOWED_EXTENSIONS = ['.pdf', '.txt', '.docx', '.xlsx', '.dwg', '.dxf', '.jpg', '.jpeg', '.png']


# --- Modelos de Base de Datos ---
# --- VERSIÓN CORREGIDA Y FINAL ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='consultor')
    
    # --- NUEVO CAMPO AÑADIDO ---
    # Aquí se guardarán las áreas permitidas como un string: "piping,mecanica,oocc"
    allowed_areas_str = db.Column(db.String(500), nullable=True)

    # --- NUEVA PROPIEDAD AÑADIDA ---
    # Esto nos permite acceder a las áreas como una lista limpia, ej: user.allowed_areas
    @property
    def allowed_areas(self):
        """Devuelve una lista de las áreas permitidas para el usuario."""
        if not self.allowed_areas_str:
            return []
        # Limpia espacios en blanco y devuelve la lista
        return [area.strip() for area in self.allowed_areas_str.split(',')]

    def set_password(self, password): 
        self.password_hash = generate_password_hash(password)

    def check_password(self, password): 
        return check_password_hash(self.password_hash, password)

    def __repr__(self): 
        return f'<User {self.username} ({self.role})>'

class Plano(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo_plano = db.Column(db.String(200), nullable=False)
    revision = db.Column(db.String(50), nullable=False)
    area = db.Column(db.String(100), nullable=False)
    nombre_archivo_original = db.Column(db.String(255), nullable=True) # Guardará el nombre con su extensión original
    r2_object_key = db.Column(db.String(500), unique=True, nullable=False)
    fecha_subida = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    descripcion = db.Column(db.Text, nullable=True)
    idioma_documento = db.Column(db.String(10), nullable=True, default='spanish')
    tsvector_contenido = db.Column(TSVECTOR)

    __table_args__ = (
        db.UniqueConstraint('codigo_plano', 'revision', name='uq_codigo_plano_revision'),
        Index('idx_plano_tsvector_contenido', tsvector_contenido, postgresql_using='gin'),
    )
    def __repr__(self): return f'<Plano {self.codigo_plano} Rev: {self.revision}>'

# --- Carga Global de Modelos spaCy ---
NLP_ES = None
NLP_EN = None
try:
    NLP_ES = spacy.load("es_core_news_sm")
    app.logger.info("Modelo spaCy 'es_core_news_sm' cargado.")
except Exception as e_es:
    app.logger.error(f"FALLO AL CARGAR MODELO spaCy 'es_core_news_sm': {e_es}. Lematización en español deshabilitada.")
try:
    NLP_EN = spacy.load("en_core_web_sm")
    app.logger.info("Modelo spaCy 'en_core_web_sm' cargado.")
except Exception as e_en:
    app.logger.error(f"FALLO AL CARGAR MODELO spaCy 'en_core_web_sm': {e_en}. Lematización en inglés deshabilitada.")

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
    text = re.sub(r'[^\w\s-]', '', text).strip()
    text = re.sub(r'[-\s]+', '_', text)
    return text if text else "sin_especificar"

def es_revision_mas_nueva(rev_nueva_str, rev_vieja_str):
    if rev_nueva_str is None or rev_vieja_str is None:
        return False

    rev_nueva_str_clean = str(rev_nueva_str).strip().upper()
    rev_vieja_str_clean = str(rev_vieja_str).strip().upper()

    if not rev_nueva_str_clean or not rev_vieja_str_clean:
        return rev_nueva_str_clean > rev_vieja_str_clean

    if rev_nueva_str_clean == rev_vieja_str_clean: return False

    try:
        return parse_version(rev_nueva_str_clean) > parse_version(rev_vieja_str_clean)
    except InvalidVersion:
        app.logger.warning(f"Comparación no estándar de revisión (fallback a string): '{rev_nueva_str_clean}' vs '{rev_vieja_str_clean}'.")
        return rev_nueva_str_clean > rev_vieja_str_clean

# FUNCIÓN PARA EXTRAER REVISIÓN DEL NOMBRE DE ARCHIVO (CORREGIDA)
def extraer_revision_del_filename(filename):
    if not filename:
        return None

    patrones_revision = [
        r"[_-]REV[._\s-]?([a-zA-Z0-9]{1,5})(?:[._\s-]|(?=\.[^.]*$)|$)",
        r"[_-]R_?([a-zA-Z0-9]{1,5})(?:[._\s-]|(?=\.[^.]*$)|$)",
        r"\(R(?:EV)?\.?[_\s-]?([a-zA-Z0-9]{1,5})\)",
        r"\bRev\.?\s*([a-zA-Z0-9]{1,5})\b",
        # CORRECCIÓN AQUÍ: {1,5} cambiado a {{1,5}}
        r"_([a-zA-Z0-9]{{1,5}})(?:_|\.(?:{}))$".format("|".join(ext.lstrip('.') for ext in ALLOWED_EXTENSIONS)),
        # CORRECCIÓN AQUÍ: {1,3} cambiado a {{1,3}}
        r"([a-zA-Z0-9]{{1,3}})\.(?:{})$".format("|".join(ext.lstrip('.') for ext in ALLOWED_EXTENSIONS))
    ]

    app.logger.debug(f"Intentando extraer revisión del nombre de archivo: '{filename}'")
    for patron in patrones_revision:
        match = re.search(patron, filename, re.IGNORECASE)
        if match and match.group(1):
            revision_extraida = match.group(1).strip().upper()
            if re.fullmatch(VALID_REVISION_PATTERN, revision_extraida):
                app.logger.info(f"Revisión extraída de '{filename}' (patrón '{patron}'): '{revision_extraida}'")
                return revision_extraida
            else:
                app.logger.debug(f"Extracción '{revision_extraida}' de '{filename}' (patrón '{patron}') no pasó VALID_REVISION_PATTERN.")

    app.logger.info(f"No se pudo extraer una revisión válida del nombre de archivo: '{filename}'")
    return None

# FUNCIÓN PARA EXTRAER ÁREA (ESPECÍFICA PARA PDFS)
def extraer_area_del_pdf(pdf_file_stream): # Esta función es específicamente para PDF
    area_encontrada = None
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            if not pdf.pages:
                app.logger.warning("El PDF para extraer área no tiene páginas.")
                return None
            page = pdf.pages[0]
            pw, ph = page.width, page.height
            # Coordenadas del cajetín (ajustar si es necesario)
            bbox = (pw * 0.40, ph * 0.65, pw * 0.98, ph * 0.98)
            if bbox[0] >= bbox[2] or bbox[1] >= bbox[3]: # Verificación de BBox válido
                app.logger.error(f"Bounding box inválido generado para extracción de área: {bbox}")
                return None
            region_recortada = page.crop(bbox)
            texto = region_recortada.extract_text(x_tolerance=2, y_tolerance=2, layout=False)

            if texto:
                txt_upper = texto.upper()
                if "WSA" in txt_upper: area_encontrada = "WSA"
                elif "SWS" in txt_upper: area_encontrada = "SWS"
                log_msg = f"Área extraída del PDF: {area_encontrada}" if area_encontrada else "No se encontró 'SWS' o 'WSA' en el texto del cajetín del PDF."
                app.logger.info(f"{log_msg}. Texto encontrado (primeros 500c): {texto[:500]}...")
            else:
                app.logger.info("No se pudo extraer texto del área del cajetín del PDF para determinar el área.")
    except Exception as e:
        app.logger.error(f"Error crítico durante la extracción del área del PDF: {e}", exc_info=True)
    finally:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0) # Rebobinar para usos posteriores del stream
    return area_encontrada

# FUNCIÓN GENÉRICA PARA EXTRAER TEXTO DE ARCHIVOS (PDF, TXT, DOCX)
def extraer_texto_del_archivo(file_stream, filename_with_ext):
    _root, ext = os.path.splitext(filename_with_ext)
    ext = ext.lower()

    texto_extraido = ""
    idioma_detectado = "spanish" # Default

    if hasattr(file_stream, 'seek'):
        file_stream.seek(0)

    if ext == '.pdf':
        try:
            with pdfplumber.open(file_stream) as pdf:
                text_pages = []
                # Limitar a las primeras 6 páginas para la extracción de texto completo
                for page_num, page in enumerate(pdf.pages):
                    if page_num >= 6:
                        app.logger.info(f"Extracción de texto PDF limitada a las primeras 6 páginas para '{filename_with_ext}'.")
                        break
                    text_page = page.extract_text(x_tolerance=2, y_tolerance=2)
                    if text_page:
                        text_pages.append(text_page)
                texto_extraido = "\n".join(text_pages)
            app.logger.info(f"Texto extraído de PDF: {filename_with_ext} (longitud: {len(texto_extraido)})")
        except Exception as e:
            app.logger.error(f"Error extrayendo texto de PDF '{filename_with_ext}': {e}")
    elif ext == '.txt':
        try:
            try:
                texto_extraido = file_stream.read().decode('utf-8')
            except UnicodeDecodeError:
                if hasattr(file_stream, 'seek'): file_stream.seek(0)
                texto_extraido = file_stream.read().decode('latin-1', errors='ignore')
            app.logger.info(f"Texto extraído de TXT: {filename_with_ext} (longitud: {len(texto_extraido)})")
        except Exception as e:
            app.logger.error(f"Error extrayendo texto de TXT '{filename_with_ext}': {e}")
    elif ext == '.docx':
        try:
            import docx # Intentar importar python-docx
            doc = docx.Document(file_stream)
            texto_extraido = "\n".join([para.text for para in doc.paragraphs])
            app.logger.info(f"Texto extraído de DOCX: {filename_with_ext} (longitud: {len(texto_extraido)})")
        except ImportError:
            app.logger.warning("La biblioteca 'python-docx' no está instalada. No se puede extraer texto de archivos .docx.")
            flash("Para extraer texto de archivos DOCX, el administrador debe instalar la biblioteca 'python-docx'.", "info")
        except Exception as e:
            app.logger.error(f"Error extrayendo texto de DOCX '{filename_with_ext}': {e}")
    # Puedes añadir más `elif ext == '.extensión':` para otros tipos de archivo
    # elif ext in ['.xlsx', '.dwg', '.dxf', '.jpg', '.jpeg', '.png']:
    # app.logger.info(f"Extracción de texto para '{ext}' no es prioritaria o no soportada actualmente.")
    else:
        app.logger.info(f"Extracción de texto no soportada (o no implementada aún) para la extensión: {ext} en archivo '{filename_with_ext}'")

    if hasattr(file_stream, 'seek'):
        file_stream.seek(0)

    if texto_extraido.strip():
        try:
            # Usar suficiente texto para una detección de idioma más fiable, hasta 2000 caracteres.
            lang_code = lang_detect_func(texto_extraido[:2000])
            idioma_detectado = 'english' if lang_code == 'en' else 'spanish'
            app.logger.info(f"Idioma detectado para '{filename_with_ext}': {lang_code} -> {idioma_detectado}")
        except LangDetectException:
            app.logger.warning(f"No se pudo detectar idioma para '{filename_with_ext}', asumiendo '{idioma_detectado}'.")
        except Exception as e_lang: # Captura más genérica para otros posibles errores de langdetect
            app.logger.error(f"Error general durante la detección de idioma para '{filename_with_ext}': {e_lang}")

    return texto_extraido, idioma_detectado


def actualizar_tsvector_plano(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_archivo_val, idioma_doc='spanish'):
    try:
        texto_para_indexar = " ".join(filter(None, [
            codigo_plano_val, area_val, descripcion_val, contenido_archivo_val # Usar el contenido genérico del archivo
        ]))

        config_fts_pg = 'english' if idioma_doc == 'english' else 'spanish'
        # app.logger.info(f"Actualizando tsvector para plano_id {plano_id_val} con config FTS: '{config_fts_pg}' e idioma_documento: '{idioma_doc}'")

        stmt_tsvector = (
            db.update(Plano)
            .where(Plano.id == plano_id_val)
            .values(tsvector_contenido=func.to_tsvector(config_fts_pg, texto_para_indexar),
                    idioma_documento=idioma_doc)
        )
        db.session.execute(stmt_tsvector)
        # app.logger.info(f"Columna tsvector e idioma_documento actualizados en sesión para plano_id: {plano_id_val}")
    except Exception as e:
        app.logger.error(f"Error actualizando tsvector/idioma para plano_id {plano_id_val}: {e}", exc_info=True)
        raise # Re-lanzar la excepción para que pueda ser manejada por un rollback si es necesario

def lematizar_texto(texto, nlp_model, idioma_codigo_spacy): # idioma_codigo_spacy es más descriptivo
    if not nlp_model or not texto:
        # app.logger.debug(f"Lematización omitida para idioma '{idioma_codigo_spacy}': Modelo no cargado o texto vacío.")
        return texto
    # app.logger.debug(f"Lematizando texto en '{idioma_codigo_spacy}' (primeros 100c): {texto[:100]}...")
    doc = nlp_model(texto.lower()) # Convertir a minúsculas ANTES de procesar con spaCy
    lemmas = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct and token.lemma_.strip()]
    resultado = " ".join(lemmas) if lemmas else texto # Devolver texto original si no hay lemmas (p.ej. solo stopwords)
    # app.logger.debug(f"Texto lematizado (primeros 100c): {resultado[:100]}...")
    return resultado

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
        else: flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# --- Rutas Principales ---
@app.route('/')
def index():
    if R2_CONFIG_MISSING:
        flash("ADVERTENCIA: La configuración para R2 no está completa. Algunas funcionalidades pueden estar limitadas.", "danger")
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST']) # Considerar renombrar a /upload_file
@login_required
def upload_pdf(): # Considerar renombrar a upload_file
    if current_user.role not in ['admin', 'cargador']:
        flash('No tienes permiso para subir archivos.', 'danger')
        return redirect(url_for('index'))
    if R2_CONFIG_MISSING:
        flash("Subida de archivos deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        file_obj = request.files.get('file_to_upload') # Nombre genérico del campo de archivo
        codigo_plano_form = request.form.get('codigo_plano', '').strip()
        revision_form_original = request.form.get('revision', '').strip()
        area_form = request.form.get('area', '').strip()
        descripcion_form = request.form.get('descripcion', '').strip()

        if not file_obj or not file_obj.filename:
            flash('No se seleccionó ningún archivo.', 'warning')
            return redirect(request.url)

        original_filename = file_obj.filename
        _filename_root, ext = os.path.splitext(original_filename)
        ext = ext.lower() # Usar extensión en minúsculas

        if ext not in ALLOWED_EXTENSIONS:
            flash(f"Formato de archivo no permitido ('{ext}'). Solo se permiten: {', '.join(ALLOWED_EXTENSIONS)}", 'danger')
            return redirect(request.url)

        # --- LÓGICA DE EXTRACCIÓN Y DECISIÓN DE REVISIÓN ---
        revision_a_usar = revision_form_original
        revision_extraida_nombre = extraer_revision_del_filename(original_filename)

        if revision_extraida_nombre:
            if not revision_form_original:
                app.logger.info(f"Upload: Campo de revisión vacío. Usando revisión '{revision_extraida_nombre}' extraída de '{original_filename}'.")
                flash(f"Se ha detectado la revisión '{revision_extraida_nombre}' del nombre del archivo y se ha utilizado.", "info")
                revision_a_usar = revision_extraida_nombre
            elif revision_form_original.strip().upper() != revision_extraida_nombre:
                flash(f"Advertencia: La revisión ingresada en el formulario ('{revision_form_original}') es diferente de la detectada en el nombre del archivo ('{revision_extraida_nombre}'). "
                      f"Se utilizará la revisión del formulario: '{revision_form_original}'.", "warning")
        # --- FIN LÓGICA DE EXTRACCIÓN Y DECISIÓN DE REVISIÓN ---

        if not codigo_plano_form or not revision_a_usar:
            flash('Los campos Código de Plano y Revisión son obligatorios (la revisión puede ser detectada del nombre del archivo si el campo está vacío).', 'warning')
            return redirect(request.url)

        if not re.match(VALID_REVISION_PATTERN, revision_a_usar):
            origen_rev_invalida = f"valor '{revision_a_usar}'"
            if not revision_form_original and revision_extraida_nombre and revision_a_usar == revision_extraida_nombre:
                origen_rev_invalida = f"revisión '{revision_a_usar}' detectada del nombre del archivo"
            elif revision_form_original and revision_a_usar == revision_form_original:
                 origen_rev_invalida = f"revisión '{revision_a_usar}' ingresada en el formulario"
            flash(REVISION_FORMAT_ERROR_MSG + f" (El {origen_rev_invalida} no es válido).", 'danger')
            app.logger.warning(f"Upload: Formato de revisión inválido: '{revision_a_usar}' para código '{codigo_plano_form}'.")
            return redirect(request.url)

        area_final_determinada = None
        es_mr = codigo_plano_form.upper().startswith("K484-0000-0000-MR-")
        if es_mr:
            if area_form:
                area_final_determinada = area_form
            elif ext == '.pdf': # Solo intentar extraer área si es un PDF
                try:
                    if hasattr(file_obj.stream, 'seek'): file_obj.stream.seek(0)
                    area_extraida = extraer_area_del_pdf(file_obj.stream) # file_obj.stream es el stream del archivo
                    if area_extraida:
                        area_final_determinada = area_extraida
                        flash(f"Área del plano MR determinada automáticamente como: '{area_extraida}'.", "info")
                    else:
                        area_final_determinada = "Area_MR_Pendiente"
                        flash("No se pudo determinar el área para el plano MR PDF desde su contenido. Se asignó 'Area_MR_Pendiente'.", "warning")
                except Exception as e_area:
                    area_final_determinada = "Area_MR_Error"
                    flash(f"Error extrayendo área del plano MR PDF: {e_area}", "warning")
                    app.logger.error(f"Error al extraer área del PDF para MR: {e_area}")
            else: # Es MR, no se proveyó área, y NO es PDF
                area_final_determinada = "Area_MR_Pendiente"
                flash("Para planos MR que no son PDF, el área debe especificarse manualmente o se usará 'Area_MR_Pendiente'.", "info")
        else: # No es MR
            if area_form:
                area_final_determinada = area_form
            else:
                flash('El campo "Área" es obligatorio para planos que no son de tipo MR.', 'warning')
                return redirect(request.url)

        if area_final_determinada is None: # Doble chequeo por si alguna lógica falla
            flash('Error crítico: El área del plano no pudo ser determinada.', 'danger')
            return redirect(request.url)

        original_filename_secure = secure_filename(original_filename)
        cleaned_area = clean_for_path(area_final_determinada)
        cleaned_codigo = clean_for_path(codigo_plano_form)
        cleaned_revision_for_filename = clean_for_path(revision_a_usar)
        # Usar la extensión original validada (ext) para el nombre en R2
        r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision_for_filename}{ext}"
        r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"

        s3 = get_s3_client()
        if not s3:
            flash("Error en la configuración de R2. No se puede subir el archivo.", "danger")
            return redirect(request.url)

        try:
            planos_existentes_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_form).all()
            r2_object_keys_a_eliminar_si_nueva_rev = []
            db_entries_a_eliminar_si_nueva_rev = []

            if not planos_existentes_mismo_codigo:
                app.logger.info(f"Upload: Creando nuevo plano (primera revisión): {codigo_plano_form} Rev {revision_a_usar}")
            else:
                revision_actual_mas_alta_db_str = None
                plano_con_revision_ingresada = None
                for p_existente in planos_existentes_mismo_codigo:
                    if p_existente.revision.strip().upper() == revision_a_usar.strip().upper():
                        plano_con_revision_ingresada = p_existente
                    if revision_actual_mas_alta_db_str is None or \
                       es_revision_mas_nueva(p_existente.revision, revision_actual_mas_alta_db_str):
                        revision_actual_mas_alta_db_str = p_existente.revision

                if plano_con_revision_ingresada:
                    flash(f"La revisión '{revision_a_usar}' para el plano '{codigo_plano_form}' ya existe. "
                          f"Si desea reemplazar el archivo o modificar sus datos, por favor utilice la opción de editar el plano existente.", "danger")
                    app.logger.warning(f"Upload: Intento de subir plano con revisión existente: {codigo_plano_form} Rev {revision_a_usar}.")
                    return redirect(request.url)

                if not revision_actual_mas_alta_db_str or \
                   not es_revision_mas_nueva(revision_a_usar, revision_actual_mas_alta_db_str):
                    error_msg = f"La revisión '{revision_a_usar}' para el plano '{codigo_plano_form}' no es válida. "
                    if revision_actual_mas_alta_db_str:
                        error_msg += f"Debe ser una revisión más nueva que la existente más alta ('{revision_actual_mas_alta_db_str}')."
                    else:
                        error_msg += "Debe ser la primera revisión válida o una revisión más nueva que las existentes."
                    flash(error_msg, "danger")
                    app.logger.warning(f"Upload: Revisión '{revision_a_usar}' para '{codigo_plano_form}' no sigue secuencia. Más alta DB: '{revision_actual_mas_alta_db_str}'.")
                    return redirect(request.url)

                app.logger.info(f"Upload: Nueva revisión '{revision_a_usar}' es la más alta para {codigo_plano_form} (anterior más alta: '{revision_actual_mas_alta_db_str}'). Planos antiguos serán eliminados.")
                for p_antiguo in planos_existentes_mismo_codigo:
                    if p_antiguo.r2_object_key:
                        r2_object_keys_a_eliminar_si_nueva_rev.append(p_antiguo.r2_object_key)
                    db_entries_a_eliminar_si_nueva_rev.append(p_antiguo)

            plano_a_crear = Plano(
                codigo_plano=codigo_plano_form,
                revision=revision_a_usar,
                area=area_final_determinada,
                nombre_archivo_original=original_filename_secure, # Guardar nombre original con extensión
                r2_object_key=r2_object_key_nuevo,
                descripcion=descripcion_form,
                # idioma_documento se establecerá después de la extracción de texto
            )

            texto_contenido_archivo, idioma_doc_detectado = "", plano_a_crear.idioma_documento
            try:
                if hasattr(file_obj.stream, 'seek'): file_obj.stream.seek(0)
                # Pasar original_filename para que extraer_texto_del_archivo sepa la extensión
                texto_contenido_archivo, idioma_doc_detectado = extraer_texto_del_archivo(file_obj.stream, original_filename)
            except Exception as e_extr_texto:
                app.logger.error(f"Upload: Fallo al extraer texto/idioma del archivo '{original_filename}': {e_extr_texto}", exc_info=True)
                # Continuar sin el texto si falla, pero registrarlo. El idioma será el default.

            plano_a_crear.idioma_documento = idioma_doc_detectado
            plano_a_crear.fecha_subida = datetime.now(timezone.utc)

            db.session.add(plano_a_crear)

            try:
                if hasattr(file_obj.stream, 'seek'): file_obj.stream.seek(0)
                s3.upload_fileobj(file_obj.stream, R2_BUCKET_NAME, r2_object_key_nuevo)
                app.logger.info(f"Upload: Archivo '{r2_object_key_nuevo}' subido a R2.")
            except ClientError as e_s3:
                db.session.rollback()
                flash(f"Error de conexión al subir el archivo a R2: {e_s3.response.get('Error', {}).get('Message', 'Error R2 desconocido')}", "danger")
                return redirect(request.url)

            db.session.flush() # Para obtener el ID del plano_a_crear
            plano_id_actual = plano_a_crear.id

            actualizar_tsvector_plano(
                plano_id_actual, plano_a_crear.codigo_plano,
                plano_a_crear.area, plano_a_crear.descripcion,
                texto_contenido_archivo, # Pasar el texto extraído
                idioma_doc_detectado
            )

            # Eliminar archivos antiguos en R2 y entradas de BD
            for r2_key in set(r2_object_keys_a_eliminar_si_nueva_rev):
                if r2_key and r2_key != r2_object_key_nuevo: # No eliminar el que acabamos de subir
                    try:
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
                        app.logger.info(f"Upload: Objeto R2 antiguo '{r2_key}' eliminado.")
                    except Exception as e_del_r2:
                        app.logger.error(f"Upload: Error borrando objeto R2 antiguo '{r2_key}': {e_del_r2}")

            for plano_db_a_borrar in db_entries_a_eliminar_si_nueva_rev:
                app.logger.info(f"Upload: Eliminando registro de BD para plano ID {plano_db_a_borrar.id} ({plano_db_a_borrar.codigo_plano} Rev {plano_db_a_borrar.revision}).")
                db.session.delete(plano_db_a_borrar)

            db.session.commit()

            flash_msg = f"Archivo '{original_filename_secure}' (Plano: {codigo_plano_form} Rev: {revision_a_usar}) subido exitosamente."
            # Advertir si no se pudo extraer texto de tipos de archivo donde se espera (PDF, TXT, DOCX)
            if not texto_contenido_archivo and ext in ['.pdf', '.txt', '.docx']:
                 flash_msg += f" ADVERTENCIA: No se pudo leer el contenido del archivo {ext.upper()} para indexación de búsqueda."
            flash(flash_msg, "success" if (texto_contenido_archivo or ext not in ['.pdf', '.txt', '.docx']) else "warning")

            return redirect(url_for('list_pdfs'))

        except Exception as e_general:
            db.session.rollback()
            flash(f"Error general al procesar el archivo: {str(e_general)}", "danger")
            app.logger.error(f"Upload: Error general: {e_general}", exc_info=True)
            return redirect(request.url)

    return render_template('upload_pdf.html') # Considerar renombrar plantilla a upload_file.html


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
        file_obj_edit = request.files.get('file_to_edit') # Campo para el nuevo archivo

        if not nueva_revision_form or not nueva_area_form:
            flash('Los campos Revisión y Área son obligatorios.', 'warning')
            return render_template('edit_plano.html', plano=plano_a_editar)

        if not re.match(VALID_REVISION_PATTERN, nueva_revision_form):
            flash(REVISION_FORMAT_ERROR_MSG, 'danger')
            app.logger.warning(f"Edit: Formato de revisión inválido: '{nueva_revision_form}' para plano ID {plano_id}.")
            return render_template('edit_plano.html', plano=plano_a_editar)

        antigua_r2_object_key = plano_a_editar.r2_object_key
        _ , current_ext_original = os.path.splitext(plano_a_editar.nombre_archivo_original)
        current_ext_original = current_ext_original.lower()

        nueva_ext_a_usar = current_ext_original # Por defecto, la extensión no cambia
        nuevo_nombre_archivo_original_secure = plano_a_editar.nombre_archivo_original

        if file_obj_edit and file_obj_edit.filename:
            nuevo_nombre_archivo_original_secure = secure_filename(file_obj_edit.filename)
            _ , ext_nuevo_archivo = os.path.splitext(nuevo_nombre_archivo_original_secure)
            ext_nuevo_archivo = ext_nuevo_archivo.lower()
            if ext_nuevo_archivo not in ALLOWED_EXTENSIONS:
                flash(f"Formato de archivo para reemplazo no permitido ('{ext_nuevo_archivo}'). Permitidos: {', '.join(ALLOWED_EXTENSIONS)}", 'warning')
                return render_template('edit_plano.html', plano=plano_a_editar)
            nueva_ext_a_usar = ext_nuevo_archivo # Usar la extensión del archivo nuevo

        nueva_area_limpia = clean_for_path(nueva_area_form)
        nueva_revision_limpia_for_filename = clean_for_path(nueva_revision_form)
        codigo_plano_limpio = clean_for_path(plano_a_editar.codigo_plano)
        # Nombre del archivo en R2 usa la nueva extensión determinada
        nuevo_r2_filename = f"{codigo_plano_limpio}_Rev{nueva_revision_limpia_for_filename}{nueva_ext_a_usar}"
        nueva_r2_object_key = f"{R2_OBJECT_PREFIX}{nueva_area_limpia}/{nuevo_r2_filename}"

        # Validar conflicto de revisión si la revisión cambia
        if nueva_revision_form.strip().upper() != plano_a_editar.revision.strip().upper():
            conflicto_revision = Plano.query.filter(
                Plano.codigo_plano == plano_a_editar.codigo_plano,
                func.upper(Plano.revision) == nueva_revision_form.strip().upper(),
                Plano.id != plano_id
            ).first()
            if conflicto_revision:
                flash(f"Error: Ya existe otro plano con código '{plano_a_editar.codigo_plano}' y la nueva revisión '{nueva_revision_form}'.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)

        # Validar conflicto de R2 object key si cambia
        if nueva_r2_object_key != antigua_r2_object_key:
            conflicto_r2_key = Plano.query.filter(Plano.r2_object_key == nueva_r2_object_key, Plano.id != plano_id).first()
            if conflicto_r2_key:
                flash(f"Error: La ruta de archivo generada '{nueva_r2_object_key}' ya está en uso por otro plano. Verifique Área y Revisión.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)
        try:
            # Actualizar metadatos del plano
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.fecha_subida = datetime.now(timezone.utc) # Actualizar fecha en cualquier cambio

            texto_contenido_para_fts = ""
            idioma_doc_para_fts = plano_a_editar.idioma_documento # Mantener por defecto

            if file_obj_edit and file_obj_edit.filename: # Si se subió un nuevo archivo
                app.logger.info(f"Edit: Reemplazando archivo para plano ID {plano_id}. Nueva key: '{nueva_r2_object_key}', Nombre original: '{nuevo_nombre_archivo_original_secure}'.")
                plano_a_editar.nombre_archivo_original = nuevo_nombre_archivo_original_secure
                plano_a_editar.r2_object_key = nueva_r2_object_key # La key cambia por el archivo o sus metadatos

                try:
                    if hasattr(file_obj_edit.stream, 'seek'): file_obj_edit.stream.seek(0)
                    texto_contenido_para_fts, idioma_doc_para_fts = extraer_texto_del_archivo(file_obj_edit.stream, nuevo_nombre_archivo_original_secure)
                    plano_a_editar.idioma_documento = idioma_doc_para_fts

                    if hasattr(file_obj_edit.stream, 'seek'): file_obj_edit.stream.seek(0)
                    s3.upload_fileobj(file_obj_edit.stream, R2_BUCKET_NAME, nueva_r2_object_key)
                    app.logger.info(f"Edit: Nuevo archivo subido a R2: '{nueva_r2_object_key}'")

                    # Si la R2 key antigua es diferente y existe, eliminar el objeto antiguo de R2
                    if antigua_r2_object_key and antigua_r2_object_key != nueva_r2_object_key:
                        app.logger.info(f"Edit: Eliminando objeto R2 antiguo '{antigua_r2_object_key}' después de reemplazar archivo.")
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)

                except ClientError as e_s3_edit:
                    db.session.rollback()
                    flash(f"Error de conexión al subir el nuevo archivo: {e_s3_edit.response.get('Error', {}).get('Message', 'Error R2')}", "danger")
                    return render_template('edit_plano.html', plano=plano_a_editar)
                except Exception as e_upload_edit: # Otros errores de procesamiento del nuevo archivo
                    db.session.rollback()
                    flash(f"Error procesando o subiendo el nuevo archivo: {str(e_upload_edit)}", "danger")
                    app.logger.error(f"Edit: Error procesando/subiendo nuevo archivo: {e_upload_edit}", exc_info=True)
                    return render_template('edit_plano.html', plano=plano_a_editar)
            else: # No se subió archivo nuevo, pero metadatos (área/revisión) pudieron cambiar la R2 key
                if nueva_r2_object_key != antigua_r2_object_key and antigua_r2_object_key and s3:
                    app.logger.info(f"Edit: Solo metadatos cambiaron, moviendo en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}'.")
                    try:
                        copy_source = {'Bucket': R2_BUCKET_NAME, 'Key': antigua_r2_object_key}
                        s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                        plano_a_editar.r2_object_key = nueva_r2_object_key # Confirmar el cambio de key
                        app.logger.info(f"Edit: Archivo movido en R2.")
                    except Exception as e_move_r2:
                        db.session.rollback()
                        flash(f"Error al mover el archivo en R2 debido a cambio de metadatos: {str(e_move_r2)}", "danger")
                        app.logger.error(f"Edit: Error moviendo objeto en R2: {e_move_r2}", exc_info=True)
                        # Revertir el cambio de r2_object_key en el objeto plano si falla el movimiento
                        plano_a_editar.r2_object_key = antigua_r2_object_key
                        return render_template('edit_plano.html', plano=plano_a_editar)

                # Si no se subió archivo, necesitamos el texto del archivo existente (que pudo haberse movido a nueva_r2_object_key)
                # para actualizar el tsvector. El idioma ya está en plano_a_editar.idioma_documento.
                if s3 and plano_a_editar.r2_object_key: # Usar la key que tiene ahora, sea nueva o antigua
                    app.logger.info(f"Edit: No se subió nuevo archivo. Re-extrayendo texto de R2 object '{plano_a_editar.r2_object_key}' para FTS.")
                    try:
                        response = s3.get_object(Bucket=R2_BUCKET_NAME, Key=plano_a_editar.r2_object_key)
                        file_content_stream = response['Body'] # Esto es un stream
                        # Necesitamos un objeto BytesIO si la función de extracción lo espera así, o leerlo a bytes
                        # y luego crear un stream en memoria si es necesario.
                        file_bytes = file_content_stream.read()
                        file_like_object = io.BytesIO(file_bytes)

                        texto_contenido_para_fts, _ = extraer_texto_del_archivo(file_like_object, plano_a_editar.nombre_archivo_original)
                        # El idioma del documento no debería cambiar si no se sube un nuevo archivo.
                        idioma_doc_para_fts = plano_a_editar.idioma_documento
                        app.logger.info(f"Edit: Texto re-extraído de '{plano_a_editar.r2_object_key}' para FTS (longitud: {len(texto_contenido_para_fts)}).")
                    except Exception as e_reextract:
                        app.logger.error(f"Edit: No se pudo descargar o re-extraer texto de '{plano_a_editar.r2_object_key}' de R2: {e_reextract}", exc_info=True)
                        flash("Advertencia: No se pudo actualizar el contenido del archivo en la búsqueda. Los metadatos sí se actualizarán.", "warning")
                        # texto_contenido_para_fts permanecerá vacío, FTS se actualizará solo con metadatos.
                else:
                    app.logger.warning(f"Edit: No hay cliente S3 o R2 object key para el plano ID {plano_id} para re-extraer texto. FTS se actualizará solo con metadatos.")


            actualizar_tsvector_plano(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano,
                area_val=plano_a_editar.area, # Usar nueva área
                descripcion_val=plano_a_editar.descripcion, # Usar nueva descripción
                contenido_archivo_val=texto_contenido_para_fts,
                idioma_doc=idioma_doc_para_fts
            )

            db.session.commit()
            flash_msg = f"Plano '{plano_a_editar.codigo_plano}' (Rev: {plano_a_editar.revision}) actualizado exitosamente."
            if (file_obj_edit and file_obj_edit.filename) and not texto_contenido_para_fts and nueva_ext_a_usar in ['.pdf', '.txt', '.docx']:
                flash_msg += f" ADVERTENCIA: No se pudo leer el contenido del nuevo archivo {nueva_ext_a_usar.upper()} para indexación."
            flash(flash_msg, "success" if not ((file_obj_edit and file_obj_edit.filename) and not texto_contenido_para_fts and nueva_ext_a_usar in ['.pdf', '.txt', '.docx']) else "warning")

            return redirect(url_for('list_pdfs'))

        except Exception as e: # Captura general para otros errores durante el commit o lógica no esperada
            db.session.rollback()
            flash(f"Error general al actualizar el plano: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)

    return render_template('edit_plano.html', plano=plano_a_editar)


@app.route('/pdfs')
@login_required
def list_pdfs():
    try:
        # Obtener parámetros de búsqueda del formulario
        query_codigo = request.args.get('q_codigo', '').strip()
        query_area = request.args.get('q_area', '').strip()
        query_contenido_original = request.args.get('q_contenido', '').strip()
        query_nombre_archivo = request.args.get('q_nombre_archivo', '').strip()

        # 1. Iniciar la consulta base
        base_query = Plano.query

        # 2. APLICAR FILTRO DE PERMISOS (EL PASO MÁS IMPORTANTE)
        # Si el usuario NO es admin, se restringe la consulta base a solo sus áreas permitidas.
        if current_user.role != 'admin':
            user_allowed_areas = current_user.allowed_areas
            
            if not user_allowed_areas:
                # Si no tiene áreas asignadas, no debe ver nada.
                return render_template('list_pdfs.html', planos=[], R2_OBJECT_PREFIX=R2_OBJECT_PREFIX, R2_ENDPOINT_URL=R2_ENDPOINT_URL, R2_BUCKET_NAME=R2_BUCKET_NAME)
            
            # Se modifica la consulta base para que SOLO incluya los planos de las áreas permitidas.
            base_query = base_query.filter(Plano.area.in_(user_allowed_areas))

        # 3. A partir de aquí, se trabaja sobre la consulta YA FILTRADA por permisos.
        final_query = base_query

        # Aplicar filtros de búsqueda adicionales
        if query_codigo:
            final_query = final_query.filter(Plano.codigo_plano.ilike(f'%{query_codigo}%'))
        
        if query_area:
            # Un usuario no puede buscar un área a la que no tiene acceso.
            if current_user.role != 'admin' and query_area not in current_user.allowed_areas:
                final_query = final_query.filter(db.false())
            else:
                final_query = final_query.filter(Plano.area.ilike(f'%{query_area}%'))

        if query_nombre_archivo:
            final_query = final_query.filter(Plano.nombre_archivo_original.ilike(f'%{query_nombre_archivo}%'))

        # Lógica de búsqueda por contenido (FTS)
        if query_contenido_original and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgresql"):
            # (Toda la lógica de FTS que ya tenías va aquí, aplicada sobre 'final_query')
            # ... (código FTS) ...
            pass # Placeholder para tu lógica FTS

        # 4. Ejecutar la consulta final y obtener los resultados
        planos_db = final_query.order_by(Plano.area, Plano.codigo_plano.desc()).all()

    except Exception as e:
        flash(f"Error al obtener la lista de planos: {str(e)}", "danger")
        app.logger.error(f"Error en la ruta /pdfs (list_pdfs): {e}", exc_info=True)
        planos_db = []
    
    return render_template('list_pdfs.html', planos=planos_db, R2_OBJECT_PREFIX=R2_OBJECT_PREFIX, R2_ENDPOINT_URL=R2_ENDPOINT_URL, R2_BUCKET_NAME=R2_BUCKET_NAME)


@app.route('/files/view/<path:object_key>') # Renombrada para generalidad
@login_required
def view_file(object_key): # Renombrada para generalidad
    if R2_CONFIG_MISSING:
        flash("Visualización de archivos deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for('list_pdfs')) # O a donde sea apropiado
    s3 = get_s3_client()
    if not s3:
        flash("Error en la configuración de R2. No se puede visualizar el archivo.", "danger")
        return redirect(url_for('list_pdfs'))
    try:
        # Generar URL pre-firmada para descargar/visualizar el archivo
        # El navegador decidirá cómo manejarlo basado en el Content-Type que R2 sirva
        # o en la extensión del archivo si R2 no establece un Content-Type específico.
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key},
            ExpiresIn=3600 # URL válida por 1 hora
        )
        return redirect(presigned_url)
    except Exception as e:
        flash(f"Error al generar enlace para el archivo: {str(e)}", "danger")
        app.logger.error(f"Error generando URL pre-firmada para {object_key}: {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))


@app.route('/files/delete/<int:plano_id>', methods=['POST']) # Renombrada para generalidad
@login_required
def delete_file(plano_id): # Renombrada para generalidad
    if current_user.role not in ['admin', 'cargador']:
        flash('No tienes permiso para eliminar archivos.', 'danger')
        return redirect(url_for('list_pdfs'))
    if R2_CONFIG_MISSING:
        flash("Eliminación de archivos deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for('list_pdfs'))

    plano_a_eliminar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()
    if not s3:
        flash("Error en la configuración de R2. No se puede eliminar el archivo de R2.", "danger")
        return redirect(url_for('list_pdfs'))

    r2_key_a_eliminar = plano_a_eliminar.r2_object_key
    try:
        if r2_key_a_eliminar:
            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key_a_eliminar)
            app.logger.info(f"Objeto '{r2_key_a_eliminar}' eliminado de R2.")

        db.session.delete(plano_a_eliminar)
        db.session.commit()
        flash(f"Plano '{plano_a_eliminar.codigo_plano}' Revisión '{plano_a_eliminar.revision}' y su archivo asociado eliminados exitosamente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el plano y/o su archivo: {str(e)}", "danger")
        app.logger.error(f"Error eliminando plano ID {plano_id} (R2 key: {r2_key_a_eliminar}): {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))


@app.route('/medidor/plano/<path:object_key>') # Esta ruta es específica para PDFs
@login_required
def visor_medidor_pdf(object_key):
    # Asegurarse que el object_key corresponde a un PDF antes de proceder.
    # Podrías obtener el 'nombre_archivo_original' desde la BD usando el object_key y chequear su extensión.
    plano_asociado = Plano.query.filter_by(r2_object_key=object_key).first()
    if plano_asociado and not plano_asociado.nombre_archivo_original.lower().endswith('.pdf'):
        flash("La herramienta de medición solo está disponible para archivos PDF.", "warning")
        return redirect(request.referrer or url_for('list_pdfs'))
    if not plano_asociado: # Si no se encuentra el plano, aunque es poco probable si la key es correcta.
        flash("No se encontró el plano asociado a esta clave de objeto.", "warning")
        return redirect(request.referrer or url_for('list_pdfs'))


    app.logger.info(f"Accediendo al visor medidor para R2 object key (PDF): {object_key}")

    if R2_CONFIG_MISSING:
        flash("La herramienta de medición no está disponible: Falta configuración de R2.", "danger")
        return redirect(request.referrer or url_for('list_pdfs'))

    s3 = get_s3_client()
    if not s3:
        flash("Error al conectar con el almacenamiento de archivos (R2). No se puede cargar el visor.", "danger")
        return redirect(request.referrer or url_for('list_pdfs'))

    try:
        pdf_presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key},
            ExpiresIn=3600 # 1 hora
        )
        app.logger.info(f"URL pre-firmada generada para visor medidor {object_key}: {pdf_presigned_url[:100]}...")

        pdf_worker_url = url_for('static', filename='lib/pdfjs/build/pdf.worker.mjs') # Asegúrate que esta ruta es correcta
        app.logger.info(f"URL para PDF.js worker: {pdf_worker_url}")

        page_title = f"Medición: {plano_asociado.codigo_plano} Rev {plano_asociado.revision}"

        return render_template(
            'pdf_measure_viewer.html',
            pdf_url_to_load=pdf_presigned_url,
            pdf_worker_url=pdf_worker_url,
            page_title=page_title
        )

    except ClientError as e_s3_presign:
        flash(f"Error al generar el enlace seguro para el PDF (medidor): {e_s3_presign.response.get('Error', {}).get('Message', 'Error R2 desconocido')}", "danger")
        app.logger.error(f"Error de Cliente S3 generando URL pre-firmada para visor medidor {object_key}: {e_s3_presign}", exc_info=True)
        return redirect(request.referrer or url_for('list_pdfs'))
    except Exception as e:
        flash(f"Error inesperado al preparar el visor de medición: {str(e)}", "danger")
        app.logger.error(f"Error general en visor_medidor_pdf para {object_key}: {e}", exc_info=True)
        return redirect(request.referrer or url_for('list_pdfs'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for('index'))

    # Obtener todas las áreas únicas para el formulario de asignación
    distinct_areas_tuples = db.session.query(Plano.area).distinct().order_by(Plano.area).all()
    distinct_areas = [area[0] for area in distinct_areas_tuples]

    assignable_roles = ['consultor', 'cargador']
    form_username, form_role = ('', '')
    error_in_form = False

    if request.method == 'POST':
        form_username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        form_role = request.form.get('role', '').strip()
        
        # --- LÓGICA DE PERMISOS MEJORADA ---
        # 1. Obtener áreas seleccionadas de la lista múltiple
        selected_areas = request.form.getlist('areas')
        
        # 2. Obtener áreas nuevas del campo de texto
        new_areas_str = request.form.get('new_areas', '').strip()
        # Procesar para obtener una lista limpia, ignorando espacios y entradas vacías
        new_areas_list = [area.strip() for area in new_areas_str.split(',') if area.strip()]

        # 3. Combinar ambas listas y eliminar duplicados usando un set
        all_selected_areas = set(selected_areas + new_areas_list)
        # --- FIN DE LA LÓGICA MEJORADA ---

        # ... (validaciones de username, password, role, no cambian)
        if not form_username or not password or not form_role:
            flash("Todos los campos (nombre, contraseña, rol) son obligatorios.", "warning")
            error_in_form = True
        
        if not error_in_form and User.query.filter(func.lower(User.username) == func.lower(form_username)).first():
            flash("Nombre de usuario ya existe.", "warning")
            error_in_form = True
        
        if not error_in_form and form_role not in assignable_roles:
            flash(f"Rol '{form_role}' inválido.", "warning")
            error_in_form = True

        if not error_in_form:
            try:
                # Unir el conjunto final de áreas en un string ordenado
                allowed_areas_str = ",".join(sorted(list(all_selected_areas)))
                
                new_user = User(
                    username=form_username, 
                    role=form_role,
                    allowed_areas_str=allowed_areas_str
                )
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash(f"Usuario '{form_username}' creado con acceso a {len(all_selected_areas)} áreas.", "success")
                return redirect(url_for('manage_users'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error creando usuario: {str(e)}", "danger")
                error_in_form = True

    users = User.query.order_by(User.username).all()
    
    return render_template('admin_manage_users.html',
                           users=users,
                           assignable_roles=assignable_roles,
                           distinct_areas=distinct_areas,
                           current_username_creating=form_username if error_in_form else '',
                           current_role_creating=form_role if error_in_form else '')
    
    # --- LÍNEA CORREGIDA ---
    # Ahora pasamos 'distinct_areas' a la plantilla.
    return render_template('admin_manage_users.html',
                           users=users,
                           assignable_roles=assignable_roles,
                           distinct_areas=distinct_areas,
                           current_username_creating=form_username if error_in_form else '',
                           current_role_creating=form_role if error_in_form else '')

# AÑADE ESTA FUNCIÓN COMPLETA EN app.py

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Solo el admin puede editar usuarios.
    if current_user.role != 'admin':
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for('index'))

    # Buscamos al usuario a editar en la base de datos. Si no existe, error 404.
    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for('manage_users'))
        
    # No se puede editar al propio admin principal para evitar bloqueos
    if user_to_edit.username == 'admin' and user_to_edit.id == 1:
        flash("La cuenta principal de administrador no se puede editar desde aquí.", "warning")
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        # --- LÓGICA PARA GUARDAR LOS CAMBIOS ---
        # Obtenemos los nuevos datos del formulario
        new_role = request.form.get('role')
        new_password = request.form.get('password')
        
        selected_areas = request.form.getlist('areas')
        new_areas_str = request.form.get('new_areas', '').strip()
        new_areas_list = [area.strip() for area in new_areas_str.split(',') if area.strip()]
        
        # Combinamos y limpiamos las áreas
        all_selected_areas = set(selected_areas + new_areas_list)
        allowed_areas_str = ",".join(sorted(list(all_selected_areas)))

        # Actualizamos los datos del usuario
        user_to_edit.role = new_role
        user_to_edit.allowed_areas_str = allowed_areas_str
        
        # IMPORTANTE: Solo cambiamos la contraseña si se escribió algo en el campo.
        if new_password:
            user_to_edit.set_password(new_password)
            flash(f"Se han guardado los cambios para '{user_to_edit.username}', incluyendo la nueva contraseña.", "success")
        else:
            flash(f"Se han guardado los cambios para '{user_to_edit.username}'. La contraseña no se modificó.", "success")

        db.session.commit()
        return redirect(url_for('manage_users'))

    # --- LÓGICA PARA MOSTRAR EL FORMULARIO (GET) ---
    # Obtenemos todas las áreas existentes para mostrarlas en el formulario
    distinct_areas_tuples = db.session.query(Plano.area).distinct().order_by(Plano.area).all()
    all_areas = [area[0] for area in distinct_areas_tuples]
    
    assignable_roles = ['consultor', 'cargador']
    
    return render_template('edit_user.html', 
                           user_to_edit=user_to_edit, 
                           all_areas=all_areas,
                           assignable_roles=assignable_roles)


@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("Acceso no autorizado.", "danger")
        app.logger.warning(f"Intento de acceso no autorizado a delete_user por '{current_user.username}'.")
        return redirect(url_for('index'))

    user_to_delete = db.session.get(User, user_id)

    if not user_to_delete:
        flash("Usuario no encontrado.", "warning")
        app.logger.warning(f"Admin '{current_user.username}' intentó eliminar usuario ID {user_id} no existente.")
        return redirect(url_for('manage_users'))

    if user_to_delete.id == current_user.id:
        flash("No puedes eliminar tu propia cuenta de administrador.", "danger")
        app.logger.warning(f"Admin '{current_user.username}' intentó auto-eliminarse (ID: {user_id}).")
        return redirect(url_for('manage_users'))

    try:
        username_deleted = user_to_delete.username
        role_deleted = user_to_delete.role
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"Usuario '{username_deleted}' (Rol: {role_deleted}) eliminado exitosamente.", "success")
        app.logger.info(f"Admin '{current_user.username}' eliminó usuario '{username_deleted}' (ID: {user_id}, Rol: {role_deleted}).")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el usuario: {str(e)}", "danger")
        app.logger.error(f"Error eliminando usuario ID {user_id} por admin '{current_user.username}': {e}", exc_info=True)

    return redirect(url_for('manage_users'))


# --- Bloque de Inicialización de la Aplicación ---
with app.app_context():
    db.create_all() # Crear tablas si no existen

    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username='admin').first():
        try:
            admin_user = User(username='admin', role='admin')
            # Es MUY recomendable cambiar esta contraseña y gestionarla de forma segura (ej. variable de entorno)
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario 'admin' por defecto creado.")
        except Exception as e: # Captura excepciones más específicas si es posible (ej. IntegrityError)
            db.session.rollback()
            app.logger.error(f"Error creando usuario admin por defecto: {e}")

    # Crear usuario consultor por defecto si no existe
    if not User.query.filter_by(username='usuario').first():
        try:
            consultor_user = User(username='usuario', role='consultor')
            consultor_user.set_password(os.getenv('CONSULTOR_PASSWORD', 'eimisa')) # Cambiar y gestionar de forma segura
            db.session.add(consultor_user)
            db.session.commit()
            app.logger.info("Usuario 'usuario' (consultor) por defecto creado.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creando usuario consultor por defecto: {e}")

    app.logger.info("Contexto de aplicación inicializado: Base de datos y usuarios por defecto verificados/creados.")


if __name__ == '__main__':
    if R2_CONFIG_MISSING:
        print("\nADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.")
        print("La subida, visualización, medición y eliminación de archivos almacenados en R2 no funcionarán correctamente.\n")
    print("Iniciando servidor de desarrollo Flask local...")
    port = int(os.getenv('PORT', 5000))
    print(f"La aplicación debería estar disponible en http://0.0.0.0:{port} o http://127.0.0.1:{port}")
    # FLASK_DEBUG='true' o 'false' (string) en .env
    # El valor 'False' (con F mayúscula) de getenv no se evalúa a booleano False directamente con 'in'
    is_debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() in ['true', '1', 't', 'yes']
    app.run(debug=is_debug_mode, host='0.0.0.0', port=port)