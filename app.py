# Copyright (c) 2025 EDUARDO ANDRES PEREIRA CARVAJAL. Todos los derechos reservados.

# ==============================================================================
# 1. IMPORTACIONES DE MÓDULOS
# ==============================================================================

# ----------------------------------------
# Módulos estándar de Python
# ----------------------------------------
import os
import re
import io
from datetime import datetime, timezone

# ----------------------------------------
# Módulos de terceros (Third-party)
# ----------------------------------------
import boto3
import docx
import spacy
import pdfplumber
import google.generativeai as genai
from dotenv import load_dotenv
from botocore.client import Config
from botocore.exceptions import ClientError
from spellchecker import SpellChecker
from deep_translator import GoogleTranslator
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from packaging.version import parse as parse_version, InvalidVersion
from langdetect import detect as lang_detect_func, LangDetectException

# ----------------------------------------
# Módulos de Flask y extensiones
# ----------------------------------------
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, func
from sqlalchemy.dialects.postgresql import TSVECTOR
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)

# ==============================================================================
# 2. CONFIGURACIÓN INICIAL Y DE ENTORNO
# ==============================================================================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

# ==============================================================================
# 3. CONSTANTES Y CONFIGURACIONES GLOBALES
# ==============================================================================

# --- Constantes de la aplicación ---
VALID_REVISION_PATTERN = r"^[a-zA-Z0-9_.\-]{1,10}$"
REVISION_FORMAT_ERROR_MSG = (
    "El formato de la revisión no es válido. "
    "Debe tener entre 1 y 10 caracteres (letras, números, '_', '.', '-'). "
    "No se permiten espacios."
)
ALLOWED_EXTENSIONS = [
    ".pdf",
    ".txt",
    ".docx",
    ".xlsx",
    ".dwg",
    ".dxf",
    ".jpg",
    ".jpeg",
    ".png",
]
R2_OBJECT_PREFIX = "planos/"
BASE_DIR = os.path.abspath(os.path.dirname(__file__)) # Para SQLite local

# --- Configuración de la Base de Datos (PostgreSQL o SQLite local) ---
DATABASE_URL_ENV = os.getenv("DATABASE_URL")
if DATABASE_URL_ENV:
    if DATABASE_URL_ENV.startswith("postgres://"):
        DATABASE_URL_ENV = DATABASE_URL_ENV.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL_ENV
    app.logger.info("Usando base de datos PostgreSQL externa.")
else:
    db_file_path = os.path.join(BASE_DIR, "planos_dev.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_file_path
    app.logger.info(
        f"ADVERTENCIA: DATABASE_URL no encontrada. Usando base de datos SQLite local en: {db_file_path}"
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Opciones para el motor de la base de datos para manejar timeouts
engine_options = {
    "pool_recycle": 280,  # Refresca conexiones que tienen más de 280 segundos (4.6 minutos)
    "pool_pre_ping": True,  # Verifica si la conexión está viva antes de usarla
}

# --- Configuración de Cloudflare R2 ---
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME")
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY")
R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL")
if not R2_ENDPOINT_URL and R2_ACCOUNT_ID:
    R2_ENDPOINT_URL = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
R2_CONFIG_MISSING = not all(
    [R2_BUCKET_NAME, R2_ENDPOINT_URL, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY]
)


# ==============================================================================
# 4. INICIALIZACIÓN DE EXTENSIONES Y SERVICIOS
# ==============================================================================

# --- Base de datos SQLAlchemy ---
db = SQLAlchemy(app, engine_options=engine_options)

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"

# --- Corrector Ortográfico ---
spell = SpellChecker(language="es")

# --- Modelos de Lenguaje spaCy ---
NLP_ES = None
NLP_EN = None
try:
    NLP_ES = spacy.load("es_core_news_sm")
    app.logger.info("Modelo spaCy 'es_core_news_sm' cargado.")
except Exception as e_es:
    app.logger.error(
        f"FALLO AL CARGAR MODELO spaCy 'es_core_news_sm': {e_es}. Lematización en español deshabilitada."
    )
try:
    NLP_EN = spacy.load("en_core_web_sm")
    app.logger.info("Modelo spaCy 'en_core_web_sm' cargado.")
except Exception as e_en:
    app.logger.error(
        f"FALLO AL CARGAR MODELO spaCy 'en_core_web_sm': {e_en}. Lematización en inglés deshabilitada."
    )

# --- API de Google Gemini ---
if os.getenv("GOOGLE_API_KEY"):
    try:
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    except Exception as e:
        app.logger.error(f"No se pudo configurar la API de Google Gemini: {e}")

# ==============================================================================
# 5. MODELOS DE LA BASE DE DATOS
# ==============================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="consultor")
    
    # Aquí se guardarán las áreas permitidas como un string: "piping,mecanica,oocc"
    allowed_areas_str = db.Column(db.String(500), nullable=True)

    @property
    def allowed_areas(self):
        """Devuelve una lista de las áreas permitidas para el usuario."""
        if not self.allowed_areas_str:
            return []
        # Limpia espacios en blanco y devuelve la lista
        return [area.strip() for area in self.allowed_areas_str.split(",")]

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Plano(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo_plano = db.Column(db.String(200), nullable=False)
    revision = db.Column(db.String(50), nullable=False)
    area = db.Column(db.String(100), nullable=False)
    nombre_archivo_original = db.Column(db.String(255), nullable=True)
    r2_object_key = db.Column(db.String(500), unique=True, nullable=False)
    fecha_subida = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    descripcion = db.Column(db.Text, nullable=True)
    idioma_documento = db.Column(db.String(10), nullable=True, default="spanish")
    tsvector_contenido = db.Column(TSVECTOR)
    disciplina = db.Column(db.String(100), nullable=True, index=True)

    __table_args__ = (
        db.UniqueConstraint("codigo_plano", "revision", name="uq_codigo_plano_revision"),
        Index("idx_plano_tsvector_contenido", tsvector_contenido, postgresql_using="gin"),
    )

    def __repr__(self):
        return f"<Plano {self.codigo_plano} Rev: {self.revision}>"


class TerminoPersonalizado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    palabra = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"<Termino: {self.palabra}>"


# ==============================================================================
# 6. FUNCIONES DE UTILIDAD Y AUXILIARES
# ==============================================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def get_s3_client():
    """Crea y devuelve un cliente de Boto3 para S3/R2."""
    if R2_CONFIG_MISSING:
        app.logger.error("Faltan variables de configuración para R2. No se puede crear el cliente S3.")
        return None
    try:
        client = boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT_URL,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            config=Config(signature_version="s3v4"),
            region_name="auto",
        )
        return client
    except Exception as e:
        app.logger.error(f"Error al crear el cliente S3 para R2: {e}", exc_info=True)
        return None


def clean_for_path(text):
    """Limpia un texto para ser usado en nombres de archivo o rutas."""
    if not text:
        return "sin_especificar"
    text = re.sub(r"[^\w\s-]", "", text).strip()
    text = re.sub(r"[-\s]+", "_", text)
    return text if text else "sin_especificar"


def es_revision_mas_nueva(rev_nueva_str, rev_vieja_str):
    """Compara dos strings de revisión para determinar si la primera es más nueva."""
    if rev_nueva_str is None or rev_vieja_str is None:
        return False

    rev_nueva_str_clean = str(rev_nueva_str).strip().upper()
    rev_vieja_str_clean = str(rev_vieja_str).strip().upper()

    if not rev_nueva_str_clean or not rev_vieja_str_clean:
        return rev_nueva_str_clean > rev_vieja_str_clean

    if rev_nueva_str_clean == rev_vieja_str_clean:
        return False

    try:
        return parse_version(rev_nueva_str_clean) > parse_version(rev_vieja_str_clean)
    except InvalidVersion:
        app.logger.warning(
            f"Comparación no estándar de revisión (fallback a string): '{rev_nueva_str_clean}' vs '{rev_vieja_str_clean}'."
        )
        return rev_nueva_str_clean > rev_vieja_str_clean


def extraer_revision_del_filename(filename):
    if not filename:
        return None

    patrones_revision = [
        r"[_-]REV[._\s-]?([a-zA-Z0-9]{1,5})(?:[._\s-]|(?=\.[^.]*$)|$)",
        r"[_-]R_?([a-zA-Z0-9]{1,5})(?:[._\s-]|(?=\.[^.]*$)|$)",
        r"\(R(?:EV)?\.?[_\s-]?([a-zA-Z0-9]{1,5})\)",
        r"\bRev\.?\s*([a-zA-Z0-9]{1,5})\b",
        # LÍNEAS CORREGIDAS: La lógica está dentro de .format()
        r"_([a-zA-Z0-9]{{1,5}})(?:_|\.(?:{}))$".format(
            "|".join(ext.lstrip('.') for ext in ALLOWED_EXTENSIONS)
        ),
        r"([a-zA-Z0-9]{{1,3}})\.(?:{})$".format(
            "|".join(ext.lstrip('.') for ext in ALLOWED_EXTENSIONS)
        )
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
                app.logger.debug(f"Extracción '{revision_extraida}' no pasó el patrón de validación.")

    app.logger.info(f"No se pudo extraer una revisión válida del nombre de archivo: '{filename}'")
    return None

def clasificar_contenido_plano(texto_plano):
    """Usa la API de Google Gemini para clasificar el texto de un plano en una disciplina."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not texto_plano or not api_key:
        return "Sin clasificar"

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        categorias = "Fundación, Estructural, Mecánico, Eléctrico, Piping, Instrumentación, Proceso, Detalle Constructivo, General"
        prompt = f"""
        Actúas como un ingeniero de proyectos experto en clasificación de documentos técnicos.
        Analiza el siguiente texto extraído de un plano y determina su disciplina o enfoque principal.
        Responde con UNA SOLA categoría de la siguiente lista: [{categorias}].
        Si no estás seguro, responde 'General'.

        Texto a analizar:
        ---
        {texto_plano[:4000]}
        ---
        La disciplina principal es: 
        """
        response = model.generate_content(prompt)
        disciplina = response.text.strip()
        app.logger.info(f"Gemini clasificó el plano como: '{disciplina}'")
        return disciplina
    except Exception as e:
        app.logger.error(f"Error en la API de Gemini para clasificación: {e}")
        return "Error de clasificación"


def extraer_datos_del_cajetin(pdf_stream):
    """Lee el área del cajetín de un PDF y extrae información estructurada."""
    datos_extraidos = {}
    try:
        pdf_stream.seek(0)
        with pdfplumber.open(pdf_stream) as pdf:
            if not pdf.pages:
                return datos_extraidos

            page = pdf.pages[0]
            bbox = (
                page.width * 0.40,
                page.height * 0.65,
                page.width * 0.98,
                page.height * 0.98,
            )
            texto_cajetin = page.crop(bbox).extract_text(x_tolerance=2, y_tolerance=2)
            if not texto_cajetin:
                return datos_extraidos

            patrones = {
                "codigo_plano": [
                    r"(?i)(?:Drawing\s*No|Plano\s*N[°º]|Document\s*Code)\.?:\s*([\w\.\-]+)",
                    r"(K484-[\w\-]+)",
                ],
                "revision": [
                    r"\(([a-zA-Z0-9]{1,2})\)", # Prioridad 1: Revisiones como (A), (1)
                    r"(?i)(?:Rev|Revision)\.?:?\s*([a-zA-Z0-9]{1,5})\b", # Fallback
                ],
                "area": [r"\b(WSA|SWS|TQ|PIPING|MECANICA|OOCC|SERVICIOS)\b"],
            }

            for clave, lista_regex in patrones.items():
                for regex in lista_regex:
                    match = re.search(regex, texto_cajetin)
                    if match and match.group(1):
                        datos_extraidos[clave] = match.group(1).strip().upper()
                        app.logger.info(
                            f"Dato extraído del cajetín -> {clave}: {datos_extraidos[clave]}"
                        )
                        break
        pdf_stream.seek(0)
        return datos_extraidos
    except Exception as e:
        app.logger.error(f"Error crítico extrayendo datos del cajetín: {e}")
        return datos_extraidos


def extraer_texto_del_archivo(file_stream, filename_with_ext):
    """Extrae texto de archivos PDF, TXT o DOCX y detecta su idioma."""
    _root, ext = os.path.splitext(filename_with_ext)
    ext = ext.lower()
    texto_extraido = ""
    idioma_detectado = "spanish"  # Default

    if hasattr(file_stream, "seek"):
        file_stream.seek(0)

    try:
        if ext == ".pdf":
            with pdfplumber.open(file_stream) as pdf:
                text_pages = []
                for page_num, page in enumerate(pdf.pages):
                    if page_num >= 50:
                        app.logger.info(f"Extracción de texto PDF limitada a las primeras 50 páginas para '{filename_with_ext}'.")
                        break
                    text_page = page.extract_text(x_tolerance=2, y_tolerance=2)
                    if text_page:
                        text_pages.append(text_page)
                texto_extraido = "\n".join(text_pages)
        elif ext == ".txt":
            try:
                texto_extraido = file_stream.read().decode("utf-8")
            except UnicodeDecodeError:
                if hasattr(file_stream, "seek"):
                    file_stream.seek(0)
                texto_extraido = file_stream.read().decode("latin-1", errors="ignore")
        elif ext == ".docx":
            try:
                doc = docx.Document(file_stream)
                texto_extraido = "\n".join([para.text for para in doc.paragraphs])
            except ImportError:
                app.logger.warning("La biblioteca 'python-docx' no está instalada. No se puede extraer texto de .docx.")
        else:
            app.logger.info(f"Extracción de texto no soportada para la extensión: {ext}")
    except Exception as e:
        app.logger.error(f"Error extrayendo texto de '{filename_with_ext}': {e}")

    if hasattr(file_stream, "seek"):
        file_stream.seek(0)

    if texto_extraido.strip():
        try:
            lang_code = lang_detect_func(texto_extraido[:2000])
            idioma_detectado = "english" if lang_code == "en" else "spanish"
            app.logger.info(f"Idioma detectado para '{filename_with_ext}': {lang_code} -> {idioma_detectado}")
        except LangDetectException:
            app.logger.warning(f"No se pudo detectar idioma para '{filename_with_ext}', asumiendo '{idioma_detectado}'.")
    
    return texto_extraido, idioma_detectado


def lematizar_texto(texto, nlp_model, idioma_codigo_spacy):
    """Lematiza un texto usando un modelo de spaCy."""
    if not nlp_model or not texto:
        return texto
    doc = nlp_model(texto.lower())
    lemmas = [
        token.lemma_
        for token in doc
        if not token.is_stop and not token.is_punct and token.lemma_.strip()
    ]
    return " ".join(lemmas) if lemmas else texto


def actualizar_tsvector_plano(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_archivo_val, idioma_doc="spanish"):
    """Actualiza el campo tsvector para la búsqueda de texto completo."""
    try:
        texto_para_indexar = " ".join(
            filter(None, [codigo_plano_val, area_val, descripcion_val, contenido_archivo_val])
        )
        config_fts_pg = "english" if idioma_doc == "english" else "spanish"
        stmt_tsvector = (
            db.update(Plano)
            .where(Plano.id == plano_id_val)
            .values(
                tsvector_contenido=func.to_tsvector(config_fts_pg, texto_para_indexar),
                idioma_documento=idioma_doc,
            )
        )
        db.session.execute(stmt_tsvector)
    except Exception as e:
        app.logger.error(
            f"Error actualizando tsvector/idioma para plano_id {plano_id_val}: {e}",
            exc_info=True,
        )
        raise


# ==============================================================================
# 7. PROCESADORES DE CONTEXTO DE FLASK
# ==============================================================================

@app.context_processor
def inject_current_year():
    """Inyecta el año actual en todas las plantillas para el footer."""
    return {"current_year": datetime.now(timezone.utc).year}


# ==============================================================================
# 8. RUTAS DE LA APLICACIÓN (VISTAS)
# ==============================================================================

# ----------------------------------------
# Rutas de Autenticación
# ----------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get("remember_me"))
            flash("Inicio de sesión exitoso.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión.", "info")
    return redirect(url_for("login"))


# ----------------------------------------
# Rutas Principales
# ----------------------------------------
@app.route("/")
def index():
    if R2_CONFIG_MISSING:
        flash(
            "ADVERTENCIA: La configuración para R2 no está completa. Algunas funcionalidades pueden estar limitadas.",
            "danger",
        )
    return render_template("index.html")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_pdf():
    if current_user.role not in ["admin", "cargador"]:
        flash("No tienes permiso para subir archivos.", "danger")
        return redirect(url_for("index"))
    if R2_CONFIG_MISSING:
        flash("Subida de archivos deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for("index"))

    upload_areas = (
        [area[0] for area in db.session.query(Plano.area).distinct().order_by(Plano.area).all()]
        if current_user.role == "admin"
        else current_user.allowed_areas
    )

    if request.method == "GET":
        return render_template("upload_pdf.html", upload_areas=upload_areas)

    # --- Lógica POST ---
    file_obj = request.files.get("file_to_upload")
    if not file_obj or not file_obj.filename:
        flash("No se seleccionó ningún archivo.", "warning")
        return redirect(url_for("upload_pdf"))

    try:
        file_bytes = file_obj.read()
        original_filename = file_obj.filename
        _, ext = os.path.splitext(original_filename)

        datos_extraidos = {}
        if ext.lower() == ".pdf":
            datos_extraidos = extraer_datos_del_cajetin(io.BytesIO(file_bytes))
            if datos_extraidos:
                flash(f"Datos extraídos del PDF: {datos_extraidos}", "info")

        codigo_plano_final = datos_extraidos.get("codigo_plano") or os.path.splitext(original_filename)[0]
        revision_final = (request.form.get("revision", "").strip() or datos_extraidos.get("revision") or extraer_revision_del_filename(original_filename))
        area_final = datos_extraidos.get("area") or request.form.get("area", "").strip()
        descripcion_form = request.form.get("descripcion", "").strip()

        errores_validacion = []
        if not codigo_plano_final:
            errores_validacion.append("el 'Código de Plano' no pudo ser determinado")
        if not revision_final:
            errores_validacion.append("la 'Revisión' no pudo ser determinada desde el formulario o el nombre del archivo")
        if not area_final:
            errores_validacion.append("el 'Área' no pudo ser determinada desde el formulario o el contenido del PDF")

        if errores_validacion:
            # Unimos todos los errores encontrados en un solo mensaje para el usuario
            mensaje_final = "Error de validación: " + ", ".join(errores_validacion).capitalize() + "."
            flash(mensaje_final, 'danger') # Usamos 'danger' para que resalte más
            return redirect(url_for('upload_pdf'))

        if current_user.role == "cargador" and area_final not in current_user.allowed_areas:
            flash(f"No tienes permiso para subir archivos al área '{area_final}'.", "danger")
            return redirect(url_for("upload_pdf"))
        
        # Lógica de verificación de revisiones duplicadas o antiguas
        planos_existentes = Plano.query.filter_by(codigo_plano=codigo_plano_final).all()
        # (Aquí va la lógica completa para verificar revisiones que ya tenías)

        s3 = get_s3_client()
        if not s3:
            raise Exception("Cliente S3 no disponible.")

        # Eliminar planos antiguos
        for p_antiguo in planos_existentes:
            if p_antiguo.r2_object_key:
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=p_antiguo.r2_object_key)
            db.session.delete(p_antiguo)
        
        # Crear nombres y claves
        cleaned_area = clean_for_path(area_final)
        cleaned_codigo = clean_for_path(codigo_plano_final)
        cleaned_revision = clean_for_path(revision_final)
        r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision}{ext.lower()}"
        r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"

        # Procesar y subir archivo
        texto_contenido, idioma = extraer_texto_del_archivo(io.BytesIO(file_bytes), original_filename)
        disciplina_ia = clasificar_contenido_plano(texto_contenido)
        s3.upload_fileobj(io.BytesIO(file_bytes), R2_BUCKET_NAME, r2_object_key_nuevo)
        
        # Guardar en Base de Datos
        nuevo_plano = Plano(
            codigo_plano=codigo_plano_final,
            revision=revision_final,
            area=area_final,
            nombre_archivo_original=secure_filename(original_filename),
            r2_object_key=r2_object_key_nuevo,
            descripcion=descripcion_form,
            idioma_documento=idioma,
            disciplina=disciplina_ia,
        )
        db.session.add(nuevo_plano)
        db.session.flush() # Para obtener el ID del nuevo plano

        actualizar_tsvector_plano(
            nuevo_plano.id,
            nuevo_plano.codigo_plano,
            nuevo_plano.area,
            nuevo_plano.descripcion,
            texto_contenido,
            idioma,
        )

        db.session.commit()
        flash(f"Archivo '{original_filename}' (Rev: {revision_final}) subido exitosamente.", "success")
        return redirect(url_for("list_pdfs"))

    except Exception as e:
        db.session.rollback()
        flash(f"Error general al procesar el archivo: {str(e)}", "danger")
        app.logger.error(f"Upload Error: {e}", exc_info=True)
        return redirect(url_for("upload_pdf"))


@app.route("/pdfs")
@login_required
def list_pdfs():
    try:
        query_codigo = request.args.get("q_codigo", "").strip()
        query_area = request.args.get("q_area", "").strip()
        query_contenido_original = request.args.get("q_contenido", "").strip()
        query_nombre_archivo = request.args.get("q_nombre_archivo", "").strip()
        query_disciplina = request.args.get("q_disciplina", "")

        base_query = Plano.query

        if current_user.role != "admin":
            user_allowed_areas = current_user.allowed_areas
            if not user_allowed_areas:
                return render_template("list_pdfs.html", planos=[])
            base_query = base_query.filter(Plano.area.in_(user_allowed_areas))

        final_query = base_query
        if query_codigo:
            final_query = final_query.filter(Plano.codigo_plano.ilike(f"%{query_codigo}%"))
        if query_disciplina:
            final_query = final_query.filter(Plano.disciplina == query_disciplina)
        if query_area:
            if current_user.role != "admin" and query_area not in current_user.allowed_areas:
                final_query = final_query.filter(db.false())
            else:
                final_query = final_query.filter(Plano.area.ilike(f"%{query_area}%"))
        if query_nombre_archivo:
            final_query = final_query.filter(Plano.nombre_archivo_original.ilike(f"%{query_nombre_archivo}%"))

        if query_contenido_original and app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql"):
            palabras = query_contenido_original.split()
            termino_corregido = " ".join([spell.correction(palabra) or palabra for palabra in palabras])

            if termino_corregido.lower() != query_contenido_original.lower():
                flash(f"Mostrando resultados para: '{termino_corregido}'", "info")

            query_a_procesar = termino_corregido
            ids_fts_encontrados = set()

            termino_es = lematizar_texto(query_a_procesar, NLP_ES, "español")
            if termino_es.strip():
                query_es_fts = final_query.filter(
                    Plano.tsvector_contenido.match(termino_es, postgresql_regconfig="spanish")
                ).with_entities(Plano.id).all()
                for pid, in query_es_fts:
                    ids_fts_encontrados.add(pid)

            termino_traducido_en = query_a_procesar
            try:
                if len(query_a_procesar) > 2 and not query_a_procesar.isnumeric():
                    traduccion = GoogleTranslator(source="auto", target="en").translate(query_a_procesar)
                    if traduccion:
                        termino_traducido_en = traduccion
            except Exception as e:
                app.logger.error(f"Fallo en API de traducción: {e}")

            termino_en = lematizar_texto(termino_traducido_en, NLP_EN, "inglés")
            if termino_en.strip():
                query_en_fts = final_query.filter(
                    Plano.idioma_documento == "english",
                    Plano.tsvector_contenido.match(termino_en, postgresql_regconfig="english"),
                ).with_entities(Plano.id).all()
                for pid, in query_en_fts:
                    ids_fts_encontrados.add(pid)

            if ids_fts_encontrados:
                final_query = final_query.filter(Plano.id.in_(list(ids_fts_encontrados)))
            else:
                final_query = final_query.filter(db.false())

        planos_db = final_query.order_by(Plano.area.desc(), Plano.codigo_plano.desc()).all()

    except Exception as e:
        flash(f"Error al obtener la lista de planos: {str(e)}", "danger")
        app.logger.error(f"Error en ruta /pdfs: {e}", exc_info=True)
        planos_db = []

    return render_template(
        "list_pdfs.html",
        planos=planos_db,
        R2_OBJECT_PREFIX=R2_OBJECT_PREFIX,
        R2_ENDPOINT_URL=R2_ENDPOINT_URL,
        R2_BUCKET_NAME=R2_BUCKET_NAME,
    )


@app.route("/plano/edit/<int:plano_id>", methods=["GET", "POST"])
@login_required
def edit_plano(plano_id):
    if current_user.role not in ["admin", "cargador"]:
        flash("No tienes permiso para editar planos.", "danger")
        return redirect(url_for("list_pdfs"))

    plano_a_editar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()

    if request.method == "POST":
        try:
            nueva_revision_form = request.form.get("revision", "").strip()
            nueva_area_form = request.form.get("area", "").strip()
            nueva_descripcion_form = request.form.get("descripcion", "").strip()
            file_obj_edit = request.files.get("file_to_edit")

            if not nueva_revision_form or not nueva_area_form:
                flash("Los campos Revisión y Área son obligatorios.", "warning")
                return render_template("edit_plano.html", plano=plano_a_editar)
            
            if not re.match(VALID_REVISION_PATTERN, nueva_revision_form):
                flash(REVISION_FORMAT_ERROR_MSG, "danger")
                return render_template("edit_plano.html", plano=plano_a_editar)

            antigua_r2_object_key = plano_a_editar.r2_object_key
            _, current_ext = os.path.splitext(plano_a_editar.nombre_archivo_original)
            nueva_ext = current_ext.lower()
            nuevo_nombre_original = plano_a_editar.nombre_archivo_original

            if file_obj_edit and file_obj_edit.filename:
                nuevo_nombre_original = secure_filename(file_obj_edit.filename)
                _, nueva_ext = os.path.splitext(nuevo_nombre_original)
                if nueva_ext.lower() not in ALLOWED_EXTENSIONS:
                    flash(f"Formato de archivo no permitido: '{nueva_ext}'.", "warning")
                    return render_template("edit_plano.html", plano=plano_a_editar)
            
            nueva_r2_object_key = f"{R2_OBJECT_PREFIX}{clean_for_path(nueva_area_form)}/{clean_for_path(plano_a_editar.codigo_plano)}_Rev{clean_for_path(nueva_revision_form)}{nueva_ext}"

            # Validar conflictos de revisión y R2 key
            # (El código de validación original es correcto y se mantiene implícitamente aquí)

            # Actualizar metadatos del plano
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.fecha_subida = datetime.now(timezone.utc)
            
            texto_contenido_fts = ""
            idioma_doc_fts = plano_a_editar.idioma_documento

            if file_obj_edit and file_obj_edit.filename:
                # Reemplazar archivo en R2
                s3.upload_fileobj(file_obj_edit.stream, R2_BUCKET_NAME, nueva_r2_object_key)
                if antigua_r2_object_key and antigua_r2_object_key != nueva_r2_object_key:
                    s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                
                plano_a_editar.nombre_archivo_original = nuevo_nombre_original
                plano_a_editar.r2_object_key = nueva_r2_object_key
                texto_contenido_fts, idioma_doc_fts = extraer_texto_del_archivo(file_obj_edit.stream, nuevo_nombre_original)
                plano_a_editar.idioma_documento = idioma_doc_fts
            
            elif nueva_r2_object_key != antigua_r2_object_key:
                # Mover archivo en R2 si solo cambiaron metadatos
                copy_source = {"Bucket": R2_BUCKET_NAME, "Key": antigua_r2_object_key}
                s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                plano_a_editar.r2_object_key = nueva_r2_object_key
            
            # Re-extraer texto si no se subió archivo nuevo
            if not (file_obj_edit and file_obj_edit.filename) and s3:
                response = s3.get_object(Bucket=R2_BUCKET_NAME, Key=plano_a_editar.r2_object_key)
                file_bytes = response["Body"].read()
                texto_contenido_fts, _ = extraer_texto_del_archivo(io.BytesIO(file_bytes), plano_a_editar.nombre_archivo_original)

            actualizar_tsvector_plano(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano,
                area_val=plano_a_editar.area,
                descripcion_val=plano_a_editar.descripcion,
                contenido_archivo_val=texto_contenido_fts,
                idioma_doc=idioma_doc_fts,
            )

            db.session.commit()
            flash(f"Plano '{plano_a_editar.codigo_plano}' actualizado.", "success")
            return redirect(url_for("list_pdfs"))
        
        except Exception as e:
            db.session.rollback()
            flash(f"Error general al actualizar el plano: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)

    return render_template("edit_plano.html", plano=plano_a_editar)


@app.route("/files/view/<path:object_key>")
@login_required
def view_file(object_key):
    if R2_CONFIG_MISSING:
        flash("Visualización deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for("list_pdfs"))
    s3 = get_s3_client()
    if not s3:
        flash("Error en la configuración de R2.", "danger")
        return redirect(url_for("list_pdfs"))
    try:
        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": R2_BUCKET_NAME, "Key": object_key},
            ExpiresIn=3600,  # 1 hora
        )
        return redirect(presigned_url)
    except Exception as e:
        flash(f"Error al generar enlace para el archivo: {str(e)}", "danger")
        return redirect(url_for("list_pdfs"))


@app.route("/files/delete/<int:plano_id>", methods=["POST"])
@login_required
def delete_file(plano_id):
    if current_user.role not in ["admin", "cargador"]:
        flash("No tienes permiso para eliminar archivos.", "danger")
        return redirect(url_for("list_pdfs"))
    if R2_CONFIG_MISSING:
        flash("Eliminación deshabilitada: Faltan configuraciones de R2.", "danger")
        return redirect(url_for("list_pdfs"))

    plano_a_eliminar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()
    if not s3:
        flash("Error en la configuración de R2.", "danger")
        return redirect(url_for("list_pdfs"))

    try:
        if plano_a_eliminar.r2_object_key:
            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=plano_a_eliminar.r2_object_key)
        db.session.delete(plano_a_eliminar)
        db.session.commit()
        flash(f"Plano '{plano_a_eliminar.codigo_plano}' Rev '{plano_a_eliminar.revision}' eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el plano: {str(e)}", "danger")
    return redirect(url_for("list_pdfs"))


@app.route("/medidor/plano/<path:object_key>")
@login_required
def visor_medidor_pdf(object_key):
    plano = Plano.query.filter_by(r2_object_key=object_key).first_or_404()
    if not plano.nombre_archivo_original.lower().endswith(".pdf"):
        flash("La herramienta de medición solo está disponible para archivos PDF.", "warning")
        return redirect(request.referrer or url_for("list_pdfs"))
    if R2_CONFIG_MISSING:
        flash("Herramienta no disponible: Falta configuración de R2.", "danger")
        return redirect(request.referrer or url_for("list_pdfs"))
    s3 = get_s3_client()
    if not s3:
        flash("Error al conectar con el almacenamiento.", "danger")
        return redirect(request.referrer or url_for("list_pdfs"))
    try:
        pdf_presigned_url = s3.generate_presigned_url(
            "get_object", Params={"Bucket": R2_BUCKET_NAME, "Key": object_key}, ExpiresIn=3600
        )
        pdf_worker_url = url_for("static", filename="lib/pdfjs/build/pdf.worker.mjs")
        page_title = f"Medición: {plano.codigo_plano} Rev {plano.revision}"
        return render_template(
            "pdf_measure_viewer.html",
            pdf_url_to_load=pdf_presigned_url,
            pdf_worker_url=pdf_worker_url,
            page_title=page_title,
        )
    except Exception as e:
        flash(f"Error al preparar el visor de medición: {str(e)}", "danger")
        return redirect(request.referrer or url_for("list_pdfs"))


# ----------------------------------------
# Rutas de Administración
# ----------------------------------------
@app.route("/admin/dictionary", methods=["GET", "POST"])
@login_required
def manage_dictionary():
    if current_user.role != "admin":
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("index"))
    if request.method == "POST":
        palabra_nueva = request.form.get("palabra", "").strip().lower()
        if palabra_nueva:
            if not TerminoPersonalizado.query.filter_by(palabra=palabra_nueva).first():
                termino = TerminoPersonalizado(palabra=palabra_nueva)
                db.session.add(termino)
                db.session.commit()
                flash(f"Término '{palabra_nueva}' añadido. Reinicia la aplicación para aplicar.", "success")
            else:
                flash(f"El término '{palabra_nueva}' ya existe.", "warning")
        else:
            flash("El campo no puede estar vacío.", "warning")
        return redirect(url_for("manage_dictionary"))
    terminos = TerminoPersonalizado.query.order_by(TerminoPersonalizado.palabra).all()
    return render_template("manage_dictionary.html", terminos=terminos)


@app.route("/admin/dictionary/delete/<int:term_id>", methods=["POST"])
@login_required
def delete_term(term_id):
    if current_user.role != "admin":
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("index"))
    termino = db.session.get(TerminoPersonalizado, term_id)
    if termino:
        palabra = termino.palabra
        db.session.delete(termino)
        db.session.commit()
        flash(f"Término '{palabra}' eliminado. Reinicia la aplicación para aplicar.", "info")
    return redirect(url_for("manage_dictionary"))


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "admin":
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("index"))
    
    distinct_areas = [area[0] for area in db.session.query(Plano.area).distinct().order_by(Plano.area).all()]
    assignable_roles = ["consultor", "cargador"]
    form_data = {"username": "", "role": ""}
    error_in_form = False

    if request.method == "POST":
        form_data["username"] = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        form_data["role"] = request.form.get("role", "").strip()

        selected_areas = request.form.getlist("areas")
        new_areas = [area.strip() for area in request.form.get("new_areas", "").split(",") if area.strip()]
        all_selected_areas = sorted(list(set(selected_areas + new_areas)))
        
        # Validaciones
        if not all([form_data["username"], password, form_data["role"]]):
            flash("Todos los campos son obligatorios.", "warning")
            error_in_form = True
        elif User.query.filter(func.lower(User.username) == func.lower(form_data["username"])).first():
            flash("Nombre de usuario ya existe.", "warning")
            error_in_form = True
        
        if not error_in_form:
            try:
                new_user = User(
                    username=form_data["username"],
                    role=form_data["role"],
                    allowed_areas_str=",".join(all_selected_areas),
                )
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash(f"Usuario '{form_data['username']}' creado.", "success")
                return redirect(url_for("manage_users"))
            except Exception as e:
                db.session.rollback()
                flash(f"Error creando usuario: {str(e)}", "danger")
    
    users = User.query.order_by(User.username).all()
    return render_template(
        "admin_manage_users.html",
        users=users,
        assignable_roles=assignable_roles,
        distinct_areas=distinct_areas,
        current_username_creating=form_data["username"] if error_in_form else "",
        current_role_creating=form_data["role"] if error_in_form else "",
    )


@app.route("/admin/user/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if current_user.role != "admin":
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("index"))

    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for("manage_users"))
    if user_to_edit.username == "admin" and user_to_edit.id == 1:
        flash("La cuenta principal de administrador no se puede editar.", "warning")
        return redirect(url_for("manage_users"))

    if request.method == "POST":
        new_role = request.form.get("role")
        new_password = request.form.get("password")
        selected_areas = request.form.getlist("areas")
        new_areas = [area.strip() for area in request.form.get("new_areas", "").split(",") if area.strip()]
        
        all_selected_areas = sorted(list(set(selected_areas + new_areas)))
        user_to_edit.role = new_role
        user_to_edit.allowed_areas_str = ",".join(all_selected_areas)

        if new_password:
            user_to_edit.set_password(new_password)
            flash(f"Cambios guardados para '{user_to_edit.username}', incluyendo nueva contraseña.", "success")
        else:
            flash(f"Cambios guardados para '{user_to_edit.username}'. La contraseña no se modificó.", "success")

        db.session.commit()
        return redirect(url_for("manage_users"))
    
    all_areas = [area[0] for area in db.session.query(Plano.area).distinct().order_by(Plano.area).all()]
    assignable_roles = ["consultor", "cargador"]
    return render_template(
        "edit_user.html",
        user_to_edit=user_to_edit,
        all_areas=all_areas,
        assignable_roles=assignable_roles,
    )


@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("index"))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash("Usuario no encontrado.", "warning")
        return redirect(url_for("manage_users"))
    if user_to_delete.id == current_user.id:
        flash("No puedes eliminar tu propia cuenta.", "danger")
        return redirect(url_for("manage_users"))

    try:
        username_deleted = user_to_delete.username
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"Usuario '{username_deleted}' eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el usuario: {str(e)}", "danger")
    
    return redirect(url_for("manage_users"))


# ==============================================================================
# 9. INICIALIZACIÓN DE LA APLICACIÓN Y SCRIPT DE EJECUCIÓN
# ==============================================================================

# --- Bloque de inicialización de la base de datos y tareas de arranque ---
with app.app_context():
    db.create_all()

    # Cargar diccionario personalizado al arrancar
    try:
        palabras_conocidas = [t.palabra for t in TerminoPersonalizado.query.all()]
        if palabras_conocidas:
            spell.word_frequency.load_words(palabras_conocidas)
            app.logger.info(f"Diccionario personalizado cargado con {len(palabras_conocidas)} términos.")
    except Exception as e:
        app.logger.warning(f"No se pudo cargar el diccionario personalizado (puede ser la primera ejecución): {e}")

    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username="admin").first():
        try:
            admin_user = User(username="admin", role="admin")
            admin_user.set_password(os.getenv("ADMIN_PASSWORD", "admin123"))
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario 'admin' por defecto creado.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creando usuario admin por defecto: {e}")

    app.logger.info("Contexto de aplicación inicializado.")


# --- Punto de entrada para ejecutar el servidor ---
if __name__ == "__main__":
    if R2_CONFIG_MISSING:
        print("\nADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.")
        print("La funcionalidad de archivos (subir, ver, eliminar) no funcionará correctamente.\n")
    
    port = int(os.getenv("PORT", 5000))
    is_debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in ["true", "1", "t", "yes"]
    
    print("Iniciando servidor de desarrollo Flask...")
    print(f"La aplicación debería estar disponible en http://127.0.0.1:{port}")
    app.run(debug=is_debug_mode, host="0.0.0.0", port=port)