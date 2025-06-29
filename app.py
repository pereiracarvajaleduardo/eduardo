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
import json
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# ----------------------------------------
# Módulos de terceros (Third-party)
# ----------------------------------------
import tempfile
import shutil
import boto3
import docx
import spacy
import pdfplumber
import pytz
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
from pdf2image import convert_from_bytes
from PIL import Image

# ----------------------------------------
# Módulos de Flask y extensiones
# ----------------------------------------
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, func, or_, text, ForeignKey
from sqlalchemy.dialects.postgresql import TSVECTOR, JSONB, ARRAY
from sqlalchemy.orm import relationship
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
    ".pdf", ".txt", ".docx", ".xlsx", ".dwg",
    ".dxf", ".jpg", ".jpeg", ".png",
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
    allowed_areas_str = db.Column(db.String(500), nullable=True)

    @property
    def allowed_areas(self):
        if not self.allowed_areas_str:
            return []
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
    sub_disciplina = db.Column(db.String(255), nullable=True)
    palabras_clave_ia = db.Column(db.Text, nullable=True)

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

class HistorialPreguntas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pregunta = db.Column(db.Text, nullable=False, index=True)
    pregunta_vector = db.Column(ARRAY(db.Float), nullable=True)
    respuesta = db.Column(db.Text, nullable=False)
    fuentes = db.Column(JSONB)
    fecha_creacion = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    contador_uso = db.Column(db.Integer, default=1)

    # Para un rendimiento óptimo en la búsqueda de similitud, se recomienda pgvector en PostgreSQL.
    # Si tienes la extensión `vector` instalada, descomenta estas líneas.
    # __table_args__ = (
    #     Index('idx_historial_pregunta_vector', 'pregunta_vector', postgresql_using='ivfflat', postgresql_ops={'pregunta_vector': 'vector_cosine_ops'}),
    # )

    def __repr__(self):
        return f"<PreguntaCacheada ID: {self.id}>"

class HechoPlano(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plano_id = db.Column(db.Integer, ForeignKey('plano.id'), nullable=False, index=True)
    hecho_texto = db.Column(db.Text, nullable=False)
    ia_metadata = db.Column(JSONB) # <-- NOMBRE CAMBIADO
    fecha_creacion = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    plano = relationship('Plano', backref=db.backref('hechos', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<Hecho ID: {self.id} para Plano ID: {self.plano_id}>"

class FeedbackRespuesta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    historial_id = db.Column(db.Integer, ForeignKey('historial_preguntas.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    es_positivo = db.Column(db.Boolean, nullable=False)
    comentario = db.Column(db.Text, nullable=True)
    fecha_creacion = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    historial = relationship('HistorialPreguntas', backref=db.backref('feedbacks', lazy=True, cascade="all, delete-orphan"))
    user = relationship('User')

    def __repr__(self):
        return f"<Feedback {'Positivo' if self.es_positivo else 'Negativo'} para Historial ID: {self.historial_id}>"


#=================================================
# FUNCIONES DE IA
#=================================================
def generar_embedding(texto):
    """Genera un vector embedding para un texto dado usando la API de Gemini."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not texto or not api_key:
        return None
    try:
        result = genai.embed_content(
            model="models/embedding-001",
            content=texto,
            task_type="RETRIEVAL_QUERY"
        )
        return result['embedding']
    except Exception as e:
        app.logger.error(f"Error generando embedding: {e}")
        return None

def extraer_hechos_con_ia(texto_plano):
    """Analiza un texto de plano y extrae una lista de hechos clave."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not texto_plano or not api_key or len(texto_plano.strip()) < 50:
        return []
    
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = f"""
        Actúas como un documentalista técnico extremadamente meticuloso.
        Analiza el siguiente texto extraído de un plano de ingeniería.
        Tu tarea es extraer una lista de 3 a 7 "hechos" concretos y fundamentales sobre el plano.
        Cada hecho debe ser una afirmación corta y precisa.
        Enfócate en:
        - El propósito principal del plano.
        - Equipos, componentes o TAGs específicos mencionados.
        - Materiales o dimensiones clave.
        - Ubicaciones o áreas específicas descritas.

        Responde únicamente con una lista JSON de strings.
        Ejemplo de respuesta:
        ["El plano detalla la disposición de tuberías en el área de bombas.", "Se especifica el uso de la bomba P-101A.", "El material de la tubería principal es Acero al Carbono A106."]

        Texto a analizar:
        ---
        {texto_plano[:4000]}
        ---
        Lista JSON de hechos:
        """
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().lstrip("```json").rstrip("```")
        hechos = json.loads(cleaned_response)
        return hechos if isinstance(hechos, list) else []
    except Exception as e:
        app.logger.error(f"Error en IA al extraer hechos: {e}")
        return []

def generar_resumen_con_ia(texto_plano, idioma="spanish"):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not texto_plano or not api_key or len(texto_plano.strip()) < 100:
        return "No se pudo generar un resumen automático."

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = f"""
        Actúas como un ingeniero de documentación técnica.
        El siguiente texto fue extraído de un plano de ingeniería.
        Tu tarea es generar una descripción corta y concisa (máximo 3 frases) que resuma el propósito principal del plano.
        Enfócate en los elementos clave, equipos, o áreas mencionadas. No incluyas información del cajetín (revisiones, fechas, etc.).
        El resumen debe estar en **español**.

        Texto a analizar:
        ---
        {texto_plano[:4000]}
        ---
        Resumen en español:
        """
        response = model.generate_content(prompt)
        resumen = response.text.strip().replace("\"", "")
        app.logger.info(f"Gemini generó el siguiente resumen: '{resumen}'")
        return resumen if resumen else "Resumen no generado."
    except Exception as e:
        app.logger.error(f"Error en la API de Gemini para resumen: {e}")
        return "Error al generar resumen."

def extraer_datos_del_cajetin(pdf_stream):
    datos_extraidos = {}
    texto_cajetin = ""
    try:
        pdf_stream.seek(0)
        with pdfplumber.open(pdf_stream) as pdf:
            if not pdf.pages:
                return datos_extraidos
            page = pdf.pages[0]
            bbox = (page.width * 0.40, page.height * 0.65, page.width * 0.98, page.height * 0.98)
            cropped_page = page.crop(bbox)
            texto_cajetin = cropped_page.extract_text(x_tolerance=2, y_tolerance=2) or ""
            datos_extraidos['texto_cajetin_bruto'] = texto_cajetin
            patrones = {
                "codigo_plano": [r"(?i)Doc\.\s*Code\s*&\s*Serial\s*No\.\s*([\w\-]+)", r"(K484-[\w\-]+)"],
                "revision": [r"\(([a-zA-Z0-9]{1,2})\)", r"(?i)(?:Rev|Revision)\.?:?\s*([a-zA-Z0-9]{1,5})\b"],
                "area": [r"\b(WSA|SWS|TQ|PIPING|MECANICA|OOCC|SERVICIOS)\b"],
            }
            for clave, lista_regex in patrones.items():
                for regex in lista_regex:
                    match = re.search(regex, texto_cajetin, re.IGNORECASE)
                    if match and match.group(1):
                        datos_extraidos[clave] = match.group(1).strip().upper()
                        break
            campos_faltantes = [k for k in patrones.keys() if k not in datos_extraidos]
            if campos_faltantes and texto_cajetin.strip() and os.getenv("GOOGLE_API_KEY"):
                app.logger.info(f"Regex no encontró: {campos_faltantes}. Intentando con IA...")
                try:
                    model = genai.GenerativeModel("gemini-1.5-flash")
                    prompt_ia = f"""
                    Analiza el siguiente texto de un cajetín de plano técnico y extrae los siguientes campos: {', '.join(campos_faltantes)}.
                    Responde únicamente con un objeto JSON con las claves solicitadas. Si no encuentras un valor, omite la clave.
                    Ejemplo de respuesta: {{"codigo_plano": "K484-M-DWG-001", "revision": "A"}}
                    Texto del cajetín:
                    ---
                    {texto_cajetin}
                    ---
                    JSON extraído:
                    """
                    response = model.generate_content(prompt_ia)
                    json_text = response.text.strip().lstrip("```json").rstrip("```")
                    datos_ia = json.loads(json_text)
                    app.logger.info(f"IA extrajo del cajetín: {datos_ia}")
                    for clave, valor in datos_ia.items():
                        if clave in campos_faltantes:
                            datos_extraidos[clave] = str(valor).strip().upper()
                except Exception as e_ia:
                    app.logger.error(f"Error en el fallback de IA para el cajetín: {e_ia}")
    except Exception as e:
        app.logger.error(f"Error crítico extrayendo datos del cajetín: {e}")
    finally:
        pdf_stream.seek(0)
    return datos_extraidos

def analizar_contenido_con_ia(texto_plano):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not texto_plano or not api_key:
        return None
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        categorias = "Mecánico, Eléctrico, Piping, Instrumentación, Civil, Estructural, Arquitectura, Proceso, General"
        prompt = f"""
        Actúas como un ingeniero de proyectos experto en clasificación de documentos técnicos.
        Analiza el siguiente texto extraído de un plano y devuelve tu análisis en un formato JSON estricto.
        El objeto JSON debe tener las siguientes claves:
        1. "disciplina": UNA SOLA categoría de la siguiente lista: [{categorias}].
        2. "sub_disciplina": Una categoría más específica que identifiques (ej: "HVAC", "Fundaciones", "Tuberías de alta presión"). Si no estás seguro, pon "N/A".
        3. "palabras_clave": Un array de Python con 3 a 5 palabras o frases cortas clave del texto que justifican tu elección.
        4. "resumen_corto": Un resumen técnico de una sola frase describiendo el propósito principal del plano.
        Texto a analizar:
        ---
        {texto_plano[:4000]}
        ---
        Responde únicamente con el objeto JSON, sin añadir texto adicional antes o después.
        """
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
        analysis_result = json.loads(cleaned_response)
        required_keys = ["disciplina", "sub_disciplina", "palabras_clave", "resumen_corto"]
        if all(key in analysis_result for key in required_keys):
            return analysis_result
        else:
            app.logger.error("La respuesta JSON de la IA no contenía todas las claves requeridas.")
            return None
    except Exception as e:
        app.logger.error(f"Error en la API de Gemini o al procesar JSON: {e}")
        return None

# ==============================================================================
# 6. FUNCIONES DE UTILIDAD Y AUXILIARES
# ==============================================================================

def extraer_codigos_tecnicos(texto):
    patron = r'\b([A-Z0-9]+-[A-Z0-9\-]+|[A-Z]{2,}-\d+|\b[A-Z]+\d+\b)'
    codigos = re.findall(patron, texto.upper())
    return codigos

@app.template_filter('local_time')
def format_datetime_local(utc_dt):
    if not utc_dt:
        return ""
    try:
        local_tz = pytz.timezone('America/Santiago')
        local_dt = utc_dt.astimezone(local_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M')
    except Exception as e:
        app.logger.error(f"Error al convertir la zona horaria: {e}")
        return utc_dt.strftime('%Y-%m-%d %H:%M')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_s3_client():
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
    if not text:
        return "sin_especificar"
    text = re.sub(r"[^\w\s-]", "", text).strip()
    text = re.sub(r"[-\s]+", "_", text)
    return text if text else "sin_especificar"

def es_revision_mas_nueva(rev_nueva_str, rev_vieja_str):
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

def extraer_texto_del_archivo(file_stream, filename_with_ext):
    _root, ext = os.path.splitext(filename_with_ext)
    ext = ext.lower()
    texto_extraido = ""
    idioma_detectado = "spanish"
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
        app.logger.error(f"Error actualizando tsvector/idioma para plano_id {plano_id_val}: {e}", exc_info=True)
        raise

def determinar_area_por_regla(texto_plano):
    if not texto_plano:
        return None
    if "3800" in texto_plano or "3890" in texto_plano:
        app.logger.info("Regla numérica aplicada: Se encontró 3800/3890. Área asignada: wsa")
        return "wsa"
    if "3900" in texto_plano or "3990" in texto_plano:
        app.logger.info("Regla numérica aplicada: Se encontró 3900/3990. Área asignada: sws")
        return "sws"
    return None

def parsear_nombre_de_archivo(filename):
    print(f"--- INICIANDO PARSER DE NOMBRE DE ARCHIVO ---\nFILENAME RECIBIDO: {filename}")
    if not filename:
        print("-> RESULTADO: Error, el nombre de archivo está vacío.")
        return {'codigo': None, 'revision': None}
    try:
        base, _ = os.path.splitext(filename)
        parts = base.split('_')
        print(f"-> Partes divididas por '_': {parts}\n-> Número de partes: {len(parts)}")
        if len(parts) < 2:
            print("-> RESULTADO: No hay suficientes partes para determinar código y revisión.")
            return {'codigo': None, 'revision': None}
        if len(parts) == 2:
            codigo, revision = parts[0], parts[1]
            print("-> LÓGICA APLICADA: Caso para 2 partes (ej: CODIGO_REV.pdf)")
        else:
            revision, codigo = parts[-2], '_'.join(parts[:-2])
            print("-> LÓGICA APLICADA: Caso para 3+ partes (ej: CODIGO_REV_META.pdf)")
        print(f"-> CÓDIGO CANDIDATO: '{codigo}'\n-> REVISIÓN CANDIDATA: '{revision}'")
        if 1 <= len(revision) <= 5 and revision.strip() and revision.isalnum():
            print("-> RESULTADO: La revisión parece válida. Éxito.\n-------------------------------------------------")
            return {'codigo': codigo.strip(), 'revision': revision.strip().upper()}
        else:
            print("-> RESULTADO: La revisión candidata no pasó la validación.\n-------------------------------------------------")
            return {'codigo': None, 'revision': None}
    except Exception as e:
        print(f"-> ERROR INESPERADO: {e}\n-------------------------------------------------")
        return {'codigo': None, 'revision': None}

def elegir_mejor_revision(rev_cajetin, rev_filename):
    r_c = rev_cajetin.strip().upper() if rev_cajetin else None
    r_f = rev_filename.strip().upper() if rev_filename else None
    if not r_c and not r_f: return None
    if not r_c: return r_f
    if not r_f: return r_c
    if r_c == r_f: return r_c
    es_cajetin_numero = r_c.isdigit()
    es_filename_numero = r_f.isdigit()
    if es_cajetin_numero and not es_filename_numero: return r_c
    if es_filename_numero and not es_cajetin_numero: return r_f
    if len(r_c) <= 2 and len(r_f) > 2: return r_c
    if len(r_f) <= 2 and len(r_c) > 2: return r_f
    app.logger.info(f"Ambas revisiones ('{r_c}', '{r_f}') son ambiguas. Se prefiere la del nombre de archivo.")
    return r_f

# ==============================================================================
# 7. PROCESADORES DE CONTEXTO DE FLASK
# ==============================================================================

@app.context_processor
def inject_current_year():
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
    if request.method == "GET":
        if current_user.role not in ["admin", "cargador"]:
            flash("No tienes permiso para ver esta página.", "danger")
            return redirect(url_for("index"))
        return render_template("upload_pdf.html")

    if current_user.role not in ["admin", "cargador"]:
        return jsonify({'status': 'error', 'message': 'No tienes permiso para subir archivos.'}), 403

    file_obj = request.files.get("file_to_upload")
    if not file_obj or not file_obj.filename:
        return jsonify({'status': 'error', 'message': 'No se recibió ningún archivo.'}), 400

    original_filename = secure_filename(file_obj.filename)
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_f:
            temp_file_path = temp_f.name
            shutil.copyfileobj(file_obj.stream, temp_f)
        app.logger.info(f"Archivo '{original_filename}' guardado temporalmente en '{temp_file_path}'")

        with open(temp_file_path, "rb") as f:
            datos_cajetin = extraer_datos_del_cajetin(f)
        
        texto_cajetin_bruto = datos_cajetin.get('texto_cajetin_bruto', '')
        info_filename = parsear_nombre_de_archivo(original_filename)

        codigo_desde_cajetin = datos_cajetin.get('codigo_plano')
        codigo_desde_filename = info_filename.get('codigo')
        PALABRAS_INVALIDAS = ["PAGE", "VIEW", "IEW", "DWG", "DRAWING", "PLANO"]
        if codigo_desde_cajetin and codigo_desde_cajetin.upper() not in PALABRAS_INVALIDAS and len(codigo_desde_cajetin) > 4:
            codigo_plano_final = codigo_desde_cajetin
        else:
            codigo_plano_final = codigo_desde_filename
        
        revision_final = elegir_mejor_revision(datos_cajetin.get('revision'), info_filename.get('revision'))
        
        if not codigo_plano_final:
            codigo_plano_final = os.path.splitext(original_filename)[0]
        if not revision_final:
            msg = "No se pudo determinar una REVISIÓN válida para el archivo."
            return jsonify({'status': 'error', 'message': msg}), 400

        area_detectada = datos_cajetin.get("area") or determinar_area_por_regla(texto_cajetin_bruto)
        area_final = "sin_clasificar"
        mensaje_adicional = ""
        if current_user.role == 'admin':
            area_final = area_detectada or "sin_clasificar"
        elif current_user.role == 'cargador':
            user_allowed_areas = current_user.allowed_areas
            if not user_allowed_areas:
                return jsonify({'status': 'error', 'message': 'Tu cuenta de cargador no tiene áreas asignadas.'}), 403
            if area_detectada and area_detectada.lower() in [a.lower() for a in user_allowed_areas]:
                area_final = area_detectada
            else:
                area_final = user_allowed_areas[0]
                if area_detectada:
                    mensaje_adicional = f"El área detectada fue '{area_detectada}', pero se asignó a tu área permitida: '{area_final}'."
                else:
                    mensaje_adicional = f"Archivo asignado a tu área por defecto: '{area_final}'."
        
        planos_con_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_final).all()
        for p_existente in planos_con_mismo_codigo:
            if p_existente.revision == revision_final:
                return jsonify({'status': 'error', 'message': f"Error: La revisión '{revision_final}' ya existe para este código."}), 409
            if es_revision_mas_nueva(p_existente.revision, revision_final):
                return jsonify({'status': 'error', 'message': f"Error: Ya existe una revisión más nueva ('{p_existente.revision}')."}), 409

        s3 = get_s3_client()
        if not s3:
            return jsonify({'status': 'error', 'message': 'Error de configuración del almacenamiento.'}), 500

        for p_antiguo in planos_con_mismo_codigo:
            if p_antiguo.r2_object_key:
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=p_antiguo.r2_object_key)
            db.session.delete(p_antiguo)
        
        cleaned_area = clean_for_path(area_final)
        r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{original_filename}"

        with open(temp_file_path, "rb") as f:
            s3.upload_fileobj(f, R2_BUCKET_NAME, r2_object_key_nuevo, ExtraArgs={'ContentType': 'application/pdf'})
        app.logger.info(f"Archivo subido a R2 con la clave: {r2_object_key_nuevo}")
        
        with open(temp_file_path, "rb") as f:
            texto_contenido, idioma = extraer_texto_del_archivo(f, original_filename)
        
        # --- NUEVA LÓGICA: EXTRAER HECHOS Y DATOS CON IA ---
        informe_ia = analizar_contenido_con_ia(texto_contenido)
        hechos_extraidos_ia = extraer_hechos_con_ia(texto_contenido)
        
        disciplina_final, sub_disciplina_final, palabras_clave_final, resumen_final = "Sin clasificar", None, None, ""
        if informe_ia:
            disciplina_final = informe_ia.get("disciplina", "Sin clasificar")
            sub_disciplina_final = informe_ia.get("sub_disciplina")
            palabras_clave_final = ", ".join(informe_ia.get("palabras_clave", []))
            resumen_final = informe_ia.get("resumen_corto")

        nuevo_plano = Plano(
            codigo_plano=codigo_plano_final, revision=revision_final, area=area_final,
            nombre_archivo_original=original_filename, r2_object_key=r2_object_key_nuevo,
            idioma_documento=idioma, disciplina=disciplina_final, sub_disciplina=sub_disciplina_final,
            palabras_clave_ia=palabras_clave_final, descripcion=resumen_final
        )
        
        # --- NUEVA LÓGICA: GUARDAR HECHOS EN LA BASE DE CONOCIMIENTO ---
        if hechos_extraidos_ia:
            for hecho_str in hechos_extraidos_ia:
                nuevo_hecho = HechoPlano(
                    hecho_texto=hecho_str, 
                    ia_metadata={"model": "gemini-1.5-flash"}
                )
                nuevo_plano.hechos.append(nuevo_hecho)
            app.logger.info(f"Guardados {len(hechos_extraidos_ia)} hechos para el plano {codigo_plano_final}.")

        db.session.add(nuevo_plano)
        db.session.flush()
        
        actualizar_tsvector_plano(
            nuevo_plano.id, nuevo_plano.codigo_plano, nuevo_plano.area,
            nuevo_plano.descripcion, texto_contenido, idioma
        )
        db.session.commit()
        
        success_message = f"Archivo '{original_filename}' subido y procesado exitosamente."
        if mensaje_adicional:
            success_message += f" {mensaje_adicional}"
        return jsonify({'status': 'success', 'message': success_message}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en subida de archivo: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Ocurrió un error interno en el servidor: {e}'}), 500
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            app.logger.info(f"Archivo temporal '{temp_file_path}' eliminado.")

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
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.fecha_subida = datetime.now(timezone.utc)
            texto_contenido_fts = ""
            idioma_doc_fts = plano_a_editar.idioma_documento
            if file_obj_edit and file_obj_edit.filename:
                s3.upload_fileobj(file_obj_edit.stream, R2_BUCKET_NAME, nueva_r2_object_key)
                if antigua_r2_object_key and antigua_r2_object_key != nueva_r2_object_key:
                    s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                plano_a_editar.nombre_archivo_original = nuevo_nombre_original
                plano_a_editar.r2_object_key = nueva_r2_object_key
                texto_contenido_fts, idioma_doc_fts = extraer_texto_del_archivo(file_obj_edit.stream, nuevo_nombre_original)
                plano_a_editar.idioma_documento = idioma_doc_fts
            elif nueva_r2_object_key != antigua_r2_object_key:
                copy_source = {"Bucket": R2_BUCKET_NAME, "Key": antigua_r2_object_key}
                s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                plano_a_editar.r2_object_key = nueva_r2_object_key
            if not (file_obj_edit and file_obj_edit.filename) and s3:
                response = s3.get_object(Bucket=R2_BUCKET_NAME, Key=plano_a_editar.r2_object_key)
                file_bytes = response["Body"].read()
                texto_contenido_fts, _ = extraer_texto_del_archivo(io.BytesIO(file_bytes), plano_a_editar.nombre_archivo_original)
            actualizar_tsvector_plano(
                plano_id_val=plano_a_editar.id, codigo_plano_val=plano_a_editar.codigo_plano,
                area_val=plano_a_editar.area, descripcion_val=plano_a_editar.descripcion,
                contenido_archivo_val=texto_contenido_fts, idioma_doc=idioma_doc_fts,
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
            ExpiresIn=3600,
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
            pdf_filename=plano.nombre_archivo_original
        )
    except Exception as e:
        flash(f"Error al preparar el visor de medición: {str(e)}", "danger")
        return redirect(request.referrer or url_for("list_pdfs"))

@app.route("/ask", methods=["GET"])
@login_required
def ask_page():
    return render_template("ask.html")

# =================================================================================
# == RUTA /api/ask-gemini CON LÓGICA DE CACHÉ INTELIGENTE Y APRENDIZAJE ==
# =================================================================================
@app.route("/api/ask-gemini", methods=["POST"])
@login_required
def api_ask_gemini():
    pregunta = request.json.get("question", "").strip()
    historial = request.json.get("history", [])

    if not pregunta:
        return jsonify({"error": "No se proporcionó ninguna pregunta."}), 400
    if not os.getenv("GOOGLE_API_KEY"):
        return jsonify({"error": "La función de búsqueda conversacional no está configurada."}), 503

    try:
        pregunta_vector = generar_embedding(pregunta)
        if pregunta_vector:
            # Esta consulta requiere la extensión pgvector en PostgreSQL para el operador <->
            query_similar = text("""
                WITH ranked_questions AS (
                    SELECT 
                        h.id, 
                        h.pregunta, 
                        h.respuesta, 
                        h.fuentes,
                        1 - (h.pregunta_vector <=> :query_vector) AS similitud,
                        COALESCE(SUM(CASE WHEN f.es_positivo THEN 0.05 ELSE -0.05 END), 0) AS feedback_score
                    FROM historial_preguntas h
                    LEFT JOIN feedback_respuesta f ON h.id = f.historial_id
                    WHERE h.pregunta_vector IS NOT NULL
                    GROUP BY h.id
                )
                SELECT id, pregunta, respuesta, fuentes, similitud + feedback_score as puntaje_final
                FROM ranked_questions
                ORDER BY puntaje_final DESC
                LIMIT 1;
            """)
            resultado_similar = db.session.execute(query_similar, {"query_vector": str(pregunta_vector)}).fetchone()

            UMBRAL_SIMILITUD = 0.95
            if resultado_similar and resultado_similar.puntaje_final >= UMBRAL_SIMILITUD:
                fuentes_cacheadas = resultado_similar.fuentes
                user_allowed_areas = current_user.allowed_areas
                es_cache_valido = True

                if current_user.role != 'admin':
                    if not fuentes_cacheadas:
                        es_cache_valido = True
                    else:
                        for fuente in fuentes_cacheadas:
                            if fuente.get("area") not in user_allowed_areas:
                                es_cache_valido = False
                                app.logger.warning(f"Cache Hit PERMISSION DENIED. Usuario {current_user.id} no tiene acceso al área '{fuente.get('area')}' de la fuente cacheada.")
                                break
                
                if es_cache_valido:
                    app.logger.info(f"¡Cache HIT Semántico y Válido! Puntaje: {resultado_similar.puntaje_final:.2f}.")
                    pregunta_cacheada = db.session.get(HistorialPreguntas, resultado_similar.id)
                    pregunta_cacheada.contador_uso += 1
                    db.session.commit()
                    return jsonify({
                        "answer": resultado_similar.respuesta,
                        "sources": resultado_similar.fuentes,
                        "cached": True,
                        "history_id": resultado_similar.id
                    })

    except Exception as e_cache_lookup:
        app.logger.error(f"Error buscando en caché semántico (puede que pgvector no esté instalado): {e_cache_lookup}")

    app.logger.info(f"Cache MISS o inválido por permisos. Procesando nueva pregunta con IA: '{pregunta}'")
    
    try:
        base_query = Plano.query
        if current_user.role != "admin":
            user_allowed_areas = current_user.allowed_areas
            if not user_allowed_areas:
                app.logger.warning(f"Usuario {current_user.id} intentó buscar sin tener áreas asignadas.")
                return jsonify({"answer": "No tienes áreas asignadas para realizar una búsqueda.", "sources": []})
            base_query = base_query.filter(Plano.area.in_(user_allowed_areas))

        codigos_extraidos = extraer_codigos_tecnicos(pregunta)
        texto_natural = re.sub(r'\s*'.join(map(re.escape, codigos_extraidos)), '', pregunta, flags=re.IGNORECASE) if codigos_extraidos else pregunta
        terminos_lematizados = lematizar_texto(texto_natural, NLP_ES, "español").split()
        
        search_conditions = []
        if terminos_lematizados or codigos_extraidos:
            query_parts = []
            if codigos_extraidos: query_parts.append(" & ".join(codigos_extraidos))
            if terminos_lematizados: query_parts.append(" & ".join(terminos_lematizados))
            tsquery_string = " & ".join(filter(None, query_parts))
            if tsquery_string:
                search_conditions.append(Plano.tsvector_contenido.op('@@')(func.to_tsquery('spanish', tsquery_string)))
        if codigos_extraidos:
            for codigo in codigos_extraidos:
                search_conditions.append(or_(Plano.descripcion.ilike(f'%{codigo}%'), Plano.codigo_plano.ilike(f'%{codigo}%')))
        
        if not search_conditions:
            return jsonify({"answer": "Por favor, haz una pregunta más específica.", "sources": []})
        
        planos_relevantes = base_query.filter(or_(*search_conditions)).limit(5).all()
        
        if not planos_relevantes:
            return jsonify({"answer": "No pude encontrar ningún plano que coincida con tu pregunta en tus áreas permitidas.", "sources": []})

        model = genai.GenerativeModel("gemini-1.5-pro")
        prompt_multimodal = []
        
        for turno in historial:
            rol_api = "model" if turno.get("role") == "assistant" else "user"
            prompt_multimodal.append({"role": rol_api, "parts": [turno.get("text")]})
        
        contexto_de_hechos = ""
        for plano in planos_relevantes:
            if plano.hechos:
                contexto_de_hechos += f"\nHechos conocidos sobre el plano '{plano.codigo_plano}' Rev '{plano.revision}':\n"
                for hecho in plano.hechos:
                    contexto_de_hechos += f"- {hecho.hecho_texto}\n"

        prompt_multimodal.append({
            "role": "user",
            "parts": [
                f"""
                Eres un ingeniero experto leyendo planos técnicos. Tu tarea es responder la pregunta del usuario basándote en un conjunto de IMÁGENES de planos que te proporciono y en un CONTEXTO de hechos ya conocidos.
                Analiza todas las fuentes para formular tu respuesta. Si la pregunta implica comparar o unir información de varios planos, hazlo.
                Sé extremadamente preciso. Si te preguntan por medidas, cotas o diámetros, busca los números exactos en la imagen.

                CONTEXTO (Hechos ya extraídos de estos planos):
                ---
                {contexto_de_hechos if contexto_de_hechos else "No hay hechos pre-analizados para estos planos."}
                ---
                
                Si no puedes encontrar la respuesta en las imágenes ni en el contexto, indícalo claramente.
                PREGUNTA ACTUAL DEL USUARIO: "{pregunta}"
                """
            ]
        })

        s3 = get_s3_client()
        if not s3:
            return jsonify({"error": "Error de configuración del servidor: El almacenamiento no está disponible."}), 503

        documentos_procesados_ok = False
        app.logger.info(f"Se encontraron {len(planos_relevantes)} planos para el usuario {current_user.id}. Analizando visualmente los primeros 3.")
        
        for plano in planos_relevantes[:3]:
            try:
                response = s3.get_object(Bucket=R2_BUCKET_NAME, Key=plano.r2_object_key)
                pdf_bytes = response["Body"].read()
                
                ruta_poppler = os.getenv("POPPLER_PATH_LOCAL") or "/usr/bin"
                
                imagenes_pdf = convert_from_bytes(
                    pdf_bytes, 
                    poppler_path=ruta_poppler, 
                    first_page=1, 
                    last_page=1
                )
                
                if imagenes_pdf:
                    prompt_multimodal[-1]["parts"].append(f"\n\n--- INICIO ANÁLISIS VISUAL DE: {plano.nombre_archivo_original} (Rev: {plano.revision}) ---")
                    prompt_multimodal[-1]["parts"].append(imagenes_pdf[0])
                    prompt_multimodal[-1]["parts"].append(f"--- FIN ANÁLISIS VISUAL DE: {plano.nombre_archivo_original} ---")
                    documentos_procesados_ok = True
            except Exception as e_proc:
                app.logger.error(f"Error procesando el plano {plano.codigo_plano} para análisis visual: {e_proc}")

        if not documentos_procesados_ok:
            app.logger.error("No se pudo procesar ningún documento fuente para el análisis visual.")
            return jsonify({"error": "No se pudieron procesar los planos fuente."}), 500

        chat_session = model.start_chat(history=prompt_multimodal[:-1])
        response = chat_session.send_message(prompt_multimodal[-1])
        respuesta_ia = response.text.strip()
        
        fuentes_ia = [{
            "codigo": p.codigo_plano, "revision": p.revision,
            "descripcion": p.descripcion, "url": url_for('view_file', object_key=p.r2_object_key),
            "area": p.area
        } for p in planos_relevantes]

        history_id = None
        try:
            vector_para_guardar = pregunta_vector if 'pregunta_vector' in locals() and pregunta_vector else generar_embedding(pregunta)
            
            nueva_pregunta_cacheada = HistorialPreguntas(
                pregunta=pregunta,
                pregunta_vector=vector_para_guardar,
                respuesta=respuesta_ia,
                fuentes=fuentes_ia
            )
            db.session.add(nueva_pregunta_cacheada)
            db.session.commit()
            history_id = nueva_pregunta_cacheada.id
            app.logger.info(f"Nueva respuesta (ID: {history_id}) y su vector guardados en caché para: '{pregunta}'")
        except Exception as e_cache_save:
            app.logger.error(f"Error al guardar en el caché: {e_cache_save}")
            db.session.rollback()

        return jsonify({
            "answer": respuesta_ia,
            "sources": fuentes_ia,
            "cached": False,
            "history_id": history_id
        })

    except Exception as e:
        app.logger.error(f"Error en API de búsqueda conversacional: {e}", exc_info=True)
        return jsonify({"error": "Ocurrió un error inesperado al procesar tu pregunta."}), 500


# ----------------------------------------
# Ruta para el Feedback de la IA
# ----------------------------------------
@app.route("/api/feedback", methods=["POST"])
@login_required
def api_feedback():
    data = request.json
    historial_id = data.get("history_id")
    es_positivo = data.get("is_positive")
    comentario = data.get("comment", "")

    if historial_id is None or es_positivo is None:
        return jsonify({"status": "error", "message": "Faltan datos (history_id, is_positive)"}), 400
    
    # Evitar feedback duplicado del mismo usuario para la misma pregunta
    feedback_existente = FeedbackRespuesta.query.filter_by(
        historial_id=historial_id, 
        user_id=current_user.id
    ).first()

    if feedback_existente:
        # Actualizar feedback existente
        feedback_existente.es_positivo = es_positivo
        feedback_existente.comentario = comentario
        feedback_existente.fecha_creacion = datetime.now(timezone.utc)
        message = "Feedback actualizado."
    else:
        # Crear nuevo feedback
        nuevo_feedback = FeedbackRespuesta(
            historial_id=historial_id,
            user_id=current_user.id,
            es_positivo=es_positivo,
            comentario=comentario
        )
        db.session.add(nuevo_feedback)
        message = "Feedback guardado."
    
    try:
        db.session.commit()
        app.logger.info(f"Feedback {'positivo' if es_positivo else 'negativo'} guardado por usuario {current_user.id} para historial {historial_id}.")
        return jsonify({"status": "success", "message": message})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al guardar feedback: {e}")
        return jsonify({"status": "error", "message": "No se pudo guardar el feedback."}), 500


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

with app.app_context():
    db.create_all()
    try:
        palabras_conocidas = [t.palabra for t in TerminoPersonalizado.query.all()]
        if palabras_conocidas:
            spell.word_frequency.load_words(palabras_conocidas)
            app.logger.info(f"Diccionario personalizado cargado con {len(palabras_conocidas)} términos.")
    except Exception as e:
        app.logger.warning(f"No se pudo cargar el diccionario personalizado (puede ser la primera ejecución): {e}")

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
    
    app.logger.info("Contexto de aplicación inicializado y tablas creadas.")

if __name__ == "__main__":
    if R2_CONFIG_MISSING:
        print("\nADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.")
        print("La funcionalidad de archivos (subir, ver, eliminar) no funcionará correctamente.\n")
    
    port = int(os.getenv("PORT", 5000))
    is_debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in ["true", "1", "t", "yes"]
    
    print("Iniciando servidor de desarrollo Flask...")
    print(f"La aplicación debería estar disponible en http://127.0.0.1:{port}")
    app.run(debug=is_debug_mode, host="0.0.0.0", port=port)