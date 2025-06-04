# === clave de acceso ===
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
# MODIFICADO: Asegúrate que todos los imports de Flask necesarios estén presentes
from flask import Flask, render_template, request, redirect, url_for, flash # send_from_directory (no usado directamente aquí pero útil para static)
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
from deep_translator import GoogleTranslator # Para la traducción en la búsqueda
import io # Para manejar streams de bytes en la edición

# --- Carga de Entorno y Configuración Inicial ---
load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__) # Flask app se instancia aquí
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
            config=Config(signature_version='s3v4'), region_name='auto' # aws_region -> region_name
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
                    if i < 2 : 
                        texto_para_deteccion += texto_pagina + " "
            
            if texto_para_deteccion.strip():
                try:
                    lang_code = lang_detect_func(texto_para_deteccion[:1000]) 
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
    return "\n".join(texto_completo), idioma_detectado_pdf

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
                    idioma_documento=idioma_doc) 
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
    if R2_CONFIG_MISSING:
        flash("ADVERTENCIA: La configuración para R2 no está completa. Algunas funcionalidades pueden estar limitadas.", "danger")
    return render_template('index.html') # Este es el index.html principal de tu aplicación

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso para subir planos.', 'danger'); return redirect(url_for('index'))
    if R2_CONFIG_MISSING: flash("Subida de archivos deshabilitada: Faltan configuraciones de R2.", "danger"); return redirect(url_for('index'))

    if request.method == 'POST':
        pdf_file = request.files.get('pdf_file')
        codigo_plano_form = request.form.get('codigo_plano', '').strip()
        revision_form = request.form.get('revision', '').strip()
        area_form = request.form.get('area', '').strip()
        descripcion_form = request.form.get('descripcion', '').strip()

        if not pdf_file or not pdf_file.filename: flash('No se seleccionó ningún archivo.', 'warning'); return redirect(request.url)
        if not codigo_plano_form or not revision_form: flash('Los campos Código de Plano y Revisión son obligatorios.', 'warning'); return redirect(request.url)
        if not pdf_file.filename.lower().endswith('.pdf'): flash('Formato de archivo no válido. Solo se permiten archivos PDF.', 'warning'); return redirect(request.url)
        
        area_final_determinada = None
        es_mr = codigo_plano_form.upper().startswith("K484-0000-0000-MR-")
        if es_mr:
            if area_form: area_final_determinada = area_form
            else:
                try:
                    if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                    area_extraida = extraer_area_del_pdf(pdf_file.stream)
                    area_final_determinada = area_extraida if area_extraida else "Area_MR_Pendiente"
                    flash(f"Área del plano MR determinada como: '{area_final_determinada}'.", "info" if area_extraida else "warning")
                except Exception as e_area:
                    area_final_determinada = "Area_MR_Error"; flash("Error extrayendo el área del plano MR.", "warning")
                    app.logger.error(f"Error extrayendo área para plano MR: {e_area}", exc_info=True)
        else: 
            if area_form: area_final_determinada = area_form
            else: flash('El campo "Área" es obligatorio para planos no-MR.', 'warning'); return redirect(request.url)
        if area_final_determinada is None: flash('Error crítico: Área no determinada para el plano.', 'danger'); return redirect(request.url)

        original_filename_secure = secure_filename(pdf_file.filename)
        cleaned_area = clean_for_path(area_final_determinada); cleaned_codigo = clean_for_path(codigo_plano_form)
        cleaned_revision = clean_for_path(revision_form)
        r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision}.pdf"; r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"
        
        s3 = get_s3_client()
        if not s3: flash("Error en la configuración de R2. No se puede subir el archivo.", "danger"); return redirect(request.url)

        try:
            planos_existentes_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_form).all()
            plano_para_actualizar_o_crear = None
            
            r2_object_keys_a_eliminar = []
            db_entries_a_eliminar = []

            if not planos_existentes_mismo_codigo:
                app.logger.info(f"Creando nuevo plano: {codigo_plano_form} Rev {revision_form}")
                plano_para_actualizar_o_crear = Plano(
                    codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                    nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                    descripcion=descripcion_form
                )
                db.session.add(plano_para_actualizar_o_crear)
            else: 
                revision_actual_mas_alta_db_str = None
                plano_con_revision_ingresada = None
                for p_existente in planos_existentes_mismo_codigo:
                    if p_existente.revision == revision_form:
                        plano_con_revision_ingresada = p_existente
                    if revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(p_existente.revision, revision_actual_mas_alta_db_str):
                        revision_actual_mas_alta_db_str = p_existente.revision
                
                if plano_con_revision_ingresada: 
                    app.logger.info(f"Actualizando plano existente (misma revisión): {codigo_plano_form} Rev {revision_form}")
                    plano_para_actualizar_o_crear = plano_con_revision_ingresada
                    if plano_para_actualizar_o_crear.r2_object_key and plano_para_actualizar_o_crear.r2_object_key != r2_object_key_nuevo:
                        r2_object_keys_a_eliminar.append(plano_para_actualizar_o_crear.r2_object_key)
                elif revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(revision_form, revision_actual_mas_alta_db_str): 
                    app.logger.info(f"Nueva revisión '{revision_form}' es la más alta para el código {codigo_plano_form}. Marcando revisiones antiguas para eliminación.")
                    for p_antiguo in planos_existentes_mismo_codigo:
                        if p_antiguo.r2_object_key:
                            r2_object_keys_a_eliminar.append(p_antiguo.r2_object_key)
                        db_entries_a_eliminar.append(p_antiguo)
                    plano_para_actualizar_o_crear = Plano(
                        codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                        nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                        descripcion=descripcion_form
                    )
                    db.session.add(plano_para_actualizar_o_crear)
                else: 
                    flash(f"La revisión '{revision_form}' no es más reciente que la existente ('{revision_actual_mas_alta_db_str}') para el plano {codigo_plano_form}. No se procesó.", "warning")
                    return redirect(request.url)

            if not plano_para_actualizar_o_crear:
                raise Exception("Error determinando el plano a crear o actualizar en la lógica de subida.")

            plano_para_actualizar_o_crear.area = area_final_determinada
            plano_para_actualizar_o_crear.r2_object_key = r2_object_key_nuevo
            plano_para_actualizar_o_crear.nombre_archivo_original = original_filename_secure
            plano_para_actualizar_o_crear.descripcion = descripcion_form
            plano_para_actualizar_o_crear.fecha_subida = datetime.now(timezone.utc)
            
            texto_completo_pdf, idioma_doc_detectado = "", "spanish"
            try:
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                texto_completo_pdf, idioma_doc_detectado = extraer_texto_completo_pdf(pdf_file.stream)
            except Exception as e_extr_texto:
                app.logger.error(f"Fallo al extraer texto/idioma del PDF durante la subida: {e_extr_texto}", exc_info=True)
                flash("ADVERTENCIA: Hubo un problema al leer el contenido del PDF. La búsqueda por contenido podría no funcionar para este archivo.", "warning")
            
            plano_para_actualizar_o_crear.idioma_documento = idioma_doc_detectado

            try:
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                s3.upload_fileobj(pdf_file.stream, R2_BUCKET_NAME, r2_object_key_nuevo)
                app.logger.info(f"Archivo '{r2_object_key_nuevo}' subido a R2 exitosamente.")
            except ClientError as e_s3:
                db.session.rollback()
                flash(f"Error de conexión al subir el archivo a R2: {e_s3.response.get('Error', {}).get('Message', 'Error R2 desconocido')}", "danger")
                return redirect(request.url)
            
            if plano_para_actualizar_o_crear not in db.session and not db.session.is_modified(plano_para_actualizar_o_crear):
                db.session.add(plano_para_actualizar_o_crear) # Asegurar que se añade si es nuevo y no fue añadido antes
            db.session.flush() 
            plano_id_actual = plano_para_actualizar_o_crear.id

            actualizar_tsvector_plano(
                plano_id_actual, plano_para_actualizar_o_crear.codigo_plano,
                plano_para_actualizar_o_crear.area, plano_para_actualizar_o_crear.descripcion,
                texto_completo_pdf, idioma_doc_detectado
            )
            
            for r2_key in set(r2_object_keys_a_eliminar): 
                if r2_key and r2_key != r2_object_key_nuevo: 
                    try:
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
                        app.logger.info(f"Objeto R2 antiguo '{r2_key}' eliminado.")
                    except Exception as e_del_r2:
                        app.logger.error(f"Error borrando objeto R2 antiguo '{r2_key}': {e_del_r2}")
            
            for plano_db_a_borrar in db_entries_a_eliminar:
                app.logger.info(f"Eliminando registro de BD para plano ID {plano_db_a_borrar.id} ({plano_db_a_borrar.codigo_plano} Rev {plano_db_a_borrar.revision}).")
                db.session.delete(plano_db_a_borrar)
            
            db.session.commit()
            flash(f"Plano '{codigo_plano_form}' Revisión '{revision_form}' procesado y guardado exitosamente.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e_general:
            db.session.rollback()
            flash(f"Error general al procesar el archivo: {str(e_general)}", "danger")
            app.logger.error(f"Error general en la ruta /upload o durante las operaciones con la base de datos/R2: {e_general}", exc_info=True)
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
            termino_es_lematizado = lematizar_texto(query_contenido_original, NLP_ES, 'español')
            
            if termino_es_lematizado.strip():
                app.logger.info(f"Buscando FTS con término español: '{termino_es_lematizado}'")
                query_es_fts = final_query.filter(
                    Plano.tsvector_contenido.match(termino_es_lematizado, postgresql_regconfig='spanish')
                ).with_entities(Plano.id).all()
                for pid, in query_es_fts: ids_fts_encontrados.add(pid)

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
                    ).with_entities(Plano.id).all()
                    for pid, in query_en_fts: ids_fts_encontrados.add(pid)
            
            if query_contenido_original.strip(): 
                if ids_fts_encontrados:
                    final_query = final_query.filter(Plano.id.in_(list(ids_fts_encontrados)))
                else: 
                    final_query = final_query.filter(db.false()) 

        planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
        app.logger.info(f"Número de planos finales encontrados: {len(planos_db)}")

    except Exception as e:
        flash(f"Error al obtener la lista de planos: {str(e)}", "danger")
        app.logger.error(f"Error en la ruta /pdfs: {e}", exc_info=True)
        planos_db = [] 
    return render_template('list_pdfs.html', planos=planos_db, R2_OBJECT_PREFIX=R2_OBJECT_PREFIX, R2_ENDPOINT_URL=R2_ENDPOINT_URL, R2_BUCKET_NAME=R2_BUCKET_NAME)


@app.route('/pdfs/view/<path:object_key>') # Esta ruta ya genera pre-signed URLs, la nueva la usará internamente
@login_required
def view_pdf(object_key):
    if R2_CONFIG_MISSING: flash("Visualización de PDF deshabilitada: Faltan configuraciones de R2.", "danger"); return redirect(url_for('list_pdfs'))
    s3 = get_s3_client()
    if not s3: flash("Error en la configuración de R2. No se puede visualizar el PDF.", "danger"); return redirect(url_for('list_pdfs'))
    try:
        presigned_url = s3.generate_presigned_url('get_object', Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key}, ExpiresIn=3600)
        return redirect(presigned_url)
    except Exception as e: flash(f"Error al generar enlace para el PDF: {str(e)}", "danger"); app.logger.error(f"Error generando URL pre-firmada para {object_key}: {e}", exc_info=True)
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
                flash(f"Error: La ruta de archivo generada '{nueva_r2_object_key}' ya está en uso por otro plano.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)

        try:
            pdf_file_edit = request.files.get('pdf_file_edit')
            
            plano_a_editar.revision = nueva_revision_form
            plano_a_editar.area = nueva_area_form
            plano_a_editar.descripcion = nueva_descripcion_form
            plano_a_editar.r2_object_key = nueva_r2_object_key 
            plano_a_editar.fecha_subida = datetime.now(timezone.utc)

            texto_completo_pdf_para_fts = "" 
            idioma_doc_para_fts = plano_a_editar.idioma_documento 

            if pdf_file_edit and pdf_file_edit.filename: 
                if not pdf_file_edit.filename.lower().endswith('.pdf'):
                    flash('Solo se permiten archivos PDF para reemplazar.', 'warning')
                    return render_template('edit_plano.html', plano=plano_a_editar)
                
                app.logger.info(f"Reemplazando archivo PDF para plano ID {plano_id} con '{nueva_r2_object_key}'.")
                original_filename_secure_edit = secure_filename(pdf_file_edit.filename)
                plano_a_editar.nombre_archivo_original = original_filename_secure_edit

                try:
                    if hasattr(pdf_file_edit.stream, 'seek'): pdf_file_edit.stream.seek(0)
                    texto_completo_pdf_para_fts, idioma_doc_para_fts = extraer_texto_completo_pdf(pdf_file_edit.stream)
                    plano_a_editar.idioma_documento = idioma_doc_para_fts 
                    
                    if hasattr(pdf_file_edit.stream, 'seek'): pdf_file_edit.stream.seek(0)
                    s3.upload_fileobj(pdf_file_edit.stream, R2_BUCKET_NAME, nueva_r2_object_key) 
                    app.logger.info(f"Nuevo archivo PDF subido a R2: '{nueva_r2_object_key}'")

                    if antigua_r2_object_key and antigua_r2_object_key != nueva_r2_object_key:
                        app.logger.info(f"Eliminando objeto R2 antiguo '{antigua_r2_object_key}' después de reemplazar archivo.")
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
            
            else: 
                if nueva_r2_object_key != antigua_r2_object_key and antigua_r2_object_key and s3:
                    app.logger.info(f"Moviendo en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}' (solo metadatos cambiaron)")
                    try:
                        copy_source = {'Bucket': R2_BUCKET_NAME, 'Key': antigua_r2_object_key}
                        s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                        app.logger.info(f"Archivo movido en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}'.")
                    except Exception as e_move_r2:
                        db.session.rollback()
                        flash(f"Error al mover el archivo en R2: {str(e_move_r2)}", "danger")
                        app.logger.error(f"Error moviendo objeto en R2 durante edición de metadatos: {e_move_r2}", exc_info=True)
                        plano_a_editar.r2_object_key = antigua_r2_object_key 
                        return render_template('edit_plano.html', plano=plano_a_editar)

                app.logger.info(f"No se subió un nuevo PDF. Se usará el contenido del PDF en '{plano_a_editar.r2_object_key}' para FTS.")
                if s3 and plano_a_editar.r2_object_key:
                    try:
                        response = s3.get_object(Bucket=R2_BUCKET_NAME, Key=plano_a_editar.r2_object_key)
                        pdf_content_stream = response['Body']
                        pdf_bytes = pdf_content_stream.read()
                        pdf_file_like_object = io.BytesIO(pdf_bytes) 
                        
                        texto_completo_pdf_para_fts, _ = extraer_texto_completo_pdf(pdf_file_like_object)
                        idioma_doc_para_fts = plano_a_editar.idioma_documento 
                        app.logger.info(f"Texto extraído del PDF existente/movido en R2 para FTS del plano ID {plano_id}.")
                    except Exception as e_download_extract:
                        app.logger.error(f"No se pudo descargar o re-extraer texto del PDF en '{plano_a_editar.r2_object_key}' de R2: {e_download_extract}", exc_info=True)
                        flash(f"Advertencia: No se pudo actualizar el contenido del PDF en la búsqueda. Los metadatos sí se actualizarán.", "warning")
                else:
                    app.logger.warning(f"No hay cliente S3 o R2 object key para el plano ID {plano_id} tras posible edición de metadatos. El FTS se actualizará solo con metadatos.")
            
            actualizar_tsvector_plano(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano, 
                area_val=plano_a_editar.area, 
                descripcion_val=plano_a_editar.descripcion, 
                contenido_pdf_val=texto_completo_pdf_para_fts,
                idioma_doc=idioma_doc_para_fts
            )
            
            db.session.commit()
            flash(f"Plano '{plano_a_editar.codigo_plano}' actualizado exitosamente.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar el plano: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)
    return render_template('edit_plano.html', plano=plano_a_editar)


@app.route('/pdfs/delete/<int:plano_id>', methods=['POST'])
@login_required
def delete_pdf(plano_id):
    if current_user.role not in ['admin', 'cargador']: flash('No tienes permiso para eliminar planos.', 'danger'); return redirect(url_for('list_pdfs'))
    if R2_CONFIG_MISSING: flash("Eliminación de archivos deshabilitada: Faltan configuraciones de R2.", "danger"); return redirect(url_for('list_pdfs'))
    
    plano_a_eliminar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()
    if not s3: flash("Error en la configuración de R2. No se puede eliminar el archivo.", "danger"); return redirect(url_for('list_pdfs'))

    r2_key_a_eliminar = plano_a_eliminar.r2_object_key
    try:
        if r2_key_a_eliminar:
            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key_a_eliminar)
            app.logger.info(f"Objeto '{r2_key_a_eliminar}' eliminado de R2.")
        
        db.session.delete(plano_a_eliminar)
        db.session.commit()
        flash(f"Plano '{plano_a_eliminar.codigo_plano}' Revisión '{plano_a_eliminar.revision}' eliminado exitosamente.", "success")
    except Exception as e:
        db.session.rollback(); flash(f"Error al eliminar el plano: {str(e)}", "danger")
        app.logger.error(f"Error eliminando plano ID {plano_id}: {e}", exc_info=True)
    return redirect(url_for('list_pdfs'))

# ===========================================================
# NUEVA RUTA PARA LA HERRAMIENTA DE MEDICIÓN DE PDF
# ===========================================================

@app.route('/medidor/plano/<path:object_key>')
@login_required # Decide si esta herramienta requiere que el usuario esté logueado
def visor_medidor_pdf(object_key):
    app.logger.info(f"Accediendo al visor medidor para R2 object key: {object_key}")
    
    if R2_CONFIG_MISSING:
        flash("La herramienta de medición no está disponible: Falta configuración de R2.", "danger")
        # Redirigir a una página anterior o a la lista de planos
        return redirect(request.referrer or url_for('list_pdfs'))

    s3 = get_s3_client()
    if not s3:
        flash("Error al conectar con el almacenamiento de archivos (R2). No se puede cargar el visor.", "danger")
        return redirect(request.referrer or url_for('list_pdfs'))

    try:
        # Generar URL pre-firmada para que el cliente acceda al PDF desde R2
        pdf_presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key},
            ExpiresIn=3600  # Validez de 1 hora (3600 segundos)
        )
        app.logger.info(f"URL pre-firmada generada para {object_key}: {pdf_presigned_url[:100]}...") # Loguear solo una parte

        # Generar la URL para el worker de PDF.js que se servirá desde la carpeta static de Flask
        # Asegúrate que la ruta 'lib/pdfjs/build/pdf.worker.mjs' es correcta dentro de tu carpeta 'static'
        pdf_worker_url = url_for('static', filename='lib/pdfjs/build/pdf.worker.mjs')
        app.logger.info(f"URL para PDF.js worker: {pdf_worker_url}")
        
        # Obtener información del plano para el título de la página (opcional)
        plano_info = Plano.query.filter_by(r2_object_key=object_key).first()
        page_title = "Herramienta de Medición PDF"
        if plano_info:
            page_title = f"Medición: {plano_info.codigo_plano} Rev {plano_info.revision}"
        else:
            app.logger.warning(f"No se encontró información del plano en la BD para la R2 key: {object_key}")


        return render_template(
            'pdf_measure_viewer.html',  # Nombre de tu plantilla HTML para la herramienta
            pdf_url_to_load=pdf_presigned_url,
            pdf_worker_url=pdf_worker_url,
            page_title=page_title
        )

    except ClientError as e_s3_presign:
        flash(f"Error al generar el enlace seguro para el PDF: {e_s3_presign.response.get('Error', {}).get('Message', 'Error R2 desconocido')}", "danger")
        app.logger.error(f"Error de Cliente S3 generando URL pre-firmada para {object_key}: {e_s3_presign}", exc_info=True)
        return redirect(request.referrer or url_for('list_pdfs'))
    except Exception as e:
        flash(f"Error inesperado al preparar el visor de medición: {str(e)}", "danger")
        app.logger.error(f"Error general en visor_medidor_pdf para {object_key}: {e}", exc_info=True)
        return redirect(request.referrer or url_for('list_pdfs'))
# ===========================================================
# FIN DE LA NUEVA RUTA
# ===========================================================

# --- Bloque de Inicialización de la Aplicación ---
with app.app_context():
    db.create_all() 
    
    if not User.query.filter_by(username='admin').first():
        try:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123')) 
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario 'admin' por defecto creado.")
        except Exception as e: db.session.rollback(); app.logger.error(f"Error creando usuario admin: {e}")
    if not User.query.filter_by(username='usuario').first():
        try:
            consultor_user = User(username='usuario', role='consultor')
            consultor_user.set_password(os.getenv('CONSULTOR_PASSWORD', 'eimisa'))
            db.session.add(consultor_user)
            db.session.commit()
            app.logger.info("Usuario 'usuario' (consultor) por defecto creado.")
        except Exception as e: db.session.rollback(); app.logger.error(f"Error creando usuario consultor: {e}")
    
    app.logger.info("Contexto de aplicación inicializado: Base de datos y usuarios por defecto verificados.")

# --- Punto de Entrada para Desarrollo Local ---
if __name__ == '__main__':
    if R2_CONFIG_MISSING:
        print("\nADVERTENCIA LOCAL: Faltan configuraciones para Cloudflare R2 en tu archivo .env.")
        print("La subida, visualización y medición de PDFs almacenados en R2 no funcionarán correctamente.\n")
    print("Iniciando servidor de desarrollo Flask local.")
    print(f"La aplicación debería estar disponible en http://127.0.0.1:{os.getenv('PORT', 5000)}")
    port = int(os.getenv('PORT', 5000))
    # En producción, Render.com usará un servidor WSGI como Gunicorn.
    # debug=True no se recomienda para producción. Render gestiona esto.
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't'], host='0.0.0.0', port=port)