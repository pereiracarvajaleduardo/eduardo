# === VERSIÓN FINAL Y FUNCIONAL ===
import spacy 
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError # Asegúrate que esta línea esté
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

# Carga global del modelo spaCy para español
# Se intentará cargar una vez. Si falla, las funciones que lo usan deben manejarlo.
NLP_ES = None
try:
    NLP_ES = spacy.load("es_core_news_sm")
    app.logger.info("Modelo spaCy 'es_core_news_sm' cargado exitosamente al iniciar la aplicación.")
except OSError:
    app.logger.error("FALLO AL CARGAR MODELO spaCy 'es_core_news_sm'. " +
                     "Asegúrate de haberlo descargado con: python -m spacy download es_core_news_sm. " +
                     "La lematización estará deshabilitada.")
except Exception as e:
    app.logger.error(f"Ocurrió un error inesperado al cargar el modelo spaCy: {e}")

# --- Configuración de la Base de Datos ---
# Usa la DATABASE_URL de las variables de entorno si existe (para Render),
# sino, usa una SQLite local para desarrollo.
DATABASE_URL_ENV = os.getenv('DATABASE_URL')
if DATABASE_URL_ENV:
    # Asegúrate de que SQLAlchemy use 'postgresql' y no 'postgres' para psycopg2
    if DATABASE_URL_ENV.startswith("postgres://"):
        DATABASE_URL_ENV = DATABASE_URL_ENV.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL_ENV
    app.logger.info(f"Usando base de datos PostgreSQL externa: {DATABASE_URL_ENV.split('@')[-1]}") # No mostrar credenciales
else:
    # Fallback a SQLite para desarrollo local si DATABASE_URL no está definida
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    db_file_path = os.path.join(BASE_DIR, 'planos_dev.db') # Puedes usar un nombre diferente para la local
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
    area_encontrada = None
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
        with pdfplumber.open(pdf_file_stream) as pdf:
            if not pdf.pages:
                app.logger.warning("El PDF subido no tiene páginas.")
                return None
            
            page = pdf.pages[0] # Solo procesa la primera página para el área
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

def extraer_texto_completo_pdf(pdf_file_stream, max_paginas=6): # Límite de páginas añadido
    texto_completo = []
    try:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
        
        with pdfplumber.open(pdf_file_stream) as pdf:
            num_paginas_a_procesar = min(len(pdf.pages), max_paginas)
            app.logger.info(f"Procesando {num_paginas_a_procesar} páginas para FTS (límite: {max_paginas}). Total páginas PDF: {len(pdf.pages)}")

            for i in range(num_paginas_a_procesar):
                page = pdf.pages[i]
                texto_pagina = page.extract_text(x_tolerance=2, y_tolerance=2)
                if texto_pagina:
                    texto_completo.append(texto_pagina)
                # El log puede ser muy verboso, considera reducirlo o cambiar el nivel a DEBUG si no es necesario siempre
                # app.logger.debug(f"Texto extraído para FTS pág {i+1} (primeros 100c): {texto_pagina[:100] if texto_pagina else 'Ninguno'}")
    except Exception as e:
        app.logger.error(f"Error extrayendo el texto completo del PDF para FTS: {e}", exc_info=True)
    finally:
        if hasattr(pdf_file_stream, 'seek') and callable(pdf_file_stream.seek):
            pdf_file_stream.seek(0)
            
    return "\n".join(texto_completo)
    
def inicializar_fts():
    inspector = db.inspect(db.engine)
    if 'plano_fts' not in inspector.get_table_names():
        try:
            with db.engine.connect() as connection:
                connection.execute(db.text("""
                CREATE VIRTUAL TABLE plano_fts USING fts5(
                    plano_id UNINDEXED, 
                    codigo_plano, 
                    area, 
                    descripcion, 
                    contenido_pdf,
                    tokenize = "unicode61 remove_diacritics 2"
                );"""))
                connection.commit()
            app.logger.info("Tabla virtual 'plano_fts' creada exitosamente.")
        except Exception as e:
            app.logger.error(f"Error al crear la tabla virtual 'plano_fts': {e}", exc_info=True)
    else:
        app.logger.info("Tabla virtual 'plano_fts' ya existe.")

def actualizar_indice_fts_session(plano_id_val, codigo_plano_val, area_val, descripcion_val, contenido_pdf_val):
    try:
        db.session.execute(db.text("DELETE FROM plano_fts WHERE plano_id = :plano_id;"), {"plano_id": plano_id_val})
        db.session.execute(db.text("""
            INSERT INTO plano_fts (plano_id, codigo_plano, area, descripcion, contenido_pdf)
            VALUES (:plano_id, :codigo_plano, :area, :descripcion, :contenido_pdf);
        """), {
            "plano_id": plano_id_val, 
            "codigo_plano": codigo_plano_val or "",
            "area": area_val or "", 
            "descripcion": descripcion_val or "",
            "contenido_pdf": contenido_pdf_val or ""
        })
        app.logger.info(f"Operaciones FTS para plano_id: {plano_id_val} añadidas a la sesión.")
    except Exception as e:
        app.logger.error(f"Error preparando la actualización FTS para plano_id {plano_id_val}: {e}", exc_info=True)
        raise

def eliminar_del_indice_fts_session(plano_id_val):
    try:
        db.session.execute(db.text("DELETE FROM plano_fts WHERE plano_id = :plano_id;"), {"plano_id": plano_id_val})
        app.logger.info(f"Operación de eliminación FTS para plano_id: {plano_id_val} añadida a la sesión.")
    except Exception as e:
        app.logger.error(f"Error preparando la eliminación FTS para plano_id {plano_id_val}: {e}", exc_info=True)
        raise


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
    
    if R2_CONFIG_MISSING:
        flash("La subida de archivos está deshabilitada por un error de configuración.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        pdf_file = request.files.get('pdf_file')
        codigo_plano_form = request.form.get('codigo_plano', '').strip()
        revision_form = request.form.get('revision', '').strip()
        area_form = request.form.get('area', '').strip()
        descripcion_form = request.form.get('descripcion', '').strip()

        if not pdf_file or not pdf_file.filename: # Chequeo adicional por si pdf_file es None
            flash('No se seleccionó ningún archivo.', 'warning')
            return redirect(request.url)
        if not codigo_plano_form or not revision_form:
            flash('Los campos Código del Plano y Revisión son obligatorios.', 'warning')
            return redirect(request.url)
        if not pdf_file.filename.lower().endswith('.pdf'):
            flash('Solo se permiten archivos PDF.', 'warning')
            return redirect(request.url)

        area_final_determinada = None
        es_mr = codigo_plano_form.upper().startswith("K484-0000-0000-MR-")

        if es_mr:
            if area_form:
                area_final_determinada = area_form
                app.logger.info(f"Plano MR. Se usará el área proporcionada manualmente: '{area_final_determinada}'")
            else:
                app.logger.info(f"Plano MR '{codigo_plano_form}' sin área proporcionada. Intentando extraer del PDF...")
                try:
                    if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                    area_extraida = extraer_area_del_pdf(pdf_file.stream)
                    if area_extraida:
                        area_final_determinada = area_extraida
                        flash(f"Área '{area_final_determinada}' detectada automáticamente del PDF.", "info")
                    else:
                        area_final_determinada = "Area_MR_Pendiente"
                        flash("No se pudo extraer el área del PDF MR. Se usará 'Area_MR_Pendiente'.", "warning")
                except Exception as e_area_ext:
                    app.logger.error(f"Excepción al extraer área del PDF MR: {e_area_ext}", exc_info=True)
                    area_final_determinada = "Area_MR_Error"
                    flash("Error al intentar extraer el área del PDF MR. Se usará 'Area_MR_Error'.", "warning")
        else: # No es MR
            if area_form:
                area_final_determinada = area_form
            else:
                flash('El campo "Área" es obligatorio para planos que no son MR.', 'warning')
                return redirect(request.url)
        
        if area_final_determinada is None: # Doble chequeo por si alguna lógica falló
             flash('Error crítico: No se pudo determinar el Área para el plano.', 'danger')
             app.logger.error("CRÍTICO: area_final_determinada es None antes de la subida.")
             return redirect(request.url)

        original_filename_secure = secure_filename(pdf_file.filename)
        cleaned_area = clean_for_path(area_final_determinada)
        cleaned_codigo = clean_for_path(codigo_plano_form)
        cleaned_revision = clean_for_path(revision_form)

        r2_filename = f"{cleaned_codigo}_Rev{cleaned_revision}.pdf"
        r2_object_key_nuevo = f"{R2_OBJECT_PREFIX}{cleaned_area}/{r2_filename}"
        
        s3 = get_s3_client()
        if not s3:
            flash("Error de configuración con el servicio de almacenamiento (R2). La subida falló.", "danger")
            return redirect(request.url)

        try:
            planos_existentes_mismo_codigo = Plano.query.filter_by(codigo_plano=codigo_plano_form).all()
            plano_para_actualizar_o_crear = None
            eliminar_objetos_r2_y_db = []

            if not planos_existentes_mismo_codigo:
                app.logger.info(f"Creando nuevo registro para el plano: {codigo_plano_form} Rev {revision_form}")
                plano_para_actualizar_o_crear = Plano(
                    codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                    nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                    descripcion=descripcion_form
                )
            else:
                revision_actual_mas_alta_db_str = None
                plano_con_revision_ingresada = None
                for p_existente in planos_existentes_mismo_codigo:
                    if p_existente.revision == revision_form:
                        plano_con_revision_ingresada = p_existente
                    if revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(p_existente.revision, revision_actual_mas_alta_db_str):
                        revision_actual_mas_alta_db_str = p_existente.revision
                
                if plano_con_revision_ingresada:
                    app.logger.info(f"Actualizando plano existente: {codigo_plano_form} Rev {revision_form}")
                    plano_para_actualizar_o_crear = plano_con_revision_ingresada
                    if plano_para_actualizar_o_crear.r2_object_key != r2_object_key_nuevo and plano_para_actualizar_o_crear.r2_object_key:
                        app.logger.info(f"La clave del objeto R2 cambiará. Antiguo: {plano_para_actualizar_o_crear.r2_object_key}, Nuevo: {r2_object_key_nuevo}")
                        # La lógica para borrar el objeto antiguo se manejará después de subir el nuevo
                elif revision_actual_mas_alta_db_str is None or es_revision_mas_nueva(revision_form, revision_actual_mas_alta_db_str):
                    app.logger.info(f"Nueva revisión '{revision_form}' es más reciente que '{revision_actual_mas_alta_db_str or 'ninguna existente'}'. Marcando revisiones antiguas para eliminación.")
                    for p_antiguo in planos_existentes_mismo_codigo:
                        eliminar_objetos_r2_y_db.append(p_antiguo)
                    plano_para_actualizar_o_crear = Plano(
                        codigo_plano=codigo_plano_form, revision=revision_form, area=area_final_determinada,
                        nombre_archivo_original=original_filename_secure, r2_object_key=r2_object_key_nuevo,
                        descripcion=descripcion_form
                    )
                else:
                    flash(f"Revisión '{revision_form}' no es más reciente que la revisión existente '{revision_actual_mas_alta_db_str}'. El archivo no fue procesado.", "warning")
                    return redirect(request.url)

            if not plano_para_actualizar_o_crear:
                app.logger.error("CRÍTICO: No se pudo determinar el objeto plano para actualizar o crear.")
                raise Exception("Error interno determinando el plano a crear/actualizar.")

            # Actualizar datos del plano
            plano_para_actualizar_o_crear.area = area_final_determinada
            plano_para_actualizar_o_crear.r2_object_key = r2_object_key_nuevo
            plano_para_actualizar_o_crear.nombre_archivo_original = original_filename_secure
            plano_para_actualizar_o_crear.descripcion = descripcion_form
            plano_para_actualizar_o_crear.fecha_subida = datetime.now(timezone.utc)

            if plano_para_actualizar_o_crear not in db.session:
                db.session.add(plano_para_actualizar_o_crear)
            
            db.session.flush() # Para obtener el ID si es un nuevo plano
            plano_id_actual = plano_para_actualizar_o_crear.id

            # Procesar y subir archivo
            try:
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                texto_completo_pdf = extraer_texto_completo_pdf(pdf_file.stream) # Límite de páginas ya aplicado dentro
                
                if hasattr(pdf_file.stream, 'seek'): pdf_file.stream.seek(0)
                s3.upload_fileobj(pdf_file.stream, R2_BUCKET_NAME, r2_object_key_nuevo)
                app.logger.info(f"Archivo '{r2_object_key_nuevo}' subido exitosamente a R2.")
            except ClientError as e_s3: # Error específico de Boto3/S3
                app.logger.error(f"Error de Boto3/S3 al subir el archivo a R2: {e_s3}", exc_info=True)
                db.session.rollback()
                flash(f"Error de conexión al subir el archivo: {e_s3.response.get('Error', {}).get('Message', 'Error desconocido')}", "danger")
                return redirect(request.url)
            except Exception as e_upload: # Otro error durante la subida o extracción
                app.logger.error(f"Error durante la extracción de texto o subida del archivo: {e_upload}", exc_info=True)
                db.session.rollback()
                flash(f"Error procesando el archivo PDF o subiéndolo: {str(e_upload)}", "danger")
                return redirect(request.url)

            # Actualizar índice FTS
            actualizar_indice_fts_session(
                plano_id_actual, plano_para_actualizar_o_crear.codigo_plano,
                plano_para_actualizar_o_crear.area, plano_para_actualizar_o_crear.descripcion,
                texto_completo_pdf
            )
            
            # Eliminar objetos y registros antiguos de la BD si es una nueva revisión mayor
            for plano_a_borrar_obj_db in eliminar_objetos_r2_y_db:
                if plano_a_borrar_obj_db.r2_object_key and plano_a_borrar_obj_db.r2_object_key != r2_object_key_nuevo:
                    try:
                        s3.delete_object(Bucket=R2_BUCKET_NAME, Key=plano_a_borrar_obj_db.r2_object_key)
                        app.logger.info(f"Objeto R2 antiguo '{plano_a_borrar_obj_db.r2_object_key}' eliminado.")
                    except Exception as e_del_r2:
                        app.logger.error(f"Error borrando objeto R2 antiguo '{plano_a_borrar_obj_db.r2_object_key}': {e_del_r2}")
                eliminar_del_indice_fts_session(plano_a_borrar_obj_db.id)
                db.session.delete(plano_a_borrar_obj_db)
                app.logger.info(f"Registro de base de datos para plano ID {plano_a_borrar_obj_db.id} (Rev '{plano_a_borrar_obj_db.revision}') eliminado.")
            
            db.session.commit()
            flash(f"Plano '{codigo_plano_form}' Revisión '{revision_form}' (Área: {area_final_determinada}) procesado e indexado correctamente.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error general procesando el archivo: {str(e)}", "danger")
            app.logger.error(f"Error general en la subida/DB: {e}", exc_info=True)
            return redirect(request.url)

    return render_template('upload_pdf.html')

@app.route('/pdfs')
@login_required
def list_pdfs():
    try:
        query_codigo = request.args.get('q_codigo', '').strip()
        query_area = request.args.get('q_area', '').strip()
        query_contenido = request.args.get('q_contenido', '').strip()

        app.logger.info(f"Buscando con Código: '{query_codigo}', Área: '{query_area}', Contenido Original: '{query_contenido}'") # Log original

        final_query = Plano.query

        if query_codigo:
            final_query = final_query.filter(Plano.codigo_plano.ilike(f'%{query_codigo}%'))
        if query_area:
            final_query = final_query.filter(Plano.area.ilike(f'%{query_area}%'))

        planos_db = []

        if query_contenido:
            processed_query_contenido = query_contenido # Por defecto, usar la consulta original
            if NLP_ES: # Solo si el modelo se cargó correctamente
                doc = NLP_ES(query_contenido.lower()) # Convertir a minúsculas para mejor lematización
                # Filtramos tokens que no sean stop words (palabras comunes) ni puntuación
                lemmatized_terms = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct and token.lemma_.strip()]
                if lemmatized_terms:
                    processed_query_contenido = " ".join(lemmatized_terms)
                    app.logger.info(f"Término FTS lematizado y filtrado: '{processed_query_contenido}' (Original: '{query_contenido}')")
                else:
                    app.logger.info(f"Lematización no produjo términos útiles para '{query_contenido}', usando original.")
            else: # Fallback si spaCy no está disponible
                app.logger.warning("Modelo NLP_ES no disponible, usando término de búsqueda original para FTS.")

            # Construir el término FTS con las palabras procesadas (lematizadas o originales)
            terminos_fts = " ".join([f"{palabra.strip()}*" for palabra in processed_query_contenido.split() if palabra.strip()])

            if not terminos_fts:
                app.logger.info("Término de búsqueda FTS vacío después del procesamiento, no se aplicará filtro FTS.")
                planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
            else:
                app.logger.info(f"Término FTS final para la búsqueda: '{terminos_fts}'")
                sql_fts = db.text("SELECT plano_id FROM plano_fts WHERE plano_fts MATCH :termino ORDER BY rank")
                with db.engine.connect() as conn:
                    result = conn.execute(sql_fts, {"termino": terminos_fts})
                ids_encontrados_fts = [row[0] for row in result]

                if not ids_encontrados_fts:
                    app.logger.info("La búsqueda FTS no devolvió IDs.")
                    planos_db = [] 
                else:
                    app.logger.info(f"IDs encontrados por FTS: {ids_encontrados_fts}")
                    final_query = final_query.filter(Plano.id.in_(ids_encontrados_fts))
                    planos_db = final_query.order_by(Plano.area, Plano.codigo_plano, Plano.revision).all()
        else:
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
    if R2_CONFIG_MISSING:
        flash("La visualización de archivos está deshabilitada por un error de configuración.", "danger")
        return redirect(url_for('list_pdfs'))
    s3 = get_s3_client()
    if not s3:
        flash("Error al conectar con el servicio de almacenamiento.", "danger")
        return redirect(url_for('list_pdfs'))
    try:
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': R2_BUCKET_NAME, 'Key': object_key},
            ExpiresIn=3600 
        )
        return redirect(presigned_url)
    except Exception as e:
        flash(f"No se pudo generar el enlace para ver el archivo: {str(e)}", "danger")
        app.logger.error(f"Error generando URL prefirmada para {object_key}: {e}", exc_info=True)
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
                Plano.id != plano_id
            ).first()
            if conflicto_revision:
                flash(f"Error: Ya existe un plano con código '{plano_a_editar.codigo_plano}' y revisión '{nueva_revision_form}'.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)
        
        if nueva_r2_object_key != antigua_r2_object_key:
            conflicto_r2_key = Plano.query.filter(Plano.r2_object_key == nueva_r2_object_key, Plano.id != plano_id).first()
            if conflicto_r2_key:
                flash(f"Error: La ruta de archivo generada '{nueva_r2_object_key}' ya está en uso por otro plano.", "danger")
                return render_template('edit_plano.html', plano=plano_a_editar)

        try:
            if nueva_r2_object_key != antigua_r2_object_key and antigua_r2_object_key and s3:
                app.logger.info(f"Moviendo en R2 de '{antigua_r2_object_key}' a '{nueva_r2_object_key}'")
                copy_source = {'Bucket': R2_BUCKET_NAME, 'Key': antigua_r2_object_key}
                s3.copy_object(Bucket=R2_BUCKET_NAME, Key=nueva_r2_object_key, CopySource=copy_source)
                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=antigua_r2_object_key)
                app.logger.info("Archivo movido con éxito en R2.")
            
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
            except Exception as e_fetch_fts:
                app.logger.error(f"No se pudo recuperar contenido_pdf de FTS para plano {plano_id} al editar: {e_fetch_fts}")

            actualizar_indice_fts_session(
                plano_id_val=plano_a_editar.id,
                codigo_plano_val=plano_a_editar.codigo_plano,
                area_val=plano_a_editar.area,
                descripcion_val=plano_a_editar.descripcion,
                contenido_pdf_val=contenido_pdf_actual
            )
            
            db.session.commit()
            flash(f"Plano '{plano_a_editar.codigo_plano}' actualizado correctamente.", "success")
            return redirect(url_for('list_pdfs'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar el plano: {str(e)}", "danger")
            app.logger.error(f"Error editando plano ID {plano_id}: {e}", exc_info=True)
            return render_template('edit_plano.html', plano=plano_a_editar)

    return render_template('edit_plano.html', plano=plano_a_editar)

@app.route('/pdfs/delete/<int:plano_id>', methods=['POST'])
@login_required
def delete_pdf(plano_id):
    if current_user.role not in ['admin', 'cargador']:
        flash('No tienes permiso para eliminar planos.', 'danger')
        return redirect(url_for('list_pdfs'))

    if R2_CONFIG_MISSING:
        flash("La eliminación de archivos está deshabilitada debido a un error de configuración.", "danger")
        return redirect(url_for('list_pdfs'))

    plano_a_eliminar = Plano.query.get_or_404(plano_id)
    s3 = get_s3_client()

    if not s3:
        flash("Error al conectar con el servicio de almacenamiento. No se pudo eliminar el archivo.", "danger")
        return redirect(url_for('list_pdfs'))

    r2_key_a_eliminar = plano_a_eliminar.r2_object_key
    codigo_plano_eliminado = plano_a_eliminar.codigo_plano
    revision_eliminada = plano_a_eliminar.revision
    
    try:
        if r2_key_a_eliminar:
            app.logger.info(f"Intentando eliminar el objeto '{r2_key_a_eliminar}' de R2.")
            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key_a_eliminar)
            app.logger.info(f"Objeto '{r2_key_a_eliminar}' eliminado (o no encontrado) de R2.")
        
        eliminar_del_indice_fts_session(plano_a_eliminar.id)
        db.session.delete(plano_a_eliminar)
        db.session.commit()
        
        flash(f"Plano '{codigo_plano_eliminado}' Rev '{revision_eliminada}' eliminado correctamente.", "success")
        app.logger.info(f"Plano ID {plano_a_eliminar.id} ('{codigo_plano_eliminado}' Rev '{revision_eliminada}') eliminado de la base de datos y del índice FTS.")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el plano: {str(e)}", "danger")
        app.logger.error(f"Error eliminando el plano ID {plano_id}: {e}", exc_info=True)
        
    return redirect(url_for('list_pdfs'))


# --- Bloque de Inicialización de la Aplicación ---
with app.app_context():
    db.create_all()
    inicializar_fts()
    
    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username='admin').first():
        try:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123')) 
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