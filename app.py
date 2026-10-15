"""
Sistema web de gestión académica para cursos
Flask + SQLite + HTML/CSS

Atributos de calidad prioritarios:
  1. Seguridad      -> contraseñas con hash, sesiones seguras, control de acceso por rol, CSRF
  2. Usabilidad     -> interfaz simple, mensajes claros, diseño responsivo
  3. Disponibilidad -> manejo de errores, ruta /salud, base de datos ligera sin servidor externo
"""
import os
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    DATABASE=os.environ.get("DATABASE", os.path.join(BASE_DIR, "academico.db")),
    SESSION_COOKIE_HTTPONLY=True,          # JS no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",         # mitiga CSRF entre sitios
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # sesión expira
)

MAX_INTENTOS = 5          # intentos fallidos antes de bloquear
BLOQUEO_SEGUNDOS = 300    # 5 minutos
intentos_fallidos = {}    # {usuario: (conteo, timestamp)}


# ---------------------------------------------------------------- Base de datos
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    nombre TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('estudiante', 'profesor'))
);
CREATE TABLE IF NOT EXISTS materias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    profesor_id INTEGER NOT NULL REFERENCES usuarios(id)
);
CREATE TABLE IF NOT EXISTS inscripciones (
    estudiante_id INTEGER NOT NULL REFERENCES usuarios(id),
    materia_id INTEGER NOT NULL REFERENCES materias(id),
    calificacion REAL CHECK (calificacion IS NULL OR (calificacion >= 0 AND calificacion <= 100)),
    PRIMARY KEY (estudiante_id, materia_id)
);
CREATE INDEX IF NOT EXISTS idx_insc_est ON inscripciones(estudiante_id);
CREATE INDEX IF NOT EXISTS idx_insc_mat ON inscripciones(materia_id);
"""


def init_db(con_datos=True):
    db = get_db()
    db.executescript(ESQUEMA)
    if con_datos and db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        usuarios = [
            ("prof.lopez", "Ing. Ana López", "Profesor123!", "profesor"),
            ("prof.ruiz", "Mtro. Carlos Ruiz", "Profesor123!", "profesor"),
            ("al001", "María Pérez", "Alumno123!", "estudiante"),
            ("al002", "Juan Torres", "Alumno123!", "estudiante"),
            ("al003", "Sofía Hernández", "Alumno123!", "estudiante"),
        ]
        for u, n, p, r in usuarios:
            db.execute(
                "INSERT INTO usuarios (usuario, nombre, password_hash, rol) VALUES (?,?,?,?)",
                (u, n, generate_password_hash(p), r),
            )
        materias = [("Matemáticas", 1), ("Programación", 1), ("Electrónica", 2), ("Control", 2)]
        db.executemany("INSERT INTO materias (nombre, profesor_id) VALUES (?,?)", materias)
        calif = [
            (3, 1, 95), (3, 2, 90), (3, 3, 88), (3, 4, 92),
            (4, 1, 85), (4, 2, 78), (4, 3, None),
            (5, 2, 100), (5, 4, 81),
        ]
        db.executemany(
            "INSERT INTO inscripciones (estudiante_id, materia_id, calificacion) VALUES (?,?,?)", calif
        )
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    """flask --app app init-db"""
    init_db()
    print("Base de datos inicializada.")


# ---------------------------------------------------------------- Seguridad
def usuario_actual():
    uid = session.get("uid")
    if uid is None:
        return None
    return get_db().execute(
        "SELECT id, usuario, nombre, rol FROM usuarios WHERE id = ?", (uid,)
    ).fetchone()


def login_requerido(rol=None):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            g.usuario = usuario_actual()
            if g.usuario is None:
                flash("Inicia sesión para continuar.", "aviso")
                return redirect(url_for("login"))
            if rol and g.usuario["rol"] != rol:
                abort(403)
            return vista(*args, **kwargs)
        return envoltura
    return decorador


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def verificar_csrf():
    if request.method == "POST" and not app.config.get("TESTING_SIN_CSRF"):
        token = request.form.get("_csrf")
        if not token or token != session.get("_csrf"):
            abort(400, description="Token de seguridad inválido. Recarga la página.")


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"  # no guardar calificaciones en caché
    return resp


def esta_bloqueado(usuario):
    conteo, t = intentos_fallidos.get(usuario, (0, 0))
    if conteo >= MAX_INTENTOS and time.time() - t < BLOQUEO_SEGUNDOS:
        return True
    if conteo >= MAX_INTENTOS:
        intentos_fallidos.pop(usuario, None)
    return False


# ---------------------------------------------------------------- Rutas
@app.route("/")
def inicio():
    u = usuario_actual()
    if u is None:
        return redirect(url_for("login"))
    return redirect(url_for("panel_profesor" if u["rol"] == "profesor" else "panel_estudiante"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip().lower()
        password = request.form.get("password", "")
        if esta_bloqueado(usuario):
            flash("Demasiados intentos. Espera 5 minutos e inténtalo de nuevo.", "error")
            return render_template("login.html"), 429
        fila = get_db().execute(
            "SELECT id, password_hash FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()
        if fila and check_password_hash(fila["password_hash"], password):
            intentos_fallidos.pop(usuario, None)
            session.clear()                      # evita fijación de sesión
            session.permanent = True
            session["uid"] = fila["id"]
            return redirect(url_for("inicio"))
        conteo, _ = intentos_fallidos.get(usuario, (0, 0))
        intentos_fallidos[usuario] = (conteo + 1, time.time())
        # mensaje genérico: no revela si el usuario existe
        flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "ok")
    return redirect(url_for("login"))


@app.route("/estudiante")
@login_requerido("estudiante")
def panel_estudiante():
    # El estudiante SOLO puede ver sus propios datos (id tomado de la sesión, no de la URL)
    filas = get_db().execute(
        """SELECT m.nombre AS materia, u.nombre AS profesor, i.calificacion
           FROM inscripciones i
           JOIN materias m ON m.id = i.materia_id
           JOIN usuarios u ON u.id = m.profesor_id
           WHERE i.estudiante_id = ?
           ORDER BY m.nombre""",
        (g.usuario["id"],),
    ).fetchall()
    notas = [f["calificacion"] for f in filas if f["calificacion"] is not None]
    promedio = round(sum(notas) / len(notas), 1) if notas else None
    return render_template("estudiante.html", filas=filas, promedio=promedio)


@app.route("/profesor")
@login_requerido("profesor")
def panel_profesor():
    materias = get_db().execute(
        """SELECT m.id, m.nombre, COUNT(i.estudiante_id) AS alumnos
           FROM materias m LEFT JOIN inscripciones i ON i.materia_id = m.id
           WHERE m.profesor_id = ? GROUP BY m.id ORDER BY m.nombre""",
        (g.usuario["id"],),
    ).fetchall()
    return render_template("profesor.html", materias=materias)


def materia_del_profesor(materia_id):
    m = get_db().execute(
        "SELECT id, nombre FROM materias WHERE id = ? AND profesor_id = ?",
        (materia_id, g.usuario["id"]),
    ).fetchone()
    if m is None:
        abort(403)  # un profesor no puede editar materias ajenas
    return m


@app.route("/profesor/materia/<int:materia_id>", methods=["GET", "POST"])
@login_requerido("profesor")
def calificar(materia_id):
    materia = materia_del_profesor(materia_id)
    db = get_db()
    if request.method == "POST":
        errores = 0
        alumnos = db.execute(
            "SELECT estudiante_id FROM inscripciones WHERE materia_id = ?", (materia_id,)
        ).fetchall()
        for a in alumnos:
            valor = request.form.get(f"cal_{a['estudiante_id']}", "").strip()
            if valor == "":
                nueva = None
            else:
                try:
                    nueva = float(valor)
                    if not 0 <= nueva <= 100:
                        raise ValueError
                except ValueError:
                    errores += 1
                    continue
            db.execute(
                "UPDATE inscripciones SET calificacion = ? WHERE materia_id = ? AND estudiante_id = ?",
                (nueva, materia_id, a["estudiante_id"]),
            )
        db.commit()
        if errores:
            flash(f"Se guardaron los cambios, pero {errores} valor(es) no eran válidos (0 a 100).", "aviso")
        else:
            flash("Calificaciones guardadas.", "ok")
        return redirect(url_for("calificar", materia_id=materia_id))

    alumnos = db.execute(
        """SELECT u.id, u.usuario, u.nombre, i.calificacion
           FROM inscripciones i JOIN usuarios u ON u.id = i.estudiante_id
           WHERE i.materia_id = ? ORDER BY u.nombre""",
        (materia_id,),
    ).fetchall()
    return render_template("calificar.html", materia=materia, alumnos=alumnos)


@app.route("/salud")
def salud():
    """Endpoint de monitoreo de disponibilidad."""
    try:
        get_db().execute("SELECT 1").fetchone()
        return {"estado": "ok"}, 200
    except sqlite3.Error:
        return {"estado": "error_bd"}, 503


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def manejar_error(e):
    codigo = getattr(e, "code", 500)
    mensajes = {
        400: "La solicitud no es válida.",
        403: "No tienes permiso para ver esta página.",
        404: "La página que buscas no existe.",
        500: "Ocurrió un error interno. Inténtalo más tarde.",
    }
    return render_template("error.html", codigo=codigo, mensaje=mensajes.get(codigo)), codigo


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False)
