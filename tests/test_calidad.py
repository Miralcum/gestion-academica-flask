"""Pruebas que evidencian los atributos de calidad. Ejecutar: python -m unittest -v"""
import os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ["DATABASE"] = os.path.join(_tmp, "prueba.db")
import app as m  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        m.intentos_fallidos.clear()
        self.c = m.app.test_client()
        with self.c.session_transaction() as s:
            s["_csrf"] = "tok"

    def entrar(self, u, p):
        return self.c.post("/login", data={"usuario": u, "password": p, "_csrf": "tok"})

    def relogin(self, u, p):
        r = self.entrar(u, p)
        with self.c.session_transaction() as s:
            s["_csrf"] = "tok"
        return r


class Seguridad(Base):
    def test_contrasenas_con_hash(self):
        with m.app.app_context():
            h = m.get_db().execute("SELECT password_hash FROM usuarios WHERE usuario='al001'").fetchone()[0]
        self.assertNotIn("Alumno123!", h)
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_sin_sesion_redirige_a_login(self):
        for ruta in ["/estudiante", "/profesor", "/profesor/materia/1"]:
            r = self.c.get(ruta)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.headers["Location"])

    def test_login_incorrecto_mensaje_generico(self):
        r = self.entrar("al001", "mala")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Usuario o contraseña incorrectos", r.get_data(as_text=True))

    def test_bloqueo_por_fuerza_bruta(self):
        for _ in range(m.MAX_INTENTOS):
            self.entrar("al002", "mala")
        r = self.entrar("al002", "Alumno123!")
        self.assertEqual(r.status_code, 429)

    def test_estudiante_no_accede_a_panel_profesor(self):
        self.relogin("al001", "Alumno123!")
        self.assertEqual(self.c.get("/profesor").status_code, 403)
        self.assertEqual(self.c.get("/profesor/materia/1").status_code, 403)

    def test_estudiante_solo_ve_sus_calificaciones(self):
        self.relogin("al003", "Alumno123!")
        html = self.c.get("/estudiante").get_data(as_text=True)
        self.assertIn("Sofía Hernández", html)
        self.assertNotIn("Matemáticas", html)  # al003 no cursa Matemáticas

    def test_profesor_no_edita_materia_ajena(self):
        self.relogin("prof.lopez", "Profesor123!")
        r = self.c.post("/profesor/materia/3", data={"cal_3": "10", "_csrf": "tok"})
        self.assertEqual(r.status_code, 403)

    def test_post_sin_csrf_rechazado(self):
        self.relogin("prof.lopez", "Profesor123!")
        r = self.c.post("/profesor/materia/1", data={"cal_3": "10"})
        self.assertEqual(r.status_code, 400)

    def test_cabeceras_y_cookie_segura(self):
        r = self.entrar("al001", "Alumno123!")
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        r = self.c.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_validacion_rango_calificacion(self):
        self.relogin("prof.lopez", "Profesor123!")
        self.c.post("/profesor/materia/1", data={"cal_3": "150", "cal_4": "85", "_csrf": "tok"})
        with m.app.app_context():
            v = m.get_db().execute(
                "SELECT calificacion FROM inscripciones WHERE estudiante_id=3 AND materia_id=1").fetchone()[0]
        self.assertEqual(v, 95)  # no se guardó el 150


class Usabilidad(Base):
    def test_profesor_registra_y_alumno_ve_cambio(self):
        self.relogin("prof.ruiz", "Profesor123!")
        r = self.c.post("/profesor/materia/3", data={"cal_3": "88", "cal_4": "91", "_csrf": "tok"},
                        follow_redirects=True)
        self.assertIn("Calificaciones guardadas", r.get_data(as_text=True))
        self.c.post("/logout", data={"_csrf": "tok"})
        with self.c.session_transaction() as s:
            s["_csrf"] = "tok"
        self.relogin("al002", "Alumno123!")
        self.assertIn("91", self.c.get("/estudiante").get_data(as_text=True))

    def test_redireccion_segun_rol(self):
        r = self.relogin("prof.lopez", "Profesor123!")
        self.assertIn("/", r.headers["Location"])
        self.assertIn("/profesor", self.c.get("/").headers["Location"])

    def test_pagina_404_amigable(self):
        r = self.c.get("/no-existe")
        self.assertEqual(r.status_code, 404)
        self.assertIn("no existe", r.get_data(as_text=True))


class DisponibilidadRendimiento(Base):
    def test_endpoint_salud(self):
        r = self.c.get("/salud")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["estado"], "ok")

    def test_tiempo_de_respuesta(self):
        self.relogin("al001", "Alumno123!")
        t = time.perf_counter()
        for _ in range(50):
            self.assertEqual(self.c.get("/estudiante").status_code, 200)
        prom_ms = (time.perf_counter() - t) / 50 * 1000
        print(f"\n   Tiempo promedio /estudiante: {prom_ms:.2f} ms")
        self.assertLess(prom_ms, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
