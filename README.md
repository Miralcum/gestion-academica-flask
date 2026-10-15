# Sistema web de gestión académica (Flask)

## Ejecutar
```
pip install -r requirements.txt
python app.py
```
Abrir http://127.0.0.1:5000 (la base `academico.db` se crea sola con datos de ejemplo).

| Usuario | Contraseña | Rol |
|---|---|---|
| al001, al002, al003 | Alumno123! | Estudiante |
| prof.lopez, prof.ruiz | Profesor123! | Profesor |

## Pruebas (evidencias de atributos de calidad)
```
python -m unittest -v tests.test_calidad
```
