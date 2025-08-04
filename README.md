🚀 Auditor de Hardening para Dispositivos Cisco
Una herramienta web poderosa y totalmente privada para auditar configuraciones de equipos Cisco (IOS, IOS-XE, NX-OS) en busca de vulnerabilidades y malas prácticas. 🔒

Como es una aplicación client-side, tus archivos de configuración nunca salen de tu navegador. Tu privacidad y seguridad están garantizadas.

✨ Características Principales
Análisis Simple: Sube un único archivo (show running-config) y obtén un análisis de seguridad instantáneo y detallado.

Análisis Comparativo: Compara dos configuraciones (un "antes" y un "después") para visualizar claramente el progreso en la mitigación de riesgos.

Análisis de Flota (Beta): Carga múltiples archivos y obtén un dashboard centralizado con métricas clave, distribución de riesgos y las vulnerabilidades más comunes de toda tu red.

Reportes Detallados: Los resultados incluyen descripciones claras, severidad, benchmarks CIS y recomendaciones de remediación para cada hallazgo.

Exportación de Reportes: Exporta tus análisis a formatos HTML y PDF para facilitar la documentación y el intercambio de información.

📝 Requerimientos
Para un análisis de hardening completo, la herramienta necesita los siguientes datos. Asegúrate de obtener la salida de estos comandos en formato de texto (.txt, .log o .cfg) de cada dispositivo.

Configuración Completa (show running-config): Este es el archivo principal que se debe analizar para la auditoría de hardening.

Versión del Software (show version): Es fundamental para identificar vulnerabilidades específicas del sistema operativo (IOS/IOS-XE/NX-OS) y el modelo del dispositivo.

Información Adicional (Opcional): Para un análisis de vulnerabilidades más profundo, se recomienda incluir también las salidas de los siguientes comandos:

show access-lists

show ip interface brief

show cdp neighbors y/o show lldp neighbors

show logging

🛠️ Cómo Empezar
Esta aplicación usa módulos de JavaScript (ESM) y no puede ejecutarse simplemente abriendo el archivo index.html desde tu navegador. Necesitas un servidor web local para que funcione correctamente.

Opción 1: Con XAMPP (Recomendado)
Instala XAMPP: Descarga y configura XAMPP si aún no lo tienes.

Clona el repositorio:

Bash

git clone https://[URL_DEL_REPOSITORIO_GIT]/auditor-cisco.git
Copia el proyecto: Mueve la carpeta auditor-cisco dentro del directorio htdocs de XAMPP.

Inicia Apache: Abre el Panel de Control de XAMPP y haz clic en "Start" junto al módulo Apache.

Accede a la app: Abre tu navegador y ve a http://localhost/auditor-cisco/.

Opción 2: Con Python (Para Desarrolladores)
Si tienes Python instalado, puedes iniciar un servidor web simple con un solo comando desde la raíz del proyecto.

Bash

# Para Python 3
python -m http.server

# Para Python 2
python -m SimpleHTTPServer
Después, navega a http://localhost:8000 en tu navegador.

🚀 Modo de Uso
Recolecta la información: Asegúrate de tener los archivos de configuración requeridos por la herramienta. Consulta la sección 📝 Requerimientos para más detalles.

Selecciona un modo: Elige entre Análisis Simple, Análisis Comparativo o Análisis de Flota.

Sube tus archivos: Arrastra y suelta tus configuraciones en la herramienta.

Analiza: Haz clic en el botón correspondiente.

Revisa y Exporta: Explora los resultados y descarga los reportes si lo necesitas.

💻 Tecnologías Utilizadas
HTML5 & CSS3: Para la estructura y el estilo.

Tailwind CSS: Framework CSS para un diseño moderno y responsive.

JavaScript (ES6): Lógica principal de la aplicación.

Chart.js: Creación de gráficas y visualizaciones.

jsPDF: Generación de reportes PDF.

Web Workers: Para análisis de flota en segundo plano sin congelar la interfaz.

🤝 Contribuciones
¡Las contribuciones son bienvenidas! Si tienes ideas para nuevas verificaciones, mejoras en la interfaz o correcciones, no dudes en abrir un issue o enviar un pull request.
