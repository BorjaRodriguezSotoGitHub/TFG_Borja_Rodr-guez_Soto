En este proyecto se encuentra el código del trabajo fin de grado sobre el desarrollo de un sistema escalable para una plataforma de conciencia cibersituacional basado en ontologías.

## Será necesario la instalación previa de los siguientes componentes:
1. Protégé 5.5.0.
2. Python 3.10.
3. Librería de Owlready2 de Python.
4. Librería de CSV de Python.
5. Java 8.0.
6. Entorno Eclipse IDE 2022-12 (recomendable).


## Se encuentra separado por:

1. Sistema escalable basado en Python.
2. Sistema escalable basado en Java.
3. Carpeta con las diferentes cargas para probar con cantidades de individuos de 10 a 400.

## Para ejecutar el sistema escalable basado en Python:

1. Copiamos dentro de la carpeta Python los archivos ontologia_vulnerabilidades.owl (ontología vacía sin individuos) y el archivo population_individuals.csv (carga de los individuos) de una de las pruebas que queramos hacer. Por ejemplo, si queremos hacer la prueba de 10 individuos copiariamos los archivos de dentro de la carpeta Cargas/10 Individuos.
2. Abrimos una terminal de comandos en el directorio de la carpeta Python.
3. Ejecutamos el comando "python populating.py".
4. Se puede comprobar como la ejecución devuelve el tiempo en segundos que ha tardado, y si se vuelve a abrir el archivo Python/ontologia_vulnerabilidades.owl veremos como la ontología tiene ya tanto los indiviuos cargados, como inferidos en las clases correspondientes.

## Para ejecutar el sistema escalable basado en Java:

1. Importamos en un entorno como Eclipse, el proyecto que se encuentra en la ruta Java/ontologia_vulnerabilidades.
2. Modificamos las siguientes rutas del proyecto:
	* En la línea 40, definir la ruta absoluta del Java\Origen\ontologia_vulnerabilidades.owl (ontología vacía) en la variable pathOntologia_origen.
	* En la línea 41, definir la ruta absoluta del Java\Destino\ontologia_vulnerabilidades_java.owl (ontología que se carga al final del sistema escalable) en la variable pathOntologia_destino.
	* En la línea 99, definir la ruta absoluta del Java\Origen\population_empresas_paises.csv (carga de datos CSV de empresas y paises) en la variable archCSV.
	* En la línea 126, definir la ruta absoluta del Java\Origen\population_individuals.csv (carga de datos CSV de CVE y ATT) en la variable archCSV.
3. Una vez definidas todas estas rutas, ahora sí, volvemos a copiar los archivos  ontologia_vulnerabilidades.owl (ontología vacía sin individuos) y  el archivo population_individuals.csv (carga de los individuos) dentro de la ruta Java/Origen. Por ejemplo, si queremos hacer la prueba de 10 individuos copiariamos  los archivos de dentro de la carpeta Cargas/10 Individuos.
4. Finalmente, ejecutamos la clase de Java desde el propio Eclipse, y en la consola nos enseñará tanto el estado del sistema (True, va todo bien), el tipo de razonador usado (de base se usará Hermit) y por último el tiempo de ejecución en milisengudos. En la ruta Java/Destino/ontologia_vulnerabilidades_java.owl veremos como se encuentra la ontología ya cargada con los individuos inferidos en las clases.
