# ExifCheck

Herramienta web para analizar **todos los metadatos de una imagen localmente en el navegador**: EXIF, GPS, IPTC, XMP, perfiles ICC, chunks PNG y MakerNotes. La imagen nunca sale del dispositivo del usuario.

Parte del portfolio [`tools-cybersecurity`](../CONVENTIONS.md), pensada para periodistas y defensores de derechos humanos que necesitan saber qué revela una foto o captura de pantalla **antes** de publicarla o compartirla — o qué revela una imagen que recibieron.

## Por qué

Los visores de EXIF online obligan a subir la imagen a un servidor ajeno. Para una foto de una fuente, o una captura con información sensible, eso es inaceptable. ExifCheck:

- Corre **100% en el navegador** (ExifReader vendored, sin CDN).
- **No tiene backend.** Sin subida, sin telemetría, sin analytics.
- **Funciona offline** una vez cargada la página.
- La única petición externa posible es abrir coordenadas GPS en OpenStreetMap, y solo tras una **confirmación explícita** que avisa de que los datos salen del dispositivo.

## Qué hace

### 1. Veredicto de riesgo primero

Antes del volcado completo, un resumen con severidades de **qué revela la imagen**:

| Categoría | Severidad | Ejemplos |
|---|---|---|
| Ubicación precisa | CRÍTICO | GPS lat/lon/altitud, rumbo de cámara, campos IPTC de lugar |
| Nombres / identidad | ALTO | Artist, CameraOwnerName, By-line, Copyright |
| Números de serie e IDs únicos | ALTO | BodySerialNumber, LensSerialNumber, ImageUniqueID, DocumentID |
| Datos ocultos tras el final de la imagen | ALTO | trailer bytes (p. ej. Samsung Motion Photo: vídeo con audio incrustado) |
| Dispositivo | MEDIO | Make, Model, LensModel, HostComputer |
| Fechas y horas | MEDIO | DateTimeOriginal, fechas GPS (UTC), tIME |
| Comentarios / descripciones | MEDIO | UserComment, ImageDescription, chunks tEXt |
| Miniatura incrustada | MEDIO | thumbnail EXIF que puede mostrar el original **sin recortar** |
| Rastro de software | BAJO | Software, CreatorTool, historial XMP |

La miniatura incrustada se **extrae y se muestra junto a la imagen** para compararlas — en imágenes editadas suele conservar la versión previa al recorte.

### 2. Inteligencia de capturas de pantalla

Las capturas llevan poco EXIF clásico, así que ExifCheck aplica una capa de inferencia, siempre etiquetada `INFERIDO` (u `OBSERVADO` cuando el propio SO lo marcó):

- **Patrón del nombre de archivo** → SO (Android/macOS/Windows/GNOME), fecha y hora, y en Android **la app que estaba en pantalla** (`Screenshot_20260715-101530_Signal.png` → Signal).
- **Dimensiones exactas** contra una tabla de ~50 pantallas nativas (iPhone/iPad/Android/Mac/Surface…) → candidatos de dispositivo, con honestidad cuando hay varios.
- Marcador del SO (macOS escribe `UserComment=Screenshot` en XMP), densidad HiDPI, patrones de WhatsApp/Telegram (que eliminan metadatos al reenviar).

### 3. Copia limpia (sin pérdida)

Botón para descargar una copia **byte a byte sin metadatos**: se eliminan segmentos APP/COM (JPEG), chunks no esenciales (PNG), chunks EXIF/XMP/ICCP (WebP, con patch de flags VP8X) y cualquier **dato oculto tras el final de la imagen**. Sin recompresión: píxeles idénticos. Después de limpiar, la copia se **re-analiza con el mismo motor** y se muestra cuántos campos sensibles quedan (debe ser 0).

Si la estructura interna del archivo no es la esperada, la herramienta **se niega a generar la copia** en vez de entregar un archivo truncado.

v0.1 limpia JPEG, PNG y WebP. Otros formatos: mensaje honesto de no soportado con alternativa manual.

### 4. Extras forenses

- **Magic bytes vs extensión**: avisa si un `.jpg` es en realidad otra cosa.
- Volcado completo agrupado y filtrable de todos los campos, con los sensibles marcados por color.
- **Export JSON** del informe completo (veredicto + inferencias + todos los campos).

## Formatos soportados (análisis)

JPEG, PNG, HEIC/HEIF, WebP, TIFF (+ RAW basados en TIFF), AVIF, GIF. SVG y desconocidos: solo identificación por magic bytes.

## Límites honestos

- Lee **metadatos**, no píxeles: no ve caras, documentos ni reflejos, y no detecta esteganografía.
- Las inferencias de capturas son heurísticas — pistas, no hechos.
- La copia limpia elimina también el perfil de color (en imágenes de gama amplia el color puede variar ligeramente).
- Un adversario puede editar metadatos: su ausencia o contenido no prueba nada por sí solo.

## Stack

HTML/CSS/JS estático, sin frameworks. [ExifReader](https://github.com/mattiasw/ExifReader) 4.41.0 (MPL-2.0) vendored sin modificar. Diseño ARGUS (node design system, vendored). CSP estricta: `connect-src 'none'`, sin inline scripts/styles. Trilingüe ES/EN/DE (alemán en Du).

## Desarrollo local

```bash
python3 -m http.server 8794 --directory .
# → http://localhost:8794
```

## Deploy

Cloudflare Pages → `exifcheck.c-lab.tools` (pendiente). Los headers de seguridad viven en `_headers`.
