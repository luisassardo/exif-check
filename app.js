/*
 * ExifCheck: client-side image metadata analysis.
 * No network calls. No telemetry. Source is auditable.
 * Parsing: ExifReader (vendored, MPL-2.0, unmodified).
 */
(function () {
  'use strict';

  var VERSION = '0.1.0';

  // The engine (parsing, verdict, screenshot inference, cleaners) lives in
  // exif-core.js so the J-LAB desk runs exactly the same code natively.
  // This page keeps its own rendering and its own three languages.
  var C = window.ExifCore;
  var formatBytes = C.formatBytes;
  var sniffFormat = C.sniffFormat;
  var jpegImageEnd = C.jpegImageEnd;
  var pngImageEnd = C.pngImageEnd;
  var detectTrailer = C.detectTrailer;
  var SENSITIVE = C.SENSITIVE;
  var CAT_SEV = C.CAT_SEV;
  var CAT_LABEL_KEY = C.CAT_LABEL_KEY;
  var tagDescription = C.tagDescription;
  var buildVerdict = C.buildVerdict;
  var DEVICE_SCREENS = C.DEVICE_SCREENS;
  var inferScreenshot = C.inferScreenshot;
  var parseModel = C.parseModel;
  var toDMS = C.toDMS;
  var GROUP_LABELS = C.GROUP_LABELS;
  var SENSITIVE_FLAT = C.SENSITIVE_FLAT;
  var CLEANABLE = C.CLEANABLE;
  var jsonSafeValue = C.jsonSafeValue;
  var JPEG_KEEP_APP = C.JPEG_KEEP_APP;
  var cleanJpeg = C.cleanJpeg;
  var PNG_KEEP = C.PNG_KEEP;
  var cleanPng = C.cleanPng;
  var cleanWebp = C.cleanWebp;


  // ---------- i18n ----------
  var STRINGS = {
    es: {
      title: 'ExifCheck',
      subtitle: 'Analiza los metadatos de una imagen sin subirla a ningún servidor.',
      eyebrow: 'C-LAB · Herramienta · metadatos de imágenes',
      tagline: 'Mira todo lo que una imagen dice de ti, antes que lo vea otra persona.',
      lead: 'ExifCheck lee todos los campos de metadatos de una foto o captura de pantalla enteramente en tu navegador: ubicación, dispositivo, números de serie, nombres, fechas, software de edición, miniaturas ocultas. La imagen nunca sale de tu dispositivo, y puedes descargar una copia limpia sin nada de eso.',
      devtools_note: 'Funciona 100% en tu navegador. Abre DevTools → Red y compruébalo: cero peticiones al analizar.',
      devtools_note_short: 'ExifReader (vendored) · procesado en el dispositivo',
      zero_requests: '0 PETICIONES',
      local_no_upload: 'LOCAL · SIN SUBIDA',
      about_clab: 'Sobre C-LAB',
      ops_label: 'Analizar una imagen',
      feat1_t: 'Solo local',
      feat1_d: 'La imagen se lee en memoria y nunca se sube. Ningún servidor toca tus datos.',
      feat2_t: 'Veredicto primero',
      feat2_d: 'Un resumen de lo que la imagen revela (ubicación, dispositivo, identidad) antes del volcado completo de campos.',
      feat3_t: 'Inteligencia de capturas',
      feat3_d: 'Las capturas de pantalla llevan poco EXIF clásico, así que ExifCheck infiere dispositivo, sistema y hora a partir de dimensiones, chunks y nombre de archivo, siempre marcado como inferencia.',
      feat4_t: 'Copia limpia',
      feat4_d: 'Borrado de metadatos sin pérdida para JPEG, PNG y WebP: mismos píxeles, cero metadatos, verificado después de limpiar.',
      about_summary: '¿Cómo funciona y por qué confiar en esta herramienta?',
      drop_primary: 'Arrastra una imagen aquí',
      drop_secondary: 'o',
      choose_file: 'Elegir imagen',
      drop_note: 'JPEG, PNG, HEIC, WebP, TIFF, AVIF, GIF. Se procesa enteramente en tu navegador: nunca sale de tu dispositivo.',
      file: 'Archivo:',
      size: 'Tamaño:',
      format: 'Formato:',
      dimensions: 'Píxeles:',
      preview_cap: 'imagen mostrada',
      thumb_cap: 'MINIATURA INCRUSTADA',
      thumb_note: '⚠ Esta imagen lleva dentro una miniatura EXIF separada. En imágenes editadas o recortadas, la miniatura puede seguir mostrando la versión original sin recortar. Compárala con la imagen mostrada.',
      verdict_label: 'Qué revela esta imagen',
      verdict_clean: 'Sin metadatos identificadores evidentes.',
      verdict_clean_note: 'No se encontró ubicación, números de serie, nombres ni marcas de dispositivo en los metadatos.',
      verdict_scope: 'ExifCheck solo lee metadatos. No ve caras, documentos o reflejos en los píxeles, y no detecta esteganografía.',
      sev_critical: 'CRÍTICO',
      sev_high: 'ALTO',
      sev_medium: 'MEDIO',
      sev_low: 'BAJO',
      v_location: 'Ubicación precisa',
      v_identity: 'Nombres / identidad',
      v_serial: 'Números de serie e IDs únicos',
      v_device: 'Dispositivo',
      v_time: 'Fechas y horas',
      v_software: 'Rastro de software',
      v_comment: 'Comentarios y descripciones',
      v_thumb: 'Miniatura incrustada (posible original sin recortar)',
      v_trailer: 'Datos ocultos tras el final de la imagen',
      v_trailer_d: 'bytes después del final de la imagen: puede ser vídeo incrustado (p. ej. Samsung Motion Photo, con audio del momento) u otros datos.',
      gps_label: 'Ubicación (GPS)',
      gps_decimal: 'Decimal',
      gps_dms: 'GMS',
      gps_alt: 'Altitud',
      gps_dir: 'Rumbo de la cámara',
      gps_speed: 'Velocidad',
      gps_ts: 'Hora GPS (UTC)',
      copy_coords: 'Copiar coordenadas',
      copied: 'Copiado',
      open_map: 'Abrir en OpenStreetMap…',
      map_warning: 'Esto abre openstreetmap.org en una pestaña nueva y le envía las coordenadas. Es la única acción de esta herramienta que sale de tu dispositivo, y solo ocurre si confirmas.',
      map_confirm: 'Abrir el mapa (petición externa)',
      map_cancel: 'Cancelar',
      shot_label: 'Análisis de captura de pantalla',
      shot_hint: 'Las capturas llevan poco EXIF clásico. Todo lo de abajo se infiere de evidencia indirecta y está marcado como tal: trátalo como pista, no como hecho.',
      inferred: 'INFERIDO',
      observed: 'OBSERVADO',
      evidence: 'evidencia',
      shot_dims: 'El tamaño {w}×{h} px coincide exactamente con la pantalla nativa de: {d}',
      shot_dims_multi: 'Varios candidatos: el tamaño de píxeles no identifica un único dispositivo.',
      shot_fname_os: 'El nombre del archivo sigue el patrón de capturas de {os}',
      shot_fname_ts: 'Hecha el {ts} (según el nombre del archivo: editable, no confiable)',
      shot_fname_app: 'La app en pantalla al capturar era: {app}',
      shot_whatsapp: 'Nombre con patrón de WhatsApp: pasó por WhatsApp, que elimina metadatos al enviar. El original tenía más información.',
      shot_telegram: 'Nombre con patrón de Telegram: pasó por Telegram, que elimina metadatos al enviar.',
      shot_oscomment: 'El propio sistema la marcó como captura de pantalla ({src})',
      shot_hidpi: 'Densidad {dpi} ppp: captura HiDPI (pantalla Retina / alta densidad)',
      shot_noexif_png: 'PNG sin metadatos de cámara: consistente con una captura de pantalla o una exportación, no con una foto directa',
      dump_label: 'Todos los campos de metadatos',
      filter_ph: 'Filtrar campos…',
      fields: 'campos',
      no_meta: 'Este archivo no contiene metadatos legibles, o el formato no está soportado para análisis.',
      format_mismatch: '⚠ La extensión dice {ext} pero el contenido real es {real}. Desconfía de archivos que mienten sobre su formato.',
      parse_error: 'No se pudieron leer metadatos de este archivo.',
      clean_label: 'Copia limpia',
      clean_hint: 'Genera una copia byte a byte sin metadatos: mismos píxeles, sin recompresión ni pérdida de calidad. Se elimina también el perfil de color, así que en imágenes de gama amplia el color puede variar ligeramente.',
      clean_btn: 'Descargar copia limpia',
      export_json: 'Exportar informe (JSON)',
      clean_unsupported: 'La limpieza sin pérdida no está disponible para {fmt} en v0.1. Convierte primero a JPEG o PNG (p. ej. exportando desde Vista Previa) y vuelve a pasarla por aquí.',
      clean_removed: 'Eliminado:',
      clean_trailer: '{n} bytes de datos tras el final de la imagen',
      clean_verified: '✓ Re-verificado sobre la copia limpia: {n} campos sensibles restantes.',
      clean_failed: 'La estructura interna del archivo no es la esperada: no se generó la copia para evitar entregarte un archivo dañado. Re-exporta la imagen y vuelve a intentarlo.',
      clean_nothing: 'No había segmentos de metadatos que eliminar.',
      analyze_another: 'Analizar otra imagen',
      textchunks: 'chunks de texto'
    },
    en: {
      title: 'ExifCheck',
      subtitle: 'Analyze an image’s metadata without uploading it to any server.',
      eyebrow: 'C-LAB · Tool · image metadata',
      tagline: 'See everything an image says about you, before someone else does.',
      lead: 'ExifCheck reads every metadata field of a photo or screenshot entirely in your browser: location, device, serial numbers, names, timestamps, editing software, hidden thumbnails. The image never leaves your device, and you can download a clean copy with everything stripped.',
      devtools_note: 'Runs 100% in your browser. Open DevTools → Network and watch: zero requests when you analyze.',
      devtools_note_short: 'ExifReader (vendored) · processed on-device',
      zero_requests: '0 REQUESTS',
      local_no_upload: 'LOCAL · NO UPLOAD',
      about_clab: 'About C-LAB',
      ops_label: 'Analyze an image',
      feat1_t: 'Local-only',
      feat1_d: 'The image is read in-memory and never uploaded. No server touches your data.',
      feat2_t: 'Risk verdict first',
      feat2_d: 'A summary of what the image reveals (location, device, identity) before the full field dump.',
      feat3_t: 'Screenshot intelligence',
      feat3_d: 'Screenshots carry little classic EXIF, so ExifCheck infers device, OS and time from dimensions, chunks and filename, always labeled as inference.',
      feat4_t: 'Clean copy',
      feat4_d: 'Lossless metadata stripping for JPEG, PNG and WebP: same pixels, zero metadata, verified after cleaning.',
      about_summary: 'How does it work, and why trust this tool?',
      drop_primary: 'Drop an image here',
      drop_secondary: 'or',
      choose_file: 'Choose image',
      drop_note: 'JPEG, PNG, HEIC, WebP, TIFF, AVIF, GIF. Processed entirely in your browser: it never leaves your device.',
      file: 'File:',
      size: 'Size:',
      format: 'Format:',
      dimensions: 'Pixels:',
      preview_cap: 'image as displayed',
      thumb_cap: 'EMBEDDED THUMBNAIL',
      thumb_note: '⚠ This image carries a separate EXIF thumbnail inside. On edited or cropped images, the thumbnail can still show the original, uncropped version. Compare it against the displayed image.',
      verdict_label: 'What this image reveals',
      verdict_clean: 'No obvious identifying metadata.',
      verdict_clean_note: 'No location, serial numbers, names or device marks were found in the metadata.',
      verdict_scope: 'ExifCheck reads metadata only. It cannot see faces, documents or reflections in the pixels, and it does not detect steganography.',
      sev_critical: 'CRITICAL',
      sev_high: 'HIGH',
      sev_medium: 'MEDIUM',
      sev_low: 'LOW',
      v_location: 'Precise location',
      v_identity: 'Names / identity',
      v_serial: 'Serial numbers & unique IDs',
      v_device: 'Device',
      v_time: 'Dates & times',
      v_software: 'Software trail',
      v_comment: 'Comments & descriptions',
      v_thumb: 'Embedded thumbnail (possible uncropped original)',
      v_trailer: 'Hidden data after end of image',
      v_trailer_d: 'bytes after the end of the image: may be embedded video (e.g. Samsung Motion Photo, with the audio of the moment) or other data.',
      gps_label: 'Location (GPS)',
      gps_decimal: 'Decimal',
      gps_dms: 'DMS',
      gps_alt: 'Altitude',
      gps_dir: 'Camera bearing',
      gps_speed: 'Speed',
      gps_ts: 'GPS time (UTC)',
      copy_coords: 'Copy coordinates',
      copied: 'Copied',
      open_map: 'Open in OpenStreetMap…',
      map_warning: 'This opens openstreetmap.org in a new tab and sends it the coordinates. It is the only action in this tool that leaves your device, and it only happens if you confirm.',
      map_confirm: 'Open the map (external request)',
      map_cancel: 'Cancel',
      shot_label: 'Screenshot analysis',
      shot_hint: 'Screenshots carry little classic EXIF. Everything below is inferred from indirect evidence and labeled as such: treat it as a lead, not a fact.',
      inferred: 'INFERRED',
      observed: 'OBSERVED',
      evidence: 'evidence',
      shot_dims: 'The {w}×{h} px size exactly matches the native screen of: {d}',
      shot_dims_multi: 'Several candidates: pixel size alone does not identify a single device.',
      shot_fname_os: 'The filename follows the {os} screenshot naming pattern',
      shot_fname_ts: 'Taken {ts} (from the filename: editable, not reliable)',
      shot_fname_app: 'The app on screen when captured was: {app}',
      shot_whatsapp: 'WhatsApp-pattern filename: it passed through WhatsApp, which strips metadata on send. The original carried more information.',
      shot_telegram: 'Telegram-pattern filename: it passed through Telegram, which strips metadata on send.',
      shot_oscomment: 'The operating system itself marked it as a screenshot ({src})',
      shot_hidpi: '{dpi} DPI density: HiDPI capture (Retina / high-density screen)',
      shot_noexif_png: 'PNG with no camera metadata: consistent with a screenshot or an export, not a direct photo',
      dump_label: 'All metadata fields',
      filter_ph: 'Filter fields…',
      fields: 'fields',
      no_meta: 'This file contains no readable metadata, or the format is not supported for analysis.',
      format_mismatch: '⚠ The extension says {ext} but the actual content is {real}. Distrust files that lie about their format.',
      parse_error: 'Could not read metadata from this file.',
      clean_label: 'Clean copy',
      clean_hint: 'Generates a byte-level copy with no metadata: same pixels, no recompression, no quality loss. The color profile is removed too, so wide-gamut images may shift color slightly.',
      clean_btn: 'Download clean copy',
      export_json: 'Export report (JSON)',
      clean_unsupported: 'Lossless cleaning is not available for {fmt} in v0.1. Convert to JPEG or PNG first (e.g. export from Preview), then run it through here again.',
      clean_removed: 'Removed:',
      clean_trailer: '{n} bytes of data after the end of the image',
      clean_verified: '✓ Re-checked on the clean copy: {n} sensitive fields remaining.',
      clean_failed: 'The file’s internal structure is not as expected: no copy was generated, to avoid handing you a broken file. Re-export the image and try again.',
      clean_nothing: 'There were no metadata segments to remove.',
      analyze_another: 'Analyze another image',
      textchunks: 'text chunks'
    },
    de: {
      title: 'ExifCheck',
      subtitle: 'Analysiere die Metadaten eines Bildes, ohne es auf einen Server hochzuladen.',
      eyebrow: 'C-LAB · Tool · Bild-Metadaten',
      tagline: 'Sieh alles, was ein Bild über dich verrät, bevor es jemand anders sieht.',
      lead: 'ExifCheck liest jedes Metadaten-Feld eines Fotos oder Screenshots komplett in deinem Browser: Standort, Gerät, Seriennummern, Namen, Zeitstempel, Bearbeitungssoftware, versteckte Vorschaubilder. Das Bild verlässt nie dein Gerät, und du kannst eine bereinigte Kopie ohne all das herunterladen.',
      devtools_note: 'Läuft zu 100% in deinem Browser. Öffne DevTools → Netzwerk und prüf es: null Anfragen beim Analysieren.',
      devtools_note_short: 'ExifReader (vendored) · auf dem Gerät verarbeitet',
      zero_requests: '0 ANFRAGEN',
      local_no_upload: 'LOKAL · KEIN UPLOAD',
      about_clab: 'Über C-LAB',
      ops_label: 'Bild analysieren',
      feat1_t: 'Nur lokal',
      feat1_d: 'Das Bild wird im Speicher gelesen und nie hochgeladen. Kein Server berührt deine Daten.',
      feat2_t: 'Erst das Urteil',
      feat2_d: 'Eine Zusammenfassung dessen, was das Bild preisgibt (Standort, Gerät, Identität) vor der vollständigen Feldliste.',
      feat3_t: 'Screenshot-Intelligenz',
      feat3_d: 'Screenshots tragen wenig klassisches EXIF, deshalb leitet ExifCheck Gerät, System und Zeit aus Abmessungen, Chunks und Dateinamen ab, immer als Schlussfolgerung markiert.',
      feat4_t: 'Bereinigte Kopie',
      feat4_d: 'Verlustfreies Entfernen von Metadaten für JPEG, PNG und WebP: gleiche Pixel, null Metadaten, nach der Bereinigung verifiziert.',
      about_summary: 'Wie funktioniert das, und warum diesem Tool vertrauen?',
      drop_primary: 'Zieh ein Bild hierher',
      drop_secondary: 'oder',
      choose_file: 'Bild wählen',
      drop_note: 'JPEG, PNG, HEIC, WebP, TIFF, AVIF, GIF. Wird komplett in deinem Browser verarbeitet: es verlässt nie dein Gerät.',
      file: 'Datei:',
      size: 'Größe:',
      format: 'Format:',
      dimensions: 'Pixel:',
      preview_cap: 'angezeigtes Bild',
      thumb_cap: 'EINGEBETTETES VORSCHAUBILD',
      thumb_note: '⚠ Dieses Bild trägt ein separates EXIF-Vorschaubild in sich. Bei bearbeiteten oder zugeschnittenen Bildern kann das Vorschaubild noch die originale, unbeschnittene Version zeigen. Vergleich es mit dem angezeigten Bild.',
      verdict_label: 'Was dieses Bild preisgibt',
      verdict_clean: 'Keine offensichtlich identifizierenden Metadaten.',
      verdict_clean_note: 'In den Metadaten wurden weder Standort noch Seriennummern, Namen oder Gerätespuren gefunden.',
      verdict_scope: 'ExifCheck liest nur Metadaten. Es sieht keine Gesichter, Dokumente oder Spiegelungen in den Pixeln und erkennt keine Steganografie.',
      sev_critical: 'KRITISCH',
      sev_high: 'HOCH',
      sev_medium: 'MITTEL',
      sev_low: 'NIEDRIG',
      v_location: 'Genauer Standort',
      v_identity: 'Namen / Identität',
      v_serial: 'Seriennummern & eindeutige IDs',
      v_device: 'Gerät',
      v_time: 'Datum & Uhrzeit',
      v_software: 'Software-Spur',
      v_comment: 'Kommentare & Beschreibungen',
      v_thumb: 'Eingebettetes Vorschaubild (möglicherweise unbeschnittenes Original)',
      v_trailer: 'Versteckte Daten nach dem Bildende',
      v_trailer_d: 'Bytes nach dem Ende des Bildes: kann eingebettetes Video sein (z. B. Samsung Motion Photo, mit dem Ton des Moments) oder andere Daten.',
      gps_label: 'Standort (GPS)',
      gps_decimal: 'Dezimal',
      gps_dms: 'GMS',
      gps_alt: 'Höhe',
      gps_dir: 'Kamerarichtung',
      gps_speed: 'Geschwindigkeit',
      gps_ts: 'GPS-Zeit (UTC)',
      copy_coords: 'Koordinaten kopieren',
      copied: 'Kopiert',
      open_map: 'In OpenStreetMap öffnen…',
      map_warning: 'Das öffnet openstreetmap.org in einem neuen Tab und übermittelt die Koordinaten. Es ist die einzige Aktion dieses Tools, die dein Gerät verlässt, und nur, wenn du bestätigst.',
      map_confirm: 'Karte öffnen (externe Anfrage)',
      map_cancel: 'Abbrechen',
      shot_label: 'Screenshot-Analyse',
      shot_hint: 'Screenshots tragen wenig klassisches EXIF. Alles unten ist aus indirekten Hinweisen abgeleitet und entsprechend markiert: behandle es als Spur, nicht als Fakt.',
      inferred: 'ABGELEITET',
      observed: 'BEOBACHTET',
      evidence: 'Beleg',
      shot_dims: 'Die Größe {w}×{h} px entspricht exakt dem nativen Bildschirm von: {d}',
      shot_dims_multi: 'Mehrere Kandidaten: die Pixelgröße allein identifiziert kein einzelnes Gerät.',
      shot_fname_os: 'Der Dateiname folgt dem Screenshot-Muster von {os}',
      shot_fname_ts: 'Aufgenommen {ts} (laut Dateiname: änderbar, nicht verlässlich)',
      shot_fname_app: 'Die App auf dem Bildschirm bei der Aufnahme war: {app}',
      shot_whatsapp: 'WhatsApp-Muster im Dateinamen: es lief durch WhatsApp, das beim Senden Metadaten entfernt. Das Original trug mehr Informationen.',
      shot_telegram: 'Telegram-Muster im Dateinamen: es lief durch Telegram, das beim Senden Metadaten entfernt.',
      shot_oscomment: 'Das Betriebssystem selbst hat es als Screenshot markiert ({src})',
      shot_hidpi: '{dpi} DPI: HiDPI-Aufnahme (Retina- / hochauflösender Bildschirm)',
      shot_noexif_png: 'PNG ohne Kamera-Metadaten: passt zu einem Screenshot oder Export, nicht zu einem direkten Foto',
      dump_label: 'Alle Metadaten-Felder',
      filter_ph: 'Felder filtern…',
      fields: 'Felder',
      no_meta: 'Diese Datei enthält keine lesbaren Metadaten, oder das Format wird nicht unterstützt.',
      format_mismatch: '⚠ Die Endung sagt {ext}, aber der tatsächliche Inhalt ist {real}. Misstraue Dateien, die über ihr Format lügen.',
      parse_error: 'Aus dieser Datei konnten keine Metadaten gelesen werden.',
      clean_label: 'Bereinigte Kopie',
      clean_hint: 'Erzeugt eine Byte-für-Byte-Kopie ohne Metadaten: gleiche Pixel, keine Neukompression, kein Qualitätsverlust. Auch das Farbprofil wird entfernt: bei Wide-Gamut-Bildern kann sich die Farbe leicht verschieben.',
      clean_btn: 'Bereinigte Kopie herunterladen',
      export_json: 'Bericht exportieren (JSON)',
      clean_unsupported: 'Verlustfreie Bereinigung ist für {fmt} in v0.1 nicht verfügbar. Konvertier zuerst zu JPEG oder PNG (z. B. Export aus Vorschau) und lass es dann erneut hier durchlaufen.',
      clean_removed: 'Entfernt:',
      clean_trailer: '{n} Bytes Daten nach dem Bildende',
      clean_verified: '✓ Auf der bereinigten Kopie erneut geprüft: {n} sensible Felder übrig.',
      clean_failed: 'Die interne Struktur der Datei ist nicht wie erwartet: es wurde keine Kopie erzeugt, um dir keine kaputte Datei zu geben. Exportiere das Bild neu und versuch es nochmal.',
      clean_nothing: 'Es gab keine Metadaten-Segmente zu entfernen.',
      analyze_another: 'Anderes Bild analysieren',
      textchunks: 'Text-Chunks'
    }
  };

  var ABOUT_HTML = {
    es: '\
      <p><strong>Cómo funciona.</strong> ExifCheck lee el archivo en memoria y lo analiza con <a href="https://github.com/mattiasw/ExifReader" target="_blank" rel="noopener noreferrer">ExifReader</a>, una biblioteca de código abierto incluida localmente (sin CDN). Extrae EXIF, GPS, IPTC, XMP, perfiles ICC, chunks PNG y MakerNotes, y encima aplica dos capas propias: un <em>veredicto de riesgo</em> (qué campos te identifican) y una <em>capa de inferencia para capturas de pantalla</em>.</p>\
      <p><strong>Por qué confiar.</strong> Los analizadores de EXIF online obligan a subir la imagen a un servidor ajeno, inaceptable para material sensible. Aquí no hay backend, no hay subida, no hay telemetría. Compruébalo: abre DevTools → Red y analiza una imagen; verás cero peticiones. La única excepción, opcional y con confirmación explícita, es abrir coordenadas GPS en OpenStreetMap.</p>\
      <p><strong>Límites honestos.</strong> ExifCheck lee metadatos: no analiza los píxeles (caras, documentos, reflejos), no detecta esteganografía y las inferencias sobre capturas son heurísticas marcadas como INFERIDO. La copia limpia elimina metadatos sin recomprimir, pero quita también el perfil de color; y en v0.1 solo cubre JPEG, PNG y WebP.</p>',
    en: '\
      <p><strong>How it works.</strong> ExifCheck reads the file in memory and parses it with <a href="https://github.com/mattiasw/ExifReader" target="_blank" rel="noopener noreferrer">ExifReader</a>, an open-source library vendored locally (no CDN). It extracts EXIF, GPS, IPTC, XMP, ICC profiles, PNG chunks and MakerNotes, then applies two layers of its own: a <em>risk verdict</em> (which fields identify you) and a <em>screenshot inference layer</em>.</p>\
      <p><strong>Why trust it.</strong> Online EXIF viewers force you to upload the image to someone else’s server, unacceptable for sensitive material. Here there is no backend, no upload, no telemetry. Verify it: open DevTools → Network and analyze an image; you will see zero requests. The only exception, optional and behind an explicit confirmation, is opening GPS coordinates in OpenStreetMap.</p>\
      <p><strong>Honest limits.</strong> ExifCheck reads metadata: it does not analyze pixels (faces, documents, reflections), does not detect steganography, and screenshot inferences are heuristics labeled INFERRED. The clean copy strips metadata without recompressing, but also removes the color profile; and v0.1 covers JPEG, PNG and WebP only.</p>',
    de: '\
      <p><strong>Wie es funktioniert.</strong> ExifCheck liest die Datei im Speicher und analysiert sie mit <a href="https://github.com/mattiasw/ExifReader" target="_blank" rel="noopener noreferrer">ExifReader</a>, einer lokal eingebundenen Open-Source-Bibliothek (kein CDN). Es extrahiert EXIF, GPS, IPTC, XMP, ICC-Profile, PNG-Chunks und MakerNotes und legt zwei eigene Ebenen darüber: ein <em>Risiko-Urteil</em> (welche Felder dich identifizieren) und eine <em>Schlussfolgerungs-Ebene für Screenshots</em>.</p>\
      <p><strong>Warum vertrauen.</strong> Online-EXIF-Viewer zwingen dich, das Bild auf einen fremden Server hochzuladen, inakzeptabel für sensibles Material. Hier gibt es kein Backend, keinen Upload, keine Telemetrie. Prüf es: Öffne DevTools → Netzwerk und analysiere ein Bild; du siehst null Anfragen. Die einzige Ausnahme, optional und hinter einer ausdrücklichen Bestätigung, ist das Öffnen von GPS-Koordinaten in OpenStreetMap.</p>\
      <p><strong>Ehrliche Grenzen.</strong> ExifCheck liest Metadaten: Es analysiert keine Pixel (Gesichter, Dokumente, Spiegelungen), erkennt keine Steganografie, und Screenshot-Schlussfolgerungen sind Heuristiken, markiert als ABGELEITET. Die bereinigte Kopie entfernt Metadaten ohne Neukompression, aber auch das Farbprofil; v0.1 deckt nur JPEG, PNG und WebP ab.</p>'
  };

  var currentLang = 'es';

  function T() { return STRINGS[currentLang]; }
  function fmtT(key, params) {
    var s = T()[key] || key;
    if (params) Object.keys(params).forEach(function (k) { s = s.split('{' + k + '}').join(params[k]); });
    return s;
  }

  function applyLang(lang) {
    currentLang = lang;
    document.documentElement.lang = lang;
    var t = STRINGS[lang];
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      if (key === 'about_body') el.innerHTML = ABOUT_HTML[lang];
      else if (t[key] !== undefined) el.textContent = t[key];
    });
    document.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
      var key = el.getAttribute('data-i18n-ph');
      if (t[key] !== undefined) el.setAttribute('placeholder', t[key]);
    });
    document.title = t.title + ' · ' + t.subtitle.replace(/\.$/, '');
    document.querySelectorAll('.lang-switch button').forEach(function (b) {
      b.classList.toggle('active', b.dataset.lang === lang);
    });
    if (state.model) renderDynamic();
  }

  document.querySelectorAll('.lang-switch button').forEach(function (b) {
    b.addEventListener('click', function () { applyLang(b.dataset.lang); });
  });

  // ---------- helpers ----------
  function $(id) { return document.getElementById(id); }
  function mk(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function downloadBlob(blob, name) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
  }

  // ---------- magic-byte sniffing ----------

  // ---------- verdict engine ----------

  // ---------- screenshot inference ----------

  // ---------- parsing ----------
  var state = { file: null, bytes: null, model: null, previewURL: null, thumbURL: null };


  // ---------- rendering ----------

  function renderVerdict(model) {
    var chips = $('verdict-chips'), list = $('verdict-list');
    chips.innerHTML = ''; list.innerHTML = '';
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    model.verdict.forEach(function (it) { counts[CAT_SEV[it.cat]]++; });

    if (!model.verdict.length) {
      var okChip = mk('span', 'chip ok', '✓ ' + T().verdict_clean);
      chips.appendChild(okChip);
      var li = mk('li', 'v-item ok-note', T().verdict_clean_note);
      list.appendChild(li);
    } else {
      ['critical', 'high', 'medium', 'low'].forEach(function (sev) {
        if (!counts[sev]) return;
        chips.appendChild(mk('span', 'chip ' + sev, counts[sev] + ' ' + T()['sev_' + sev]));
      });
      model.verdict.forEach(function (it) {
        var li = mk('li', 'v-item ' + CAT_SEV[it.cat]);
        li.appendChild(mk('span', 'sev-dot ' + CAT_SEV[it.cat]));
        li.appendChild(mk('strong', '', T()[CAT_LABEL_KEY[it.cat]]));
        var detail = it.detail;
        if (it.trailer) detail = detail + T().v_trailer_d;
        if (detail) li.appendChild(mk('span', 'v-detail mono', detail));
        li.appendChild(mk('span', 'v-src mono', it.source));
        list.appendChild(li);
      });
    }
    var scope = mk('li', 'v-item scope-note', T().verdict_scope);
    list.appendChild(scope);
  }

  function renderGps(model) {
    var sec = $('gps-section');
    if (!model.gps) { sec.classList.add('hidden'); return; }
    sec.classList.remove('hidden');
    var g = model.gps, grid = $('gps-grid');
    grid.innerHTML = '';
    function row(k, v) {
      grid.appendChild(mk('span', 'gps-k', k));
      grid.appendChild(mk('span', 'gps-v', v));
    }
    row(T().gps_decimal, g.lat.toFixed(6) + ', ' + g.lon.toFixed(6));
    row(T().gps_dms, toDMS(g.lat, true) + '  ' + toDMS(g.lon, false));
    if (g.alt !== undefined) row(T().gps_alt, g.alt.toFixed(1) + ' m');
    if (g.dir) row(T().gps_dir, g.dir);
    if (g.speed) row(T().gps_speed, g.speed);
    if (g.ts) row(T().gps_ts, g.ts);
    $('gps-map-link').href = 'https://www.openstreetmap.org/?mlat=' + g.lat.toFixed(6) + '&mlon=' + g.lon.toFixed(6) + '#map=16/' + g.lat.toFixed(6) + '/' + g.lon.toFixed(6);
    $('gps-map-confirm').classList.add('hidden');
    $('gps-map-btn').classList.remove('hidden');
  }

  function renderScreenshot(model) {
    var sec = $('shot-section'), list = $('shot-list');
    if (!model.screenshot.length) { sec.classList.add('hidden'); return; }
    sec.classList.remove('hidden');
    list.innerHTML = '';
    model.screenshot.forEach(function (f) {
      var item = mk('div', 'shot-item');
      item.appendChild(mk('span', 'shot-tag mono ' + f.tag, T()[f.tag]));
      var body = mk('div', 'shot-body');
      var key = { fname_os: 'shot_fname_os', fname_ts: 'shot_fname_ts', fname_app: 'shot_fname_app', whatsapp: 'shot_whatsapp', telegram: 'shot_telegram', oscomment: 'shot_oscomment', dims: 'shot_dims', hidpi: 'shot_hidpi', noexif_png: 'shot_noexif_png' }[f.kind];
      body.appendChild(mk('p', '', fmtT(key, f.params)));
      if (f.multi) body.appendChild(mk('p', 'hint', T().shot_dims_multi));
      body.appendChild(mk('p', 'shot-ev mono', T().evidence + ': ' + f.evidence));
      item.appendChild(body);
      list.appendChild(item);
    });
  }


  function renderDump(model) {
    var wrap = $('dump-groups');
    wrap.innerHTML = '';
    var groupNames = Object.keys(model.groups);
    if (!groupNames.length) {
      wrap.appendChild(mk('p', 'hint', T().no_meta));
      return;
    }
    groupNames.forEach(function (g) {
      var tags = model.groups[g];
      var names = Object.keys(tags);
      if (!names.length) return;
      var det = document.createElement('details');
      det.className = 'dump-group';
      det.open = (g !== 'icc' && names.length <= 40) || g === 'exif';
      var sum = document.createElement('summary');
      sum.className = 'dump-head mono';
      sum.appendChild(mk('span', '', GROUP_LABELS[g] || g));
      sum.appendChild(mk('span', 'dump-count', names.length + ' ' + T().fields));
      det.appendChild(sum);
      var table = mk('div', 'dump-table');
      names.forEach(function (tname) {
        var row = mk('div', 'dump-row');
        var cat = SENSITIVE_FLAT[tname.toLowerCase()];
        var isGpsTag = /^gps/i.test(tname);
        if (cat || isGpsTag) row.classList.add('flagged', (isGpsTag ? 'critical' : CAT_SEV[cat]));
        row.appendChild(mk('span', 'dump-k mono', tname));
        row.appendChild(mk('span', 'dump-v', tagDescription(tags[tname])));
        table.appendChild(row);
      });
      det.appendChild(table);
      wrap.appendChild(det);
    });
    applyDumpFilter();
  }

  function applyDumpFilter() {
    var q = $('dump-filter').value.trim().toLowerCase();
    document.querySelectorAll('#dump-groups .dump-row').forEach(function (row) {
      var hit = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
      row.classList.toggle('hidden', !hit);
    });
    document.querySelectorAll('#dump-groups .dump-group').forEach(function (det) {
      var any = det.querySelectorAll('.dump-row:not(.hidden)').length > 0;
      det.classList.toggle('hidden', !any);
      if (q && any) det.open = true;
    });
  }
  $('dump-filter').addEventListener('input', applyDumpFilter);

  function renderThumb(model) {
    var box = $('thumb-box'), note = $('thumb-note');
    if (state.thumbURL) { URL.revokeObjectURL(state.thumbURL); state.thumbURL = null; }
    if (!model.thumbnail) { box.classList.add('hidden'); note.classList.add('hidden'); return; }
    state.thumbURL = URL.createObjectURL(new Blob([model.thumbnail], { type: 'image/jpeg' }));
    $('thumb-img').src = state.thumbURL;
    box.classList.remove('hidden');
    note.classList.remove('hidden');
  }

  function renderCleaner(model) {
    var btn = $('clean-btn'), hint = $('clean-hint');
    $('clean-result').classList.add('hidden');
    $('clean-result').innerHTML = '';
    if (CLEANABLE[model.format]) {
      btn.disabled = false;
      hint.textContent = T().clean_hint;
    } else {
      btn.disabled = true;
      hint.textContent = fmtT('clean_unsupported', { fmt: model.formatLabel });
    }
  }

  function renderFileInfo(model) {
    $('file-name').textContent = model.name;
    $('file-size').textContent = formatBytes(model.size) + ' (' + model.size.toLocaleString() + ' B)';
    $('file-format').textContent = model.formatLabel;
    $('file-dims').textContent = model.dims ? model.dims.w + ' × ' + model.dims.h + ' px (' + (model.dims.w * model.dims.h / 1e6).toFixed(1) + ' MP)' : '\u2014';
    var warn = $('format-warn');
    var ext = (model.name.split('.').pop() || '').toLowerCase();
    var fmt = sniffFormat(state.bytes);
    if (fmt.id !== 'unknown' && ext && fmt.exts.length && fmt.exts.indexOf(ext) === -1) {
      warn.textContent = fmtT('format_mismatch', { ext: '.' + ext, real: fmt.label });
      warn.classList.remove('hidden');
    } else warn.classList.add('hidden');
    var perr = $('parse-error');
    perr.classList.toggle('hidden', !model.parseError);
    if (model.parseError) perr.textContent = T().parse_error;
  }

  function renderDynamic() {
    var model = state.model;
    renderFileInfo(model);
    renderVerdict(model);
    renderGps(model);
    renderScreenshot(model);
    renderDump(model);
    renderThumb(model);
    renderCleaner(model);
  }

  // ---------- file intake ----------
  var dropZone = $('drop-zone'), fileInput = $('file-input');

  function setFile(file) {
    state.file = file;
    var reader = new FileReader();
    reader.onload = function () {
      state.bytes = new Uint8Array(reader.result);
      state.model = parseModel(state.bytes, file.name, file.size);
      if (state.previewURL) URL.revokeObjectURL(state.previewURL);
      state.previewURL = URL.createObjectURL(file);
      var img = $('preview-img');
      img.classList.remove('hidden');
      img.onload = function () {
        // authoritative dimensions if the container didn't say
        if (!state.model.dims && img.naturalWidth) {
          state.model.dims = { w: img.naturalWidth, h: img.naturalHeight };
          state.model.screenshot = inferScreenshot(state.model, state.model.name);
          renderDynamic();
        }
      };
      img.onerror = function () { img.classList.add('hidden'); };
      img.src = state.previewURL;
      $('analysis').classList.remove('hidden');
      dropZone.classList.add('hidden');
      renderDynamic();
    };
    reader.readAsArrayBuffer(file);
  }

  fileInput.addEventListener('change', function (e) {
    if (e.target.files[0]) setFile(e.target.files[0]);
  });
  ['dragenter', 'dragover'].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.remove('dragover'); });
  });
  dropZone.addEventListener('drop', function (e) {
    var f = e.dataTransfer.files[0];
    if (f) setFile(f);
  });

  $('reset-btn').addEventListener('click', function () {
    state.file = null; state.bytes = null; state.model = null;
    if (state.previewURL) { URL.revokeObjectURL(state.previewURL); state.previewURL = null; }
    if (state.thumbURL) { URL.revokeObjectURL(state.thumbURL); state.thumbURL = null; }
    fileInput.value = '';
    $('dump-filter').value = '';
    $('analysis').classList.add('hidden');
    dropZone.classList.remove('hidden');
  });

  // ---------- GPS actions ----------
  $('gps-copy').addEventListener('click', function () {
    if (!state.model || !state.model.gps) return;
    var g = state.model.gps;
    navigator.clipboard.writeText(g.lat.toFixed(6) + ', ' + g.lon.toFixed(6)).then(function () {
      var btn = $('gps-copy');
      btn.textContent = T().copied;
      setTimeout(function () { btn.textContent = T().copy_coords; }, 1500);
    });
  });
  $('gps-map-btn').addEventListener('click', function () {
    $('gps-map-confirm').classList.remove('hidden');
    $('gps-map-btn').classList.add('hidden');
  });
  $('gps-map-cancel').addEventListener('click', function () {
    $('gps-map-confirm').classList.add('hidden');
    $('gps-map-btn').classList.remove('hidden');
  });

  // ---------- export ----------
  $('export-btn').addEventListener('click', function () {
    var m = state.model;
    if (!m) return;
    var meta = {};
    Object.keys(m.groups).forEach(function (g) {
      meta[g] = {};
      Object.keys(m.groups[g]).forEach(function (t) {
        meta[g][t] = { description: tagDescription(m.groups[g][t]), value: jsonSafeValue(m.groups[g][t].value) };
      });
    });
    var payload = {
      tool: 'exifcheck/' + VERSION,
      generated_utc: new Date().toISOString(),
      file: { name: m.name, size_bytes: m.size, format_magic: m.formatLabel, dimensions: m.dims },
      verdict: m.verdict.map(function (it) { return { severity: CAT_SEV[it.cat], category: it.cat, detail: it.detail, source: it.source }; }),
      gps: m.gps,
      screenshot_inference: m.screenshot.map(function (f) { return { kind: f.kind, params: f.params, evidence: f.evidence, confidence: f.tag }; }),
      trailer: m.trailer,
      has_embedded_thumbnail: !!m.thumbnail,
      metadata: meta
    };
    downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), 'exifcheck-' + m.name.replace(/\.[^.]+$/, '') + '.json');
  });

  // ---------- cleaner ----------

  $('clean-btn').addEventListener('click', function () {
    var m = state.model, b = state.bytes;
    if (!m || !b || !CLEANABLE[m.format]) return;
    var res;
    if (m.format === 'jpeg') res = cleanJpeg(b);
    else if (m.format === 'png') res = cleanPng(b);
    else res = cleanWebp(b);

    if (!res.ok) {
      var errBox = $('clean-result');
      errBox.innerHTML = '';
      errBox.classList.remove('hidden');
      errBox.appendChild(mk('p', 'clean-verified warn', T().clean_failed));
      return;
    }

    var totalLen = 0;
    res.parts.forEach(function (p) { totalLen += p.length; });
    var clean = new Uint8Array(totalLen), off = 0;
    res.parts.forEach(function (p) { clean.set(p, off); off += p.length; });

    var trailerBytes = m.trailer ? m.trailer.bytes : 0;

    // re-verify the cleaned bytes with the same engine
    var after = parseModel(clean, m.name, clean.length);
    var leftovers = after.verdict.length;

    var box = $('clean-result');
    box.innerHTML = '';
    box.classList.remove('hidden');
    if (!res.removed.length && !trailerBytes) {
      box.appendChild(mk('p', 'hint', T().clean_nothing));
    } else {
      var parts = res.removed.map(function (r) { return r.label + ' (' + formatBytes(r.bytes) + ')'; });
      // collapse repeated PNG text chunk labels
      if (m.format === 'png') {
        var counts = {};
        res.removed.forEach(function (r) { counts[r.label] = (counts[r.label] || 0) + 1; });
        parts = Object.keys(counts).map(function (k) { return counts[k] > 1 ? counts[k] + '× ' + k : k; });
      }
      if (trailerBytes) parts.push(fmtT('clean_trailer', { n: trailerBytes.toLocaleString() }));
      box.appendChild(mk('p', 'clean-removed mono', T().clean_removed + ' ' + parts.join(' · ')));
    }
    var verified = mk('p', 'clean-verified ' + (leftovers ? 'warn' : 'ok'), fmtT('clean_verified', { n: leftovers }));
    box.appendChild(verified);

    var mime = { jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' }[m.format];
    var base = m.name.replace(/\.[^.]+$/, ''), ext = (m.name.match(/\.[^.]+$/) || ['.' + m.format])[0];
    downloadBlob(new Blob([clean], { type: mime }), base + '.clean' + ext);
  });

  // ---------- init ----------
  var browserLang = (navigator.language || 'es').toLowerCase().slice(0, 2);
  applyLang(STRINGS[browserLang] ? browserLang : 'es');
})();
