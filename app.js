/*
 * ExifCheck: client-side image metadata analysis.
 * No network calls. No telemetry. Source is auditable.
 * Parsing: ExifReader (vendored, MPL-2.0, unmodified).
 */
(function () {
  'use strict';

  var VERSION = '0.1.0';

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
  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    var units = ['KB', 'MB', 'GB'], v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[i];
  }
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
  function sniffFormat(b) {
    function ascii(off, len) {
      var s = '';
      for (var i = off; i < off + len && i < b.length; i++) s += String.fromCharCode(b[i]);
      return s;
    }
    if (b.length > 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return { id: 'jpeg', label: 'JPEG', exts: ['jpg', 'jpeg', 'jpe', 'jfif'] };
    if (b.length > 8 && b[0] === 0x89 && ascii(1, 3) === 'PNG') return { id: 'png', label: 'PNG', exts: ['png'] };
    if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return { id: 'webp', label: 'WebP', exts: ['webp'] };
    if (ascii(0, 3) === 'GIF') return { id: 'gif', label: 'GIF', exts: ['gif'] };
    if (ascii(0, 4) === 'II*\u0000' || ascii(0, 4) === 'MM\u0000*') return { id: 'tiff', label: 'TIFF', exts: ['tif', 'tiff', 'dng', 'nef', 'cr2', 'arw'] };
    if (ascii(4, 4) === 'ftyp') {
      var brand = ascii(8, 4).trim();
      if (/^(heic|heix|hevc|heim|heis|hevm|hevs|mif1|msf1)$/.test(brand)) return { id: 'heic', label: 'HEIC/HEIF', exts: ['heic', 'heif'] };
      if (/^(avif|avis)$/.test(brand)) return { id: 'avif', label: 'AVIF', exts: ['avif'] };
      return { id: 'isobmff', label: 'ISO-BMFF (' + brand + ')', exts: [] };
    }
    if (ascii(0, 2) === 'BM') return { id: 'bmp', label: 'BMP', exts: ['bmp'] };
    var head = ascii(0, 256).toLowerCase();
    if (head.indexOf('<svg') !== -1 || (head.indexOf('<?xml') !== -1 && head.indexOf('svg') !== -1)) return { id: 'svg', label: 'SVG (XML)', exts: ['svg'] };
    return { id: 'unknown', label: '?', exts: [] };
  }

  // ---------- container end / trailer detection ----------
  function jpegImageEnd(b) {
    var pos = 2;
    while (pos + 3 < b.length) {
      if (b[pos] !== 0xFF) return null;
      var m = b[pos + 1];
      if (m === 0xDA) { // SOS: scan entropy-coded data for EOI
        for (var i = pos + 2; i + 1 < b.length; i++) {
          if (b[i] === 0xFF && b[i + 1] === 0xD9) return i + 2;
        }
        return null;
      }
      if (m === 0xD9) return pos + 2;
      if ((m >= 0xD0 && m <= 0xD7) || m === 0x01) { pos += 2; continue; }
      pos += 2 + ((b[pos + 2] << 8) | b[pos + 3]);
    }
    return null;
  }
  function pngImageEnd(b) {
    var pos = 8;
    while (pos + 8 <= b.length) {
      var len = (b[pos] << 24 >>> 0) + (b[pos + 1] << 16) + (b[pos + 2] << 8) + b[pos + 3];
      var type = String.fromCharCode(b[pos + 4], b[pos + 5], b[pos + 6], b[pos + 7]);
      pos += 12 + len;
      if (type === 'IEND') return pos;
    }
    return null;
  }
  function detectTrailer(b, fmt) {
    var end = null;
    if (fmt === 'jpeg') end = jpegImageEnd(b);
    else if (fmt === 'png') end = pngImageEnd(b);
    else if (fmt === 'webp') {
      if (b.length >= 12) {
        var size = b[4] + (b[5] << 8) + (b[6] << 16) + (b[7] << 24 >>> 0);
        end = 8 + size + (size % 2);
      }
    }
    if (end !== null && end > 0 && b.length > end) return { imageEnd: end, bytes: b.length - end };
    return null;
  }

  // ---------- verdict engine ----------
  var SENSITIVE = {
    identity: ['artist', 'xpauthor', 'cameraownername', 'ownername', 'creator', 'by-line', 'byline', 'by-line title', 'credit', 'copyright', 'copyright notice', 'rights', 'authorsposition', 'writer-editor', 'contact', 'creatorcontactinfo', 'author'],
    serial: ['bodyserialnumber', 'serialnumber', 'lensserialnumber', 'internalserialnumber', 'imageuniqueid', 'documentid', 'originaldocumentid', 'instanceid', 'contentidentifier', 'mediagroupuuid', 'burstuuid', 'digitalimageguid', 'imagenumber', 'cameraserialnumber'],
    device: ['make', 'model', 'lensmodel', 'lensmake', 'lens', 'lensinfo', 'hostcomputer', 'cameramodelname', 'devicemanufacturer', 'devicemodel'],
    software: ['software', 'processingsoftware', 'creatortool', 'historysoftwareagent', 'softwareagent'],
    time: ['datetimeoriginal', 'datetimedigitized', 'datetime', 'createdate', 'modifydate', 'metadatadate', 'gpsdatestamp', 'gpstimestamp', 'date created', 'time created', 'digitalcreationdate', 'digitalcreationtime', 'creation time', 'creationtime', 'modify date', 'datecreated', 'date'],
    comment: ['usercomment', 'imagedescription', 'xpcomment', 'xpsubject', 'xpkeywords', 'xptitle', 'caption/abstract', 'headline', 'description', 'comment', 'keywords', 'subject', 'title', 'label', 'objectname'],
    location_text: ['city', 'sub-location', 'province-or-state', 'country/primary location name', 'country/primary location code', 'location', 'locationcreated', 'locationshown', 'gpsareainformation']
  };
  var CAT_SEV = { location: 'critical', location_text: 'critical', identity: 'high', serial: 'high', trailer: 'high', device: 'medium', time: 'medium', comment: 'medium', thumb: 'medium', software: 'low' };
  var CAT_LABEL_KEY = { location: 'v_location', location_text: 'v_location', identity: 'v_identity', serial: 'v_serial', device: 'v_device', time: 'v_time', software: 'v_software', comment: 'v_comment', thumb: 'v_thumb', trailer: 'v_trailer' };

  function tagDescription(tag) {
    if (tag == null) return '';
    var d = tag.description;
    if (d === undefined || d === null || d === '') d = tag.value;
    if (Array.isArray(d)) d = d.join(', ');
    if (typeof d === 'object') { try { d = JSON.stringify(d); } catch (e) { d = String(d); } }
    d = String(d);
    return d.length > 160 ? d.slice(0, 160) + '…' : d;
  }

  function buildVerdict(model) {
    var items = [];
    var seen = {};
    if (model.gps) {
      items.push({ cat: 'location', detail: model.gps.lat.toFixed(6) + ', ' + model.gps.lon.toFixed(6) + (model.gps.alt !== undefined ? ' · ' + model.gps.alt.toFixed(0) + ' m' : ''), source: 'EXIF GPS' });
    }
    Object.keys(model.groups).forEach(function (gname) {
      if (gname === 'icc') return; // profile internals: in the dump, not the verdict
      var group = model.groups[gname];
      Object.keys(group).forEach(function (tname) {
        var lower = tname.toLowerCase();
        if (gname === 'gps' || /^gps/.test(lower)) return; // covered by the location item
        Object.keys(SENSITIVE).forEach(function (cat) {
          if (SENSITIVE[cat].indexOf(lower) === -1) return;
          var desc = tagDescription(group[tname]);
          if (!desc || desc === 'undefined' || /^\[?0+\]?$/.test(desc)) return;
          var key = cat + '|' + tname + '|' + desc;
          if (seen[key]) return;
          seen[key] = 1;
          items.push({ cat: cat, detail: tname + ' = ' + desc, source: gname });
        });
      });
    });
    if (model.thumbnail) items.push({ cat: 'thumb', detail: '', source: 'EXIF IFD1' });
    if (model.trailer) items.push({ cat: 'trailer', detail: model.trailer.bytes.toLocaleString() + ' ', source: 'file', trailer: true });
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    items.sort(function (a, b) { return order[CAT_SEV[a.cat]] - order[CAT_SEV[b.cat]]; });
    return items;
  }

  // ---------- screenshot inference ----------
  var DEVICE_SCREENS = {
    '640x960': 'iPhone 4 / 4S', '640x1136': 'iPhone 5 / 5s / SE (2016)',
    '750x1334': 'iPhone 6 / 6s / 7 / 8 / SE (2020/2022)', '1080x1920': 'iPhone 6+/7+/8+ Plus · many Android (FHD)',
    '1125x2436': 'iPhone X / XS / 11 Pro', '1242x2688': 'iPhone XS Max / 11 Pro Max', '828x1792': 'iPhone XR / 11',
    '1170x2532': 'iPhone 12 / 12 Pro / 13 / 13 Pro / 14', '1080x2340': 'iPhone 12 mini / 13 mini · many Android',
    '1284x2778': 'iPhone 12 Pro Max / 13 Pro Max / 14 Plus', '1179x2556': 'iPhone 14 Pro / 15 / 15 Pro / 16',
    '1290x2796': 'iPhone 14 Pro Max / 15 Plus / 15 Pro Max / 16 Plus', '1206x2622': 'iPhone 16 Pro', '1320x2868': 'iPhone 16 Pro Max',
    '1080x2400': 'many Android (Samsung A/S FE, Xiaomi, Motorola…)', '1080x2408': 'many Android (Xiaomi/POCO, Samsung mid-range…)',
    '720x1600': 'entry-level Android', '1440x3088': 'Samsung Galaxy S21+/S22 Ultra/S23 Ultra/S24 Ultra',
    '1440x3120': 'Google Pixel 6 Pro / 7 Pro', '1440x3200': 'Samsung Galaxy S20 / S21 Ultra series',
    '1344x2992': 'Google Pixel 8 Pro / 9 Pro XL', '1080x2424': 'Google Pixel 8a / 9',
    '768x1024': 'iPad (early) / iPad mini 1', '1536x2048': 'iPad 3–6 / mini 2–5 / Air 1–2 / Pro 9.7"',
    '1620x2160': 'iPad 7 / 8 / 9 (10.2")', '1640x2360': 'iPad Air 4/5 · iPad 10', '1488x2266': 'iPad mini 6/7',
    '1668x2224': 'iPad Pro 10.5" / Air 3', '1668x2388': 'iPad Pro 11"', '2048x2732': 'iPad Pro 12.9"', '2064x2752': 'iPad Pro 13" (M4)',
    '1920x1080': 'Full-HD display (very common)', '2560x1440': 'QHD display', '3840x2160': '4K display',
    '1366x768': 'budget laptop display', '1440x900': 'MacBook Air (pre-Retina) / older display', '1680x1050': 'older 20–22" display',
    '1280x800': 'older MacBook / small laptop', '2560x1600': 'MacBook Pro 13" Retina', '2880x1800': 'MacBook Pro 15" Retina',
    '3024x1964': 'MacBook Pro 14" (M-series)', '3456x2234': 'MacBook Pro 16" (M-series)', '2560x1664': 'MacBook Air 13" (M2/M3/M4)',
    '2880x1864': 'MacBook Air 15"', '5120x2880': 'iMac 27" 5K / Studio Display', '4480x2520': 'iMac 24"',
    '3440x1440': 'ultrawide display', '2736x1824': 'Surface Pro', '2256x1504': 'Surface Laptop 13.5"'
  };

  function inferScreenshot(model, fileName) {
    var out = [];
    var name = fileName || '';

    var mAndroid = name.match(/^screenshot[_-]?(\d{4})(\d{2})(\d{2})[-_](\d{2})(\d{2})(\d{2})(?:[-_](.+?))?\.[a-z0-9]+$/i);
    var mMac = name.match(/^(screenshot|captura de pantalla|bildschirmfoto)[ _](\d{4}-\d{2}-\d{2})[ _](?:at|a las?|um|om)[ _.]?(\d{1,2})\.(\d{2})\.(\d{2})/i);
    var mGnome = name.match(/^screenshot from (\d{4}-\d{2}-\d{2}) (\d{2})-(\d{2})-(\d{2})/i);
    var mWin = name.match(/^(screenshot|captura de pantalla) \((\d+)\)\.[a-z0-9]+$/i);
    var mWA = name.match(/^(img|vid)-(\d{4})(\d{2})(\d{2})-wa\d{4,}/i) || name.match(/^whatsapp (image|video) (\d{4}-\d{2}-\d{2}) at /i);
    var mTg = name.match(/^photo_(\d{4}-\d{2}-\d{2})[ _](\d{2})[.-](\d{2})[.-](\d{2})/i);

    if (mAndroid) {
      out.push({ kind: 'fname_os', params: { os: 'Android' }, evidence: name, tag: 'inferred' });
      out.push({ kind: 'fname_ts', params: { ts: mAndroid[1] + '-' + mAndroid[2] + '-' + mAndroid[3] + ' ' + mAndroid[4] + ':' + mAndroid[5] + ':' + mAndroid[6] }, evidence: name, tag: 'inferred' });
      if (mAndroid[7]) out.push({ kind: 'fname_app', params: { app: mAndroid[7] }, evidence: name, tag: 'inferred' });
    } else if (mMac) {
      out.push({ kind: 'fname_os', params: { os: 'macOS' }, evidence: name, tag: 'inferred' });
      out.push({ kind: 'fname_ts', params: { ts: mMac[2] + ' ' + mMac[3] + ':' + mMac[4] + ':' + mMac[5] }, evidence: name, tag: 'inferred' });
    } else if (mGnome) {
      out.push({ kind: 'fname_os', params: { os: 'Linux (GNOME)' }, evidence: name, tag: 'inferred' });
      out.push({ kind: 'fname_ts', params: { ts: mGnome[1] + ' ' + mGnome[2] + ':' + mGnome[3] + ':' + mGnome[4] }, evidence: name, tag: 'inferred' });
    } else if (mWin) {
      out.push({ kind: 'fname_os', params: { os: 'Windows' }, evidence: name, tag: 'inferred' });
    }
    if (mWA) out.push({ kind: 'whatsapp', params: {}, evidence: name, tag: 'inferred' });
    if (mTg) {
      out.push({ kind: 'telegram', params: {}, evidence: name, tag: 'inferred' });
      out.push({ kind: 'fname_ts', params: { ts: mTg[1] + ' ' + mTg[2] + ':' + mTg[3] + ':' + mTg[4] }, evidence: name, tag: 'inferred' });
    }

    // OS-written screenshot marker (macOS writes UserComment=Screenshot into XMP)
    ['exif', 'xmp'].forEach(function (g) {
      var grp = model.groups[g];
      if (grp && grp.UserComment && /screenshot/i.test(tagDescription(grp.UserComment))) {
        out.push({ kind: 'oscomment', params: { src: g === 'xmp' ? 'XMP UserComment' : 'EXIF UserComment' }, evidence: 'UserComment = ' + tagDescription(grp.UserComment), tag: 'observed' });
      }
    });

    // exact native-screen dimension match (both orientations)
    if (model.dims) {
      var w = model.dims.w, h = model.dims.h;
      var hit = DEVICE_SCREENS[w + 'x' + h] || DEVICE_SCREENS[h + 'x' + w];
      if (hit) {
        out.push({ kind: 'dims', params: { w: w, h: h, d: hit }, evidence: w + '×' + h + ' px', tag: 'inferred', multi: hit.indexOf('/') !== -1 || hit.indexOf('·') !== -1 || /many/i.test(hit) });
      }
    }

    // HiDPI density
    var res = null;
    if (model.groups.exif && model.groups.exif.XResolution) res = parseFloat(tagDescription(model.groups.exif.XResolution));
    if (!res && model.groups.png && model.groups.png['Pixels Per Unit X']) {
      var ppu = parseFloat(model.groups.png['Pixels Per Unit X'].value);
      if (ppu) res = Math.round(ppu * 0.0254);
    }
    if (res && res >= 140) out.push({ kind: 'hidpi', params: { dpi: String(Math.round(res)) }, evidence: Math.round(res) + ' DPI', tag: 'inferred' });

    var noCamera = !(model.groups.exif && (model.groups.exif.Make || model.groups.exif.Model));
    if (model.format === 'png' && noCamera) {
      out.push({ kind: 'noexif_png', params: {}, evidence: 'PNG · no Make/Model', tag: 'inferred' });
    }
    // Only surface the section when there is a real screenshot signal,
    // not just "PNG without EXIF" (that alone also matches logos, exports…)
    var strong = out.some(function (f) { return f.kind !== 'noexif_png' && f.kind !== 'hidpi'; });
    return strong || (out.length > 1 && model.format === 'png') ? out : (mWA || mTg ? out : []);
  }

  // ---------- parsing ----------
  var state = { file: null, bytes: null, model: null, previewURL: null, thumbURL: null };

  function parseModel(bytes, fileName, fileSize) {
    var fmt = sniffFormat(bytes);
    var model = {
      name: fileName, size: fileSize, format: fmt.id, formatLabel: fmt.label,
      groups: {}, gps: null, thumbnail: null, dims: null, trailer: null, parseError: false
    };
    var tags = null;
    try {
      tags = ExifReader.load(bytes.buffer, { expanded: true, includeUnknown: true });
    } catch (e) {
      model.parseError = true;
    }
    if (tags) {
      Object.keys(tags).forEach(function (g) {
        if (g === 'Thumbnail') {
          if (tags.Thumbnail && tags.Thumbnail.image) model.thumbnail = tags.Thumbnail.image;
          return;
        }
        if (g === 'gps') {
          var gg = tags.gps;
          if (gg && typeof gg.Latitude === 'number' && typeof gg.Longitude === 'number' && (gg.Latitude !== 0 || gg.Longitude !== 0)) {
            model.gps = { lat: gg.Latitude, lon: gg.Longitude };
            if (typeof gg.Altitude === 'number') model.gps.alt = gg.Altitude;
          }
          return;
        }
        var group = tags[g];
        if (!group || typeof group !== 'object') return;
        var clean = {};
        Object.keys(group).forEach(function (tname) {
          if (group[tname] === undefined || group[tname] === null) return;
          clean[tname] = group[tname];
        });
        if (Object.keys(clean).length) model.groups[g] = clean;
      });
      // GPS extras from exif group
      if (model.gps && model.groups.exif) {
        var ex = model.groups.exif;
        if (ex.GPSImgDirection) model.gps.dir = tagDescription(ex.GPSImgDirection) + (ex.GPSImgDirectionRef ? ' (' + tagDescription(ex.GPSImgDirectionRef) + ')' : '°');
        if (ex.GPSSpeed && parseFloat(tagDescription(ex.GPSSpeed)) > 0) model.gps.speed = tagDescription(ex.GPSSpeed) + (ex.GPSSpeedRef ? ' ' + tagDescription(ex.GPSSpeedRef) : '');
        if (ex.GPSDateStamp && ex.GPSTimeStamp) model.gps.ts = tagDescription(ex.GPSDateStamp) + ' ' + tagDescription(ex.GPSTimeStamp);
      }
      // dimensions
      var dims = null;
      ['file', 'pngFile', 'png', 'exif', 'riff', 'gif'].some(function (g) {
        var grp = model.groups[g];
        if (!grp) return false;
        var wTag = grp['Image Width'] || grp.ImageWidth || grp.PixelXDimension;
        var hTag = grp['Image Height'] || grp.ImageHeight || grp.PixelYDimension;
        if (wTag && hTag) {
          var w = parseInt(String(wTag.value !== undefined ? wTag.value : wTag.description), 10);
          var h = parseInt(String(hTag.value !== undefined ? hTag.value : hTag.description), 10);
          if (w > 0 && h > 0) { dims = { w: w, h: h }; return true; }
        }
        return false;
      });
      model.dims = dims;
    }
    model.trailer = detectTrailer(bytes, fmt.id);
    model.verdict = buildVerdict(model);
    model.screenshot = inferScreenshot(model, fileName);
    return model;
  }

  // ---------- rendering ----------
  function toDMS(dec, isLat) {
    var dir = dec >= 0 ? (isLat ? 'N' : 'E') : (isLat ? 'S' : 'W');
    var a = Math.abs(dec);
    var d = Math.floor(a), m = Math.floor((a - d) * 60);
    var s = ((a - d) * 60 - m) * 60;
    return d + '°' + String(m).padStart(2, '0') + '′' + s.toFixed(2) + '″' + dir;
  }

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

  var GROUP_LABELS = {
    file: 'File header', jfif: 'JFIF', exif: 'EXIF', iptc: 'IPTC', xmp: 'XMP', icc: 'ICC profile',
    mpf: 'MPF (multi-picture)', photoshop: 'Photoshop', canon: 'MakerNotes · Canon', pentax: 'MakerNotes · Pentax',
    riff: 'RIFF (WebP)', gif: 'GIF', png: 'PNG', pngFile: 'PNG header', pngText: 'PNG text chunks', composite: 'Composite'
  };
  var SENSITIVE_FLAT = (function () {
    var all = {};
    Object.keys(SENSITIVE).forEach(function (cat) {
      SENSITIVE[cat].forEach(function (t) { all[t] = cat; });
    });
    return all;
  })();

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

  var CLEANABLE = { jpeg: 1, png: 1, webp: 1 };
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
  function jsonSafeValue(v) {
    if (Array.isArray(v)) {
      if (v.length > 64) return '[' + v.length + ' values]';
      return v.map(jsonSafeValue);
    }
    if (v && typeof v === 'object') {
      if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return '[' + (v.byteLength || 0) + ' bytes]';
      var o = {};
      Object.keys(v).forEach(function (k) { o[k] = jsonSafeValue(v[k]); });
      return o;
    }
    if (typeof v === 'string' && v.length > 2000) return v.slice(0, 2000) + '…';
    return v;
  }
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
  var JPEG_KEEP_APP = { 0xE0: 1, 0xEE: 1 }; // APP0 JFIF, APP14 Adobe (color transform)
  function cleanJpeg(b) {
    var out = [], removed = [], ok = false;
    out.push(b.subarray(0, 2)); // SOI
    var pos = 2;
    while (pos + 3 < b.length) {
      if (b[pos] !== 0xFF) break; // malformed segment chain → bail, never emit a truncated image
      var m = b[pos + 1];
      if (m === 0xDA) { // SOS → copy through EOI, drop trailer
        var end = jpegImageEnd(b) || b.length;
        out.push(b.subarray(pos, end));
        ok = true;
        break;
      }
      var segLen = 2 + ((b[pos + 2] << 8) | b[pos + 3]);
      if ((m >= 0xD0 && m <= 0xD7) || m === 0x01) segLen = 2;
      var drop = false, label = null;
      if (m >= 0xE1 && m <= 0xEF && !JPEG_KEEP_APP[m]) {
        drop = true;
        var head = '';
        for (var i = pos + 4; i < Math.min(pos + 24, b.length); i++) head += String.fromCharCode(b[i]);
        label = 'APP' + (m - 0xE0);
        if (/^Exif/.test(head)) label += ' (EXIF)';
        else if (/adobe\.com\/xap|ns\.adobe/.test(head)) label += ' (XMP)';
        else if (/^ICC_PROFILE/.test(head)) label += ' (ICC)';
        else if (/^MPF/.test(head)) label += ' (MPF)';
        else if (/^Photoshop/.test(head)) label += ' (Photoshop/IPTC)';
      } else if (m === 0xFE) { drop = true; label = 'COM'; }
      if (drop) removed.push({ label: label, bytes: segLen });
      else out.push(b.subarray(pos, pos + segLen));
      pos += segLen;
    }
    return { parts: out, removed: removed, ok: ok };
  }

  var PNG_KEEP = { IHDR: 1, PLTE: 1, IDAT: 1, IEND: 1, tRNS: 1, gAMA: 1, cHRM: 1, sRGB: 1, sBIT: 1, bKGD: 1, acTL: 1, fcTL: 1, fdAT: 1 };
  function cleanPng(b) {
    var out = [b.subarray(0, 8)], removed = [], pos = 8, ok = false;
    while (pos + 8 <= b.length) {
      var len = (b[pos] << 24 >>> 0) + (b[pos + 1] << 16) + (b[pos + 2] << 8) + b[pos + 3];
      var type = String.fromCharCode(b[pos + 4], b[pos + 5], b[pos + 6], b[pos + 7]);
      if (!/^[A-Za-z]{4}$/.test(type)) break; // malformed chunk chain → bail
      var total = 12 + len;
      if (PNG_KEEP[type]) out.push(b.subarray(pos, pos + total));
      else removed.push({ label: type, bytes: total });
      pos += total;
      if (type === 'IEND') { ok = true; break; }
    }
    return { parts: out, removed: removed, ok: ok };
  }

  function cleanWebp(b) {
    var removedTypes = { 'EXIF': 1, 'XMP ': 1, 'ICCP': 1 };
    var chunks = [], removed = [], pos = 12;
    while (pos + 8 <= b.length) {
      var fourcc = String.fromCharCode(b[pos], b[pos + 1], b[pos + 2], b[pos + 3]);
      var len = b[pos + 4] + (b[pos + 5] << 8) + (b[pos + 6] << 16) + (b[pos + 7] << 24 >>> 0);
      var total = 8 + len + (len % 2);
      if (removedTypes[fourcc]) removed.push({ label: fourcc.trim(), bytes: total });
      else chunks.push(b.slice(pos, pos + total));
      pos += total;
    }
    // patch VP8X flags: clear ICC (0x20), EXIF (0x08), XMP (0x04)
    chunks.forEach(function (c) {
      var cc = String.fromCharCode(c[0], c[1], c[2], c[3]);
      if (cc === 'VP8X' && c.length > 8) c[8] = c[8] & ~(0x20 | 0x08 | 0x04);
    });
    var payload = 4; // 'WEBP'
    chunks.forEach(function (c) { payload += c.length; });
    var header = new Uint8Array(12);
    header.set([0x52, 0x49, 0x46, 0x46]); // RIFF
    header[4] = payload & 0xFF; header[5] = (payload >> 8) & 0xFF; header[6] = (payload >> 16) & 0xFF; header[7] = (payload >> 24) & 0xFF;
    header.set([0x57, 0x45, 0x42, 0x50], 8); // WEBP
    return { parts: [header].concat(chunks), removed: removed, ok: chunks.length > 0 };
  }

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
