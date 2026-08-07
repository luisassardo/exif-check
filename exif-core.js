/* ExifCheck · the engine, with no DOM and no network.

   Everything here is a pure function over bytes: format sniffing, metadata
   parsing, the verdict (what this image would reveal about you), screenshot
   inference, and the lossless strippers. It renders nothing and fetches
   nothing, so the same engine runs in this tool's own page and natively
   inside the J-LAB desk. One brain, two faces.

   Depends only on the vendored ExifReader global (MPL-2.0), which is never
   edited (STD-002.1). Verdict items and screenshot findings carry keys, not
   sentences, so each surface translates them in its own language.

   Canonical copy: 03-j-lab/exif-check/exif-core.js. The desk holds a synced
   copy it never hand-edits; sync-to-desk.mjs keeps the two identical.
*/
(function () {
  'use strict';
  // ---------- formatBytes ----------
  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    var units = ['KB', 'MB', 'GB'], v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[i];
  }

  // ---------- format sniffing and trailer detection ----------
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

  // ---------- sensitivity map and verdict engine ----------
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

  // ---------- screen fingerprints and screenshot inference ----------
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

  // ---------- parseModel ----------
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

  // ---------- toDMS ----------
  function toDMS(dec, isLat) {
    var dir = dec >= 0 ? (isLat ? 'N' : 'E') : (isLat ? 'S' : 'W');
    var a = Math.abs(dec);
    var d = Math.floor(a), m = Math.floor((a - d) * 60);
    var s = ((a - d) * 60 - m) * 60;
    return d + '°' + String(m).padStart(2, '0') + '′' + s.toFixed(2) + '″' + dir;
  }

  // ---------- group labels and the flattened sensitivity index ----------
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

  // ---------- cleanable formats ----------
  var CLEANABLE = { jpeg: 1, png: 1, webp: 1 };

  // ---------- jsonSafeValue ----------
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

  // ---------- lossless cleaners ----------
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

  window.ExifCore = {
    formatBytes: formatBytes,
    sniffFormat: sniffFormat,
    jpegImageEnd: jpegImageEnd,
    pngImageEnd: pngImageEnd,
    detectTrailer: detectTrailer,
    SENSITIVE: SENSITIVE,
    CAT_SEV: CAT_SEV,
    CAT_LABEL_KEY: CAT_LABEL_KEY,
    tagDescription: tagDescription,
    buildVerdict: buildVerdict,
    DEVICE_SCREENS: DEVICE_SCREENS,
    inferScreenshot: inferScreenshot,
    parseModel: parseModel,
    toDMS: toDMS,
    GROUP_LABELS: GROUP_LABELS,
    SENSITIVE_FLAT: SENSITIVE_FLAT,
    CLEANABLE: CLEANABLE,
    jsonSafeValue: jsonSafeValue,
    JPEG_KEEP_APP: JPEG_KEEP_APP,
    cleanJpeg: cleanJpeg,
    PNG_KEEP: PNG_KEEP,
    cleanPng: cleanPng,
    cleanWebp: cleanWebp
  };
})();
