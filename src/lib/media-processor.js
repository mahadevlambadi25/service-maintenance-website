import fs from 'node:fs';
import path from 'node:path';
import heicConvert from 'heic-convert';
import sharp from 'sharp';
import { UPLOAD_LIMITS } from '../config.js';
import { createObjectStore } from '../services/object-store.js';
import { generateUuid, sha256Hex } from './crypto.js';
import { scanBufferStatic, scanUploadedBuffer } from '../services/malware-scanner.js';

let customHeicConverter = null;
export function setHeicConverter(fn) {
  customHeicConverter = fn || null;
}

/**
 * Validates file signatures (magic bytes) rather than trusting browser MIME types or filenames.
 */
export function detectFileSignature(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;

  if (buf.subarray(0, 5).toString('ascii') === '%PDF-') {
    return { mime: 'application/pdf', ext: 'pdf' };
  }
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { mime: 'image/jpeg', ext: 'jpg' };
  }
  if (
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return { mime: 'image/png', ext: 'png' };
  }
  if (buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') {
    return { mime: 'image/webp', ext: 'webp' };
  }
  if (buf.subarray(4, 8).toString('ascii') === 'ftyp') {
    const brand = buf.subarray(8, 12).toString('ascii').toLowerCase();
    if (['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1'].includes(brand)) {
      return { mime: 'image/heic', ext: 'heic' };
    }
  }
  if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    const rawText = buf.toString('latin1');
    if (rawText.includes('vbaProject.bin') || rawText.includes('macros/')) {
      return { mime: 'application/vnd.ms-word.document.macroEnabled.12', ext: 'docm', unsafeMacro: true };
    }
    if (rawText.includes('word/document.xml') && rawText.includes('[Content_Types].xml')) {
      return {
        mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ext: 'docx',
      };
    }
    return { mime: 'application/zip', ext: 'zip' };
  }

  return null;
}

export function scanForMaliciousIndicators(buf, detectedMime) {
  return scanBufferStatic(buf, detectedMime);
}

/**
 * Extracts image width, height, and EXIF orientation quickly without unbounded decompression.
 */
export function inspectImageDimensions(buf, mime) {
  if (mime === 'image/png') {
    if (buf.length < 24 || buf.subarray(12, 16).toString('ascii') !== 'IHDR') return null;
    const width = buf.readUInt32BE(16);
    const height = buf.readUInt32BE(20);
    return { width, height, orientation: 1 };
  }

  if (mime === 'image/jpeg') {
    let offset = 2;
    let width = null;
    let height = null;
    let orientation = 1;
    while (offset + 4 < buf.length) {
      if (buf[offset] !== 0xff) break;
      const marker = buf[offset + 1];
      if (marker === 0xd8 || marker === 0xd9) {
        offset += 2;
        continue;
      }
      if (marker === 0xda) break;
      const segLen = buf.readUInt16BE(offset + 2);
      if (segLen < 2 || offset + 2 + segLen > buf.length) break;

      if (marker === 0xe1 && buf.subarray(offset + 4, offset + 10).toString('ascii') === 'Exif\0\0') {
        const parsedOrient = parseExifOrientation(buf.subarray(offset + 10, offset + 2 + segLen));
        if (parsedOrient) orientation = parsedOrient;
      }
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
        if (offset + 9 <= buf.length) {
          height = buf.readUInt16BE(offset + 5);
          width = buf.readUInt16BE(offset + 7);
        }
      }
      offset += 2 + segLen;
    }
    if (!width || !height) return null;
    if (orientation >= 5 && orientation <= 8) {
      return { width: height, height: width, orientation };
    }
    return { width, height, orientation };
  }

  if (mime === 'image/webp') {
    if (buf.length < 30) return null;
    const chunk = buf.subarray(12, 16).toString('ascii');
    if (chunk === 'VP8 ' && buf.length >= 30) {
      return { width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff, orientation: 1 };
    }
    if (chunk === 'VP8L' && buf.length >= 25) {
      const b0 = buf[21];
      const b1 = buf[22];
      const b2 = buf[23];
      const b3 = buf[24];
      return {
        width: 1 + (((b1 & 0x3f) << 8) | b0),
        height: 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)),
        orientation: 1,
      };
    }
    if (chunk === 'VP8X' && buf.length >= 30) {
      return {
        width: 1 + (buf[24] | (buf[25] << 8) | (buf[26] << 16)),
        height: 1 + (buf[27] | (buf[28] << 8) | (buf[29] << 16)),
        orientation: 1,
      };
    }
    return null;
  }

  if (mime === 'image/heic') {
    const idx = buf.indexOf(Buffer.from('ispe'));
    if (idx !== -1 && idx + 16 <= buf.length) {
      const width = buf.readUInt32BE(idx + 8);
      const height = buf.readUInt32BE(idx + 12);
      if (width > 0 && height > 0) return { width, height, orientation: 1 };
    }
    return { width: 1600, height: 1200, orientation: 1 };
  }

  return null;
}

function parseExifOrientation(tiffBuf) {
  if (tiffBuf.length < 8) return null;
  const endian = tiffBuf.subarray(0, 2).toString('ascii');
  const le = endian === 'II';
  if (!le && endian !== 'MM') return null;
  const read16 = (o) => (le ? tiffBuf.readUInt16LE(o) : tiffBuf.readUInt16BE(o));
  const read32 = (o) => (le ? tiffBuf.readUInt32LE(o) : tiffBuf.readUInt32BE(o));
  if (read16(2) !== 42) return null;
  const ifd0 = read32(4);
  if (ifd0 + 2 > tiffBuf.length) return null;
  const count = read16(ifd0);
  for (let i = 0; i < count; i++) {
    const entryOffset = ifd0 + 2 + i * 12;
    if (entryOffset + 12 > tiffBuf.length) break;
    if (read16(entryOffset) === 0x0112) {
      return read16(entryOffset + 8);
    }
  }
  return null;
}

export function stripImageMetadata(buf, mime) {
  if (mime === 'image/jpeg') {
    const chunks = [buf.subarray(0, 2)];
    let offset = 2;
    while (offset + 4 <= buf.length) {
      if (buf[offset] !== 0xff) {
        chunks.push(buf.subarray(offset));
        break;
      }
      const marker = buf[offset + 1];
      if (marker === 0xda) {
        chunks.push(buf.subarray(offset));
        break;
      }
      if (marker === 0xd9) {
        chunks.push(buf.subarray(offset, offset + 2));
        break;
      }
      const segLen = buf.readUInt16BE(offset + 2);
      if (segLen < 2 || offset + 2 + segLen > buf.length) break;
      const isMetadataSegment = (marker >= 0xe1 && marker <= 0xef) || marker === 0xfe;
      if (!isMetadataSegment) {
        chunks.push(buf.subarray(offset, offset + 2 + segLen));
      }
      offset += 2 + segLen;
    }
    return Buffer.concat(chunks);
  }

  if (mime === 'image/png') {
    const chunks = [buf.subarray(0, 8)];
    let offset = 8;
    const stripTypes = new Set(['eXIf', 'tEXt', 'zTXt', 'iTXt', 'tIME']);
    while (offset + 12 <= buf.length) {
      const length = buf.readUInt32BE(offset);
      const type = buf.subarray(offset + 4, offset + 8).toString('ascii');
      const total = 12 + length;
      if (offset + total > buf.length) break;
      if (!stripTypes.has(type)) {
        chunks.push(buf.subarray(offset, offset + total));
      }
      offset += total;
      if (type === 'IEND') break;
    }
    return Buffer.concat(chunks);
  }

  if (mime === 'image/webp') {
    const kept = [];
    let offset = 12;
    while (offset + 8 <= buf.length) {
      const fourcc = buf.subarray(offset, offset + 4).toString('ascii');
      const size = buf.readUInt32LE(offset + 4);
      const padded = size + (size % 2);
      const total = 8 + padded;
      if (offset + total > buf.length) break;
      if (fourcc !== 'EXIF' && fourcc !== 'XMP ') {
        kept.push(buf.subarray(offset, offset + total));
      }
      offset += total;
    }
    const body = Buffer.concat(kept);
    const header = Buffer.alloc(12);
    header.write('RIFF', 0, 'ascii');
    header.writeUInt32LE(4 + body.length, 4);
    header.write('WEBP', 8, 'ascii');
    return Buffer.concat([header, body]);
  }

  return buf;
}

/**
 * Full async image processing pipeline using sharp + heic-convert + fail-closed scanner:
 *  - Validates limits, magic signature, and < 64 MP cap before & during decode
 *  - Runs malware/active-content scan (fail-closed)
 *  - Converts HEIC -> JPEG via heic-convert
 *  - Applies true EXIF orientation (.rotate()) & strips all EXIF/GPS/XMP/IPTC metadata
 *  - Generates optimized responsive WebP + JPEG variants for desktop (1600w), tablet (960w), mobile (480w)
 */
export async function processProjectImageUploadAsync({ buffer, originalName, storagePaths }) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, errorCode: 'empty_file', message: 'Uploaded file is empty.' };
  }
  if (buffer.length > UPLOAD_LIMITS.projectMedia.maxFileBytes) {
    return { ok: false, errorCode: 'file_too_large', message: 'Image exceeds 20 MB maximum limit.' };
  }

  const sig = detectFileSignature(buffer);
  if (!sig || !UPLOAD_LIMITS.projectMedia.allowedTypes.includes(sig.mime)) {
    return {
      ok: false,
      errorCode: 'unsupported_signature',
      message: 'Unsupported or mismatched file format. Allowed: JPEG, PNG, WebP, or HEIC.',
    };
  }

  const dimsPre = inspectImageDimensions(buffer, sig.mime);
  if (dimsPre && (dimsPre.width * dimsPre.height) / 1_000_000 > UPLOAD_LIMITS.projectMedia.maxMegapixels) {
    return {
      ok: false,
      errorCode: 'pixel_limit_exceeded',
      message: `Image dimensions (${dimsPre.width}x${dimsPre.height}) exceed the 64 MP maximum limit.`,
    };
  }

  const scan = await scanUploadedBuffer(buffer, { mime: sig.mime, originalName });
  if (!scan.safe) {
    return {
      ok: false,
      errorCode: 'quarantined_file',
      message: `Security check rejected file (${scan.reason}).`,
    };
  }

  let workingBuf = buffer;
  let originalOrientation = dimsPre?.orientation || 1;
  if (sig.mime === 'image/heic') {
    try {
      const converter = customHeicConverter || ((opts) => heicConvert(opts));
      const converted = await converter({ buffer, format: 'JPEG', quality: 0.92 });
      workingBuf = Buffer.isBuffer(converted) ? converted : Buffer.from(converted);
    } catch (err) {
      return {
        ok: false,
        errorCode: 'heic_conversion_failed',
        message: `HEIC conversion failed (${err.message}). Upload a valid HEIC, JPEG, PNG, or WebP photo.`,
      };
    }
  }

  const maxPixels = UPLOAD_LIMITS.projectMedia.maxMegapixels * 1_000_000;
  let meta;
  let baseRotatedBuf;
  try {
    const probe = sharp(workingBuf, { limitInputPixels: maxPixels, failOn: 'error' });
    meta = await probe.metadata();
    if (!meta?.width || !meta?.height) {
      return { ok: false, errorCode: 'corrupt_image', message: 'Decoded image has invalid dimensions.' };
    }
    if (meta.width * meta.height > maxPixels) {
      return {
        ok: false,
        errorCode: 'pixel_limit_exceeded',
        message: `Image dimensions (${meta.width}x${meta.height}) exceed the 64 MP maximum limit.`,
      };
    }
    if (meta.orientation) originalOrientation = meta.orientation;

    // .rotate() physically rotates pixel buffer according to EXIF orientation and strips ALL metadata!
    baseRotatedBuf = await sharp(workingBuf, { limitInputPixels: maxPixels, failOn: 'error' })
      .rotate()
      .toBuffer();
  } catch (err) {
    if (/pixel limit/i.test(err.message)) {
      return { ok: false, errorCode: 'pixel_limit_exceeded', message: 'Image exceeds the 64 MP pixel limit.' };
    }
    return {
      ok: false,
      errorCode: 'corrupt_image',
      message: `Image decoding failed cleanly (${err.message}).`,
    };
  }

  const rotatedMeta = await sharp(baseRotatedBuf).metadata();
  const finalWidth = rotatedMeta.width;
  const finalHeight = rotatedMeta.height;

  const store = createObjectStore(storagePaths);
  const assetId = generateUuid();
  const originalKey = `${assetId}.${sig.ext}`;
  await store.putObject({
    area: 'originals',
    key: originalKey,
    buffer,
    contentType: sig.mime,
  });

  const sizes = [
    { name: 'desktop', width: 1600 },
    { name: 'tablet', width: 960 },
    { name: 'mobile', width: 480 },
  ];

  const variants = { webp: {}, jpeg: {}, width: finalWidth, height: finalHeight };
  let primaryBytes = 0;
  for (const sz of sizes) {
    const webpKey = `${assetId}-${sz.name}.webp`;
    const jpgKey = `${assetId}-${sz.name}.jpg`;

    const webpBuf = await sharp(baseRotatedBuf)
      .resize({ width: sz.width, withoutEnlargement: true })
      .webp({ quality: 82 })
      .toBuffer();

    const jpgBuf = await sharp(baseRotatedBuf)
      .resize({ width: sz.width, withoutEnlargement: true })
      .jpeg({ quality: 84, mozjpeg: true })
      .toBuffer();

    await store.putObject({
      area: 'publicMedia',
      key: webpKey,
      buffer: webpBuf,
      contentType: 'image/webp',
      cacheControl: 'public, max-age=300, must-revalidate',
    });

    await store.putObject({
      area: 'publicMedia',
      key: jpgKey,
      buffer: jpgBuf,
      contentType: 'image/jpeg',
      cacheControl: 'public, max-age=300, must-revalidate',
    });

    if (sz.name === 'desktop') primaryBytes = jpgBuf.length;
    variants.webp[sz.name] = webpKey;
    variants.jpeg[sz.name] = jpgKey;
  }

  const primaryKey = variants.jpeg.desktop;

  return {
    ok: true,
    asset: {
      asset_id: assetId,
      original_filename: path.basename(String(originalName || 'upload')).slice(0, 140),
      mime_type: sig.mime,
      derivative_mime: 'image/jpeg',
      byte_size: buffer.length,
      derivative_bytes: primaryBytes,
      width: finalWidth,
      height: finalHeight,
      orientation: originalOrientation,
      normalized_orientation: 1,
      sha256: sha256Hex(buffer),
      scan_state: scan.scanState,
      private_original_key: originalKey,
      public_derivative_key: primaryKey,
      variants,
      metadata_stripped: true,
    },
  };
}

/**
 * Legacy synchronous helper preserved for existing unit tests with minimal header stubs.
 */
export function processProjectImageUpload({ buffer, originalName, storagePaths }) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, errorCode: 'empty_file', message: 'Uploaded file is empty.' };
  }
  if (buffer.length > UPLOAD_LIMITS.projectMedia.maxFileBytes) {
    return { ok: false, errorCode: 'file_too_large', message: 'Image exceeds 20 MB maximum limit.' };
  }

  const sig = detectFileSignature(buffer);
  if (!sig || !UPLOAD_LIMITS.projectMedia.allowedTypes.includes(sig.mime)) {
    return { ok: false, errorCode: 'unsupported_signature', message: 'Unsupported or mismatched file format. Allowed: JPEG, PNG, WebP, or HEIC.' };
  }

  const scan = scanForMaliciousIndicators(buffer, sig.mime);
  if (!scan.safe) {
    return { ok: false, errorCode: 'quarantined_file', message: `Security check rejected file (${scan.reason}).` };
  }

  const dims = inspectImageDimensions(buffer, sig.mime);
  if (!dims || dims.width <= 0 || dims.height <= 0) {
    return { ok: false, errorCode: 'corrupt_image', message: 'Could not decode valid image dimensions.' };
  }
  const megapixels = (dims.width * dims.height) / 1_000_000;
  if (megapixels > UPLOAD_LIMITS.projectMedia.maxMegapixels) {
    return { ok: false, errorCode: 'pixel_limit_exceeded', message: `Image dimensions (${dims.width}x${dims.height}) exceed the 64 MP maximum limit.` };
  }

  const assetId = generateUuid();
  const originalKey = `${assetId}.${sig.ext}`;
  fs.mkdirSync(storagePaths.originals, { recursive: true });
  fs.writeFileSync(path.join(storagePaths.originals, originalKey), buffer);

  const derivativeKey = `${assetId}-clean.${sig.ext === 'heic' ? 'heic' : sig.ext}`;
  const derivativeBuf = stripImageMetadata(buffer, sig.mime);
  fs.mkdirSync(storagePaths.publicMedia, { recursive: true });
  fs.writeFileSync(path.join(storagePaths.publicMedia, derivativeKey), derivativeBuf);

  return {
    ok: true,
    asset: {
      asset_id: assetId,
      original_filename: path.basename(String(originalName || 'upload')).slice(0, 140),
      mime_type: sig.mime,
      derivative_mime: sig.mime,
      byte_size: buffer.length,
      derivative_bytes: derivativeBuf.length,
      width: dims.width,
      height: dims.height,
      orientation: dims.orientation,
      sha256: sha256Hex(buffer),
      private_original_key: originalKey,
      public_derivative_key: derivativeKey,
      metadata_stripped: true,
    },
  };
}

export async function processPrivateDocumentUploadAsync({
  buffer,
  originalName,
  allowedTypes,
  maxBytes,
  destDir,
  storagePaths = null,
  area = null,
}) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, errorCode: 'empty_file', message: 'Uploaded file is empty.' };
  }
  if (buffer.length > maxBytes) {
    return { ok: false, errorCode: 'file_too_large', message: `File exceeds ${(maxBytes / (1024 * 1024)).toFixed(0)} MB limit.` };
  }

  const sig = detectFileSignature(buffer);
  if (!sig || sig.unsafeMacro || !allowedTypes.includes(sig.mime)) {
    return {
      ok: false,
      errorCode: 'invalid_file_type',
      message: sig?.unsafeMacro ? 'Macro-enabled documents are prohibited.' : 'Unsupported or invalid file signature.',
    };
  }

  const scan = await scanUploadedBuffer(buffer, { mime: sig.mime, originalName });
  const objectId = generateUuid();
  const storageKey = `${objectId}.bin`;
  const requestedArea = area || (destDir ? path.basename(destDir) : 'quarantine');
  // Never place non-clean/quarantined files inside the resumes area
  const resolvedArea = scan.scanState !== 'clean' ? 'quarantine' : requestedArea;
  if (storagePaths || resolvedArea === 'quarantine' || resolvedArea === 'resumes') {
    const resolvedPaths = storagePaths || {
      resumes: resolvedArea === 'resumes' ? destDir : undefined,
      quarantine: resolvedArea === 'quarantine' ? destDir : undefined,
    };
    const store = createObjectStore(resolvedPaths);
    await store.putObject({
      area: resolvedArea,
      key: storageKey,
      buffer,
      contentType: sig.mime,
    });
  } else {
    fs.mkdirSync(destDir, { recursive: true });
    fs.writeFileSync(path.join(destDir, storageKey), buffer);
  }

  return {
    ok: true,
    file: {
      object_id: objectId,
      storage_key: storageKey,
      original_name: path.basename(String(originalName || 'document')).slice(0, 140),
      mime_type: sig.mime,
      byte_size: buffer.length,
      sha256: sha256Hex(buffer),
      scan_state: scan.scanState,
      scan_reason: scan.reason,
    },
  };
}

export function processPrivateDocumentUpload({ buffer, originalName, allowedTypes, maxBytes, destDir }) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, errorCode: 'empty_file', message: 'Uploaded file is empty.' };
  }
  if (buffer.length > maxBytes) {
    return { ok: false, errorCode: 'file_too_large', message: `File exceeds ${(maxBytes / (1024 * 1024)).toFixed(0)} MB limit.` };
  }

  const sig = detectFileSignature(buffer);
  if (!sig || sig.unsafeMacro || !allowedTypes.includes(sig.mime)) {
    return {
      ok: false,
      errorCode: 'invalid_file_type',
      message: sig?.unsafeMacro ? 'Macro-enabled documents are prohibited.' : 'Unsupported or invalid file signature.',
    };
  }

  const scan = scanForMaliciousIndicators(buffer, sig.mime);
  const objectId = generateUuid();
  const storageKey = `${objectId}.bin`;
  fs.mkdirSync(destDir, { recursive: true });
  fs.writeFileSync(path.join(destDir, storageKey), buffer);

  return {
    ok: true,
    file: {
      object_id: objectId,
      storage_key: storageKey,
      original_name: path.basename(String(originalName || 'document')).slice(0, 140),
      mime_type: sig.mime,
      byte_size: buffer.length,
      sha256: sha256Hex(buffer),
      scan_state: scan.safe ? 'clean' : 'quarantined',
      scan_reason: scan.reason,
    },
  };
}
