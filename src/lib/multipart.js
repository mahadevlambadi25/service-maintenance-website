/**
 * Zero-dependency bounded HTTP body parser supporting JSON, URL-encoded forms, and multipart/form-data.
 */

export async function readBodyBuffer(req, maxBytes = 30 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let aborted = false;

    req.on('data', (chunk) => {
      if (aborted) return;
      total += chunk.length;
      if (total > maxBytes) {
        aborted = true;
        const err = new Error('Payload too large');
        err.statusCode = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (!aborted) resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (!aborted) reject(err);
    });
  });
}

export async function parseRequestBody(req, maxBytes = 30 * 1024 * 1024) {
  const ct = String(req.headers['content-type'] || '');
  const buf = await readBodyBuffer(req, maxBytes);

  if (ct.includes('application/json')) {
    try {
      const json = buf.length ? JSON.parse(buf.toString('utf8')) : {};
      return { fields: json, files: [] };
    } catch {
      const err = new Error('Invalid JSON payload');
      err.statusCode = 400;
      throw err;
    }
  }

  if (ct.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(buf.toString('utf8'));
    const fields = {};
    for (const [k, v] of params.entries()) {
      fields[k] = v;
    }
    return { fields, files: [] };
  }

  if (ct.includes('multipart/form-data')) {
    const m = ct.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
    if (!m) {
      const err = new Error('Missing multipart boundary');
      err.statusCode = 400;
      throw err;
    }
    const boundary = m[1] || m[2];
    return parseMultipart(buf, boundary);
  }

  return { fields: {}, files: [] };
}

export function parseMultipart(buf, boundary) {
  const delimiter = Buffer.from(`--${boundary}`);
  const fields = {};
  const files = [];

  let pos = buf.indexOf(delimiter);
  if (pos === -1) return { fields, files };

  while (pos !== -1) {
    pos += delimiter.length;
    // End boundary "--"
    if (buf.subarray(pos, pos + 2).toString('ascii') === '--') break;
    // Skip CRLF after boundary
    if (buf[pos] === 0x0d && buf[pos + 1] === 0x0a) pos += 2;
    else if (buf[pos] === 0x0a) pos += 1;

    const nextBoundary = buf.indexOf(delimiter, pos);
    if (nextBoundary === -1) break;

    let part = buf.subarray(pos, nextBoundary);
    // Trim trailing CRLF before next boundary
    if (part.length >= 2 && part[part.length - 2] === 0x0d && part[part.length - 1] === 0x0a) {
      part = part.subarray(0, part.length - 2);
    } else if (part.length >= 1 && part[part.length - 1] === 0x0a) {
      part = part.subarray(0, part.length - 1);
    }

    const headerEndCrlf = part.indexOf(Buffer.from('\r\n\r\n'));
    const headerEndLf = part.indexOf(Buffer.from('\n\n'));
    let headerEnd = -1;
    let sepLen = 4;
    if (headerEndCrlf !== -1 && (headerEndLf === -1 || headerEndCrlf < headerEndLf)) {
      headerEnd = headerEndCrlf;
      sepLen = 4;
    } else if (headerEndLf !== -1) {
      headerEnd = headerEndLf;
      sepLen = 2;
    }

    if (headerEnd !== -1) {
      const headerStr = part.subarray(0, headerEnd).toString('utf8');
      const bodyBuf = part.subarray(headerEnd + sepLen);
      const dispMatch = headerStr.match(/content-disposition:\s*form-data;\s*([^\r\n]+)/i);
      if (dispMatch) {
        const nameMatch = dispMatch[1].match(/\bname="([^"]+)"/i);
        const fileMatch = dispMatch[1].match(/\bfilename="([^"]*)"/i);
        const typeMatch = headerStr.match(/content-type:\s*([^\r\n;]+)/i);
        const fieldName = nameMatch ? nameMatch[1] : '';

        if (fileMatch) {
          if (fileMatch[1] || bodyBuf.length > 0) {
            files.push({
              fieldName,
              originalName: fileMatch[1] || 'upload',
              mimeType: typeMatch ? typeMatch[1].trim() : 'application/octet-stream',
              buffer: Buffer.from(bodyBuf),
            });
          }
        } else if (fieldName) {
          fields[fieldName] = bodyBuf.toString('utf8');
        }
      }
    }

    pos = nextBoundary;
  }

  return { fields, files };
}
