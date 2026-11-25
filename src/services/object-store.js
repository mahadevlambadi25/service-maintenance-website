import fs from 'node:fs';
import path from 'node:path';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { ENV, STORAGE_PATHS } from '../config.js';

let customS3Client = null;
let cachedS3Client = null;
let cachedS3Key = '';

export function setCustomS3Client(client) {
  customS3Client = client || null;
}

export function isS3StorageConfigured(storagePaths = null) {
  if (customS3Client) return true;
  if (process.env.DISABLE_S3_STORAGE === '1') return false;
  if (storagePaths?.forceLocal) return false;
  const endpoint = String(process.env.AWS_ENDPOINT_URL_S3 ?? ENV.AWS_ENDPOINT_URL_S3 ?? '').trim();
  const keyId = String(process.env.AWS_ACCESS_KEY_ID ?? ENV.AWS_ACCESS_KEY_ID ?? '').trim();
  const secret = String(process.env.AWS_SECRET_ACCESS_KEY ?? ENV.AWS_SECRET_ACCESS_KEY ?? '').trim();
  return Boolean(endpoint && keyId && secret);
}

export function getS3BucketName() {
  return String(process.env.S3_BUCKET || process.env.NEON_STORAGE_BUCKET || ENV.S3_BUCKET || 'storage').trim();
}

function getS3Client() {
  if (customS3Client) return customS3Client;
  const endpoint = String(process.env.AWS_ENDPOINT_URL_S3 ?? ENV.AWS_ENDPOINT_URL_S3 ?? '').trim();
  const region = String(process.env.AWS_REGION ?? ENV.AWS_REGION ?? 'ap-southeast-1').trim();
  const accessKeyId = String(process.env.AWS_ACCESS_KEY_ID ?? ENV.AWS_ACCESS_KEY_ID ?? '').trim();
  const secretAccessKey = String(process.env.AWS_SECRET_ACCESS_KEY ?? ENV.AWS_SECRET_ACCESS_KEY ?? '').trim();
  const cacheSig = `${endpoint}|${region}|${accessKeyId}`;
  if (cachedS3Client && cachedS3Key === cacheSig) return cachedS3Client;

  cachedS3Client = new S3Client({
    region,
    endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId, secretAccessKey },
  });
  cachedS3Key = cacheSig;
  return cachedS3Client;
}

const AREA_PREFIX = {
  originals: 'originals',
  publicMedia: 'public-media',
  resumes: 'resumes',
  quarantine: 'quarantine',
  backups: 'backups',
  staging: 'staging',
};

function normalizeRelKey(key) {
  return String(key || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .split('/')
    .filter((seg) => seg && seg !== '..' && seg !== '.')
    .join('/');
}

function s3ObjectKey(area, key) {
  const prefix = AREA_PREFIX[area] || 'misc';
  const rel = normalizeRelKey(key);
  return `${prefix}/${rel}`;
}

function localFilePath(storagePaths, area, key) {
  const rel = normalizeRelKey(key);
  if (area === 'staging') {
    const base = path.join(storagePaths.privateRoot, 'staging');
    return path.join(base, rel);
  }
  const baseDir = storagePaths[area] || storagePaths.privateRoot;
  return path.join(baseDir, area === 'backups' ? rel : path.basename(rel));
}

export function createObjectStore(storagePaths = STORAGE_PATHS) {
  return {
    get mode() {
      return isS3StorageConfigured() ? 's3' : 'local';
    },

    async putObject({ area, key, buffer, contentType = 'application/octet-stream', cacheControl = null }) {
      const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
      if (isS3StorageConfigured()) {
        const s3 = getS3Client();
        const params = {
          Bucket: getS3BucketName(),
          Key: s3ObjectKey(area, key),
          Body: buf,
          ContentType: contentType,
        };
        if (cacheControl) params.CacheControl = cacheControl;
        await s3.send(new PutObjectCommand(params));
        return { mode: 's3', key: normalizeRelKey(key), bytes: buf.length };
      }

      const dst = localFilePath(storagePaths, area, key);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.writeFileSync(dst, buf);
      return { mode: 'local', key: normalizeRelKey(key), bytes: buf.length };
    },

    async getObjectBuffer({ area, key }) {
      if (isS3StorageConfigured()) {
        const s3 = getS3Client();
        try {
          const out = await s3.send(
            new GetObjectCommand({
              Bucket: getS3BucketName(),
              Key: s3ObjectKey(area, key),
            })
          );
          if (!out?.Body) return null;
          if (typeof out.Body.transformToByteArray === 'function') {
            return Buffer.from(await out.Body.transformToByteArray());
          }
          const chunks = [];
          for await (const ch of out.Body) chunks.push(Buffer.from(ch));
          return Buffer.concat(chunks);
        } catch (err) {
          if (err?.name === 'NoSuchKey' || err?.$metadata?.httpStatusCode === 404) return null;
          throw err;
        }
      }

      const src = localFilePath(storagePaths, area, key);
      if (!fs.existsSync(src) || !fs.statSync(src).isFile()) return null;
      return fs.readFileSync(src);
    },

    async existsObject({ area, key }) {
      if (isS3StorageConfigured()) {
        const s3 = getS3Client();
        try {
          await s3.send(
            new HeadObjectCommand({
              Bucket: getS3BucketName(),
              Key: s3ObjectKey(area, key),
            })
          );
          return true;
        } catch (err) {
          if (err?.name === 'NotFound' || err?.$metadata?.httpStatusCode === 404) return false;
          throw err;
        }
      }
      const src = localFilePath(storagePaths, area, key);
      return fs.existsSync(src) && fs.statSync(src).isFile();
    },

    async deleteObject({ area, key }) {
      if (!key) return;
      if (isS3StorageConfigured()) {
        const s3 = getS3Client();
        try {
          await s3.send(
            new DeleteObjectCommand({
              Bucket: getS3BucketName(),
              Key: s3ObjectKey(area, key),
            })
          );
        } catch {}
        return;
      }
      const fp = localFilePath(storagePaths, area, key);
      if (fs.existsSync(fp)) {
        try {
          fs.unlinkSync(fp);
        } catch {}
      }
    },

    async listAreaObjects({ area, prefix = '' }) {
      if (isS3StorageConfigured()) {
        const s3 = getS3Client();
        const areaPrefix = `${AREA_PREFIX[area] || 'misc'}/`;
        const fullPrefix = `${areaPrefix}${normalizeRelKey(prefix)}`;
        const keys = [];
        let continuationToken;
        do {
          const out = await s3.send(
            new ListObjectsV2Command({
              Bucket: getS3BucketName(),
              Prefix: fullPrefix,
              ContinuationToken: continuationToken,
            })
          );
          for (const item of out?.Contents || []) {
            if (item.Key && item.Key.startsWith(areaPrefix)) {
              keys.push({
                key: item.Key.slice(areaPrefix.length),
                bytes: Number(item.Size || 0),
              });
            }
          }
          continuationToken = out?.IsTruncated ? out.NextContinuationToken : undefined;
        } while (continuationToken);
        return keys;
      }

      const dir = area === 'staging'
        ? path.join(storagePaths.privateRoot, 'staging')
        : storagePaths[area];
      if (!dir || !fs.existsSync(dir)) return [];
      const out = [];
      const walk = (curr, relBase) => {
        for (const entry of fs.readdirSync(curr, { withFileTypes: true })) {
          const full = path.join(curr, entry.name);
          const rel = relBase ? `${relBase}/${entry.name}` : entry.name;
          if (entry.isDirectory()) {
            walk(full, rel);
          } else if (entry.isFile()) {
            if (!prefix || rel.startsWith(normalizeRelKey(prefix))) {
              out.push({ key: rel, bytes: fs.statSync(full).size });
            }
          }
        }
      };
      walk(dir, '');
      return out;
    },

    async createPresignedUpload({ key, contentType, expiresIn = 600 }) {
      if (!isS3StorageConfigured()) {
        return { enabled: false, mode: 'direct_multipart' };
      }
      const s3 = getS3Client();
      const bucket = getS3BucketName();
      const fullKey = s3ObjectKey('staging', key);
      const command = new PutObjectCommand({
        Bucket: bucket,
        Key: fullKey,
        ContentType: contentType,
      });
      const url = await getSignedUrl(s3, command, { expiresIn });
      return {
        enabled: true,
        mode: 's3_presigned_put',
        url,
        bucket,
        stagingKey: normalizeRelKey(key),
        headers: {
          'Content-Type': contentType,
        },
        expiresIn,
      };
    },
  };
}
