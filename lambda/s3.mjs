import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

const s3     = new S3Client({ region: 'us-east-2' });
const BUCKET = 'jaetill-carto';

export async function s3Get(key) {
  try {
    const res  = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
    const body = await res.Body.transformToString();
    return JSON.parse(body);
  } catch (e) {
    if (e.name === 'NoSuchKey') return null;
    throw e;
  }
}

export async function s3Put(key, data) {
  await s3.send(new PutObjectCommand({
    Bucket:      BUCKET,
    Key:         key,
    Body:        JSON.stringify(data),
    ContentType: 'application/json',
  }));
}
