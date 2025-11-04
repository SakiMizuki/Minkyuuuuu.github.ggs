import { S3Client } from "@aws-sdk/client-s3"
import { RequestChecksumCalculation } from "@aws-sdk/middleware-flexible-checksums"

type S3Config = {
  region: string
  bucket: string
  accessKeyId: string
  secretAccessKey: string
}

let client: S3Client | null = null
let cachedConfig: S3Config | null = null

const requiredEnv = (name: string): string => {
  const value = process.env[name]
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`)
  }

  return value
}

export function getS3Config(): S3Config {
  if (cachedConfig) return cachedConfig

  cachedConfig = {
    region: requiredEnv("AWS_REGION"),
    bucket: requiredEnv("S3_BUCKET_NAME"),
    accessKeyId: requiredEnv("AWS_ACCESS_KEY_ID"),
    secretAccessKey: requiredEnv("AWS_SECRET_ACCESS_KEY"),
  }

  return cachedConfig
}

export function getS3Client(): S3Client {
  if (client) return client

  const config = getS3Config()

  client = new S3Client({
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    requestChecksumCalculation: RequestChecksumCalculation.WHEN_REQUIRED,
  })

  return client
}

export function getPublicFileUrl(key: string): string {
  const { bucket, region } = getS3Config()
  const encodedKey = key
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/")

  const baseUrl = region === "us-east-1"
    ? `https://${bucket}.s3.amazonaws.com`
    : `https://${bucket}.s3.${region}.amazonaws.com`

  return `${baseUrl}/${encodedKey}`
}

export const FILES_PREFIX = "files/"
