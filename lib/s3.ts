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

const REGION_ENV_PREFERENCE = ["AWS_S3_REGION", "S3_BUCKET_REGION", "AWS_DEFAULT_REGION", "AWS_REGION"] as const

export function getS3Config(): S3Config {
  if (cachedConfig) return cachedConfig

  cachedConfig = {
    region: resolveRegion(),
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

function resolveRegion(): string {
  for (const name of REGION_ENV_PREFERENCE) {
    const raw = process.env[name]
    if (!raw) continue

    const candidate = raw.trim()
    if (!candidate) continue

    if (isValidAwsRegion(candidate)) {
      return candidate.toLowerCase()
    }
  }

  const preferenceList = REGION_ENV_PREFERENCE.join(", ")
  throw new Error(`Missing a valid AWS region. Provide one of: ${preferenceList}. Example: "ap-southeast-1".`)
}

function isValidAwsRegion(value: string): boolean {
  return /^[a-z]{2}(?:-[a-z0-9]+)+-\d+$/i.test(value)
}
