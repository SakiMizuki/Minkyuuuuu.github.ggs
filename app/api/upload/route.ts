import { NextResponse, type NextRequest } from "next/server"
import { HeadObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3"
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"
import { createHash, randomUUID } from "crypto"
import { extname } from "path"
import { computeExpiry, isAutoDeleteOption, type AutoDeleteOption } from "@/lib/auto-delete"
import { FILES_PREFIX, getPublicFileUrl, getS3Client, getS3Config } from "@/lib/s3"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

type FilenameMode = "original" | "random"

const MAX_FILENAME_LENGTH = 200
const DEFAULT_FILENAME_MODE: FilenameMode = "random"
const PRESIGNED_HTTP_METHOD = "PUT" as const
const UPLOAD_URL_TTL_SECONDS = 60 * 60 // 1 hour

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as unknown
    if (!isValidRequestBody(body)) {
      return NextResponse.json({ error: "Invalid request payload." }, { status: 400 })
    }

    const { fileName, fileType, autoDelete, filenameMode: filenameModeRaw } = body

    if (!isAutoDeleteOption(autoDelete)) {
      return NextResponse.json({ error: "Invalid auto-delete option." }, { status: 400 })
    }

      const autoDeleteOption: AutoDeleteOption = autoDelete
      const filenameMode = resolveFilenameMode(filenameModeRaw)

      const s3Client = getS3Client()
      const { bucket, region: s3Region } = getS3Config()

      await ensureS3ClientRegion(s3Client, s3Region)

      const extension = extractExtension(fileName)
      const sharePath = await determineSharePath({
        filenameMode,
        originalName: fileName,
        extension,
        s3Client,
        bucket,
      })
      const key = `${FILES_PREFIX}${sharePath}`

      const now = new Date()
      const expiresAtDate = computeExpiry(autoDeleteOption, now)

      const contentType = resolveContentType(fileType)
      const metadata = buildObjectMetadata({
        autoDeleteOption,
        expiresAtDate,
        now,
        filenameMode,
        originalFilename: fileName,
      })

      const requiredHeaders = buildRequiredHeaders({ contentType, metadata })

      const putObject = new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        ContentType: contentType,
        Metadata: metadata,
      })

      const uploadUrl = await getSignedUrl(s3Client, putObject, {
        // Increase the TTL to give S3 presigned URLs breathing room when the hosting
        // environment's clock drifts slightly behind AWS. A shorter 15 minute window
        // led to immediate expirations in production due to clock skew.
        expiresIn: UPLOAD_URL_TTL_SECONDS,
        signingRegion: s3Region,
      })

      maybeLogPresignDebug({
        method: PRESIGNED_HTTP_METHOD,
        presignedUrl: uploadUrl,
        requiredHeaders,
      })

    const payload = {
      uploadUrl,
        requiredHeaders,
      key,
      url: getPublicFileUrl(key),
      sharePath,
      expiresAt: expiresAtDate ? expiresAtDate.toISOString() : null,
      expiryOption: autoDeleteOption,
    }

    return NextResponse.json(payload, { status: 201 })
  } catch (error) {
    console.error("Upload failed", error)
    return NextResponse.json({ error: "Failed to upload file." }, { status: 500 })
  }
}

type RequestBody = {
  fileName: string
  fileType?: string | null
  fileSize?: number
  autoDelete: AutoDeleteOption
  filenameMode?: string | null
}

function isValidRequestBody(value: unknown): value is RequestBody {
  if (!value || typeof value !== "object") return false

  const candidate = value as Partial<RequestBody>
  if (typeof candidate.fileName !== "string" || candidate.fileName.trim().length === 0) {
    return false
  }

  if (candidate.fileType !== undefined && candidate.fileType !== null && typeof candidate.fileType !== "string") {
    return false
  }

  if (candidate.fileSize !== undefined && candidate.fileSize !== null && (typeof candidate.fileSize !== "number" || !Number.isFinite(candidate.fileSize) || candidate.fileSize < 0)) {
    return false
  }

  if (typeof candidate.autoDelete !== "string") {
    return false
  }

  if (candidate.filenameMode !== undefined && candidate.filenameMode !== null && typeof candidate.filenameMode !== "string") {
    return false
  }

  return true
}

type ObjectMetadataParams = {
  autoDeleteOption: AutoDeleteOption
  expiresAtDate: Date | null
  now: Date
  filenameMode: FilenameMode
  originalFilename: string
}

function buildObjectMetadata({ autoDeleteOption, expiresAtDate, now, filenameMode, originalFilename }: ObjectMetadataParams): Record<string, string> {
  return {
    "uploaded-at": now.toISOString(),
    "expiry-option": autoDeleteOption,
    "expires-at": expiresAtDate ? expiresAtDate.toISOString() : "never",
    "original-filename": sanitizeFilename(originalFilename),
    "filename-mode": filenameMode,
  }
}

type RequiredHeadersParams = {
  contentType: string
  metadata: Record<string, string>
}

function buildRequiredHeaders({ contentType, metadata }: RequiredHeadersParams): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": contentType,
  }

  const metadataEntries = Object.entries(metadata).sort(([a], [b]) => a.localeCompare(b))

  for (const [key, value] of metadataEntries) {
    headers[`x-amz-meta-${key}`] = value
  }

  return headers
}

function resolveContentType(fileType: string | null | undefined): string {
  if (typeof fileType === "string" && fileType.trim() !== "") {
    return fileType
  }

  return "application/octet-stream"
}

function extractExtension(filename: string): string {
  const extension = extname(filename.trim())
  if (!extension) return ""
  return extension
}

function sanitizeFilename(filename: string): string {
  if (!filename) return "unknown"

  const normalized = filename.trim().replace(/[\r\n]/g, " ")
  if (normalized.length <= MAX_FILENAME_LENGTH) {
    return normalized
  }

  const extension = extname(normalized)
  const limit = Math.max(0, MAX_FILENAME_LENGTH - extension.length - 3)
  const base = normalized.slice(0, limit)
  return `${base}...${extension}`
}

function resolveFilenameMode(value: unknown): FilenameMode {
  return isFilenameMode(value) ? value : DEFAULT_FILENAME_MODE
}

function isFilenameMode(value: unknown): value is FilenameMode {
  return value === "original" || value === "random"
}

type SharePathParams = {
  filenameMode: FilenameMode
  originalName: string
  extension: string
  s3Client: ReturnType<typeof getS3Client>
  bucket: string
}

async function determineSharePath({ filenameMode, originalName, extension, s3Client, bucket }: SharePathParams): Promise<string> {
  if (filenameMode === "random") {
    const timestamp = Date.now()
    return `${timestamp}-${randomUUID()}${extension}`
  }

  const { baseName } = splitFilename(originalName, extension)
  const sanitizedBase = sanitizeBaseName(baseName)
  const truncatedBase = truncateBase(sanitizedBase, extension)

  return ensureUniqueFilename(truncatedBase, extension, s3Client, bucket)
}

type FilenameParts = {
  baseName: string
  extension: string
}

function splitFilename(filename: string, extension: string): FilenameParts {
  const trimmed = filename.trim()
  if (!extension) {
    return { baseName: trimmed, extension: "" }
  }

  const lowerTrimmed = trimmed.toLowerCase()
  const lowerExtension = extension.toLowerCase()

  if (lowerTrimmed.endsWith(lowerExtension)) {
    return {
      baseName: trimmed.slice(0, trimmed.length - extension.length),
      extension,
    }
  }

  return { baseName: trimmed, extension }
}

function sanitizeBaseName(baseName: string): string {
  const normalized = baseName.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
  const withoutControl = normalized.replace(/[\r\n]+/g, " ")
  const withoutSlashes = withoutControl.replace(/[\\/]+/g, "-")
  const cleaned = withoutSlashes.replace(/[^A-Za-z0-9 ._\-()]+/g, "-")
  const collapsedSpaces = cleaned.replace(/\s+/g, " ")
  const collapsedSeparators = collapsedSpaces.replace(/-+/g, "-")
  const trimmed = collapsedSeparators.trim().replace(/^\.+/, "").replace(/\.+$/, "")

  return trimmed || "file"
}

function truncateBase(baseName: string, extension: string): string {
  const limit = Math.max(1, MAX_FILENAME_LENGTH - extension.length)
  if (baseName.length <= limit) return baseName
  return baseName.slice(0, limit)
}

async function ensureUniqueFilename(baseName: string, extension: string, s3Client: ReturnType<typeof getS3Client>, bucket: string): Promise<string> {
  let attempt = 1
  const maxBaseLength = Math.max(1, MAX_FILENAME_LENGTH - extension.length)

  while (attempt < 10000) {
    const suffix = attempt === 1 ? "" : `(${attempt})`
    const limit = Math.max(1, maxBaseLength - suffix.length)
    const adjustedBase = baseName.length > limit ? baseName.slice(0, limit) : baseName
    const candidate = `${adjustedBase}${suffix}${extension}`
    const key = `${FILES_PREFIX}${candidate}`

    if (!(await objectExists(s3Client, bucket, key))) {
      return candidate
    }

    attempt += 1
  }

  throw new Error("Unable to allocate a unique filename after many attempts.")
}

async function objectExists(s3Client: ReturnType<typeof getS3Client>, bucket: string, key: string): Promise<boolean> {
  try {
    await s3Client.send(
      new HeadObjectCommand({
        Bucket: bucket,
        Key: key,
      }),
    )
    return true
  } catch (error) {
    if (isNotFoundError(error)) {
      return false
    }
    throw error
  }
}

function isNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false

  const serviceError = error as { name?: string; $metadata?: { httpStatusCode?: number } }
  if (serviceError.$metadata?.httpStatusCode === 404) return true

  const name = serviceError.name?.toLowerCase()
  return name === "nosuchkey" || name === "notfound"
}

async function ensureS3ClientRegion(s3Client: ReturnType<typeof getS3Client>, expectedRegion: string): Promise<void> {
  try {
    const regionConfig = s3Client.config.region
    if (!regionConfig) {
      console.warn(`[s3:presign] S3 client is missing a region configuration. Expected "${expectedRegion}".`)
      return
    }

    const resolvedRegion = typeof regionConfig === "function" ? await regionConfig() : regionConfig
    if (!resolvedRegion) {
      console.warn(`[s3:presign] Unable to resolve S3 client region. Expected "${expectedRegion}".`)
      return
    }

    const trimmed = resolvedRegion.trim()
    if (trimmed.length === 0) {
      console.warn(`[s3:presign] Resolved S3 client region was empty. Expected "${expectedRegion}".`)
      return
    }

    if (trimmed !== expectedRegion) {
      console.warn(`[s3:presign] S3 client region "${trimmed}" does not match expected bucket region "${expectedRegion}". Using the expected region for presigning.`)
    }
  } catch (error) {
    console.warn("[s3:presign] Failed to verify S3 client region.", error)
  }
}

type PresignDebugContext = {
  method: string
  presignedUrl: string
  requiredHeaders: Record<string, string>
}

const PRESIGN_DEBUG_ENV_VARS = ["AWS_PRESIGN_DEBUG", "LOG_AWS_PRESIGN", "LOG_S3_PRESIGN", "LOG_CANONICAL_REQUEST"] as const

function maybeLogPresignDebug(context: PresignDebugContext): void {
  if (!shouldLogPresignDebug()) return

  try {
    const { canonicalRequest, stringToSign } = buildPresignDebugArtifacts(context)
    console.info(`[s3:presign] CanonicalRequest\n${canonicalRequest}`)
    console.info(`[s3:presign] StringToSign\n${stringToSign}`)
  } catch (error) {
    console.error("[s3:presign] Failed to compute presign debug details.", error)
  }
}

function shouldLogPresignDebug(): boolean {
  for (const name of PRESIGN_DEBUG_ENV_VARS) {
    const value = process.env[name]
    if (!value) continue

    const normalized = value.trim().toLowerCase()
    if (normalized === "1" || normalized === "true" || normalized === "yes") {
      return true
    }
  }

  return false
}

function buildPresignDebugArtifacts({ method, presignedUrl, requiredHeaders }: PresignDebugContext) {
  const url = new URL(presignedUrl)
  const canonicalUri = url.pathname

  const encodedParams = Array.from(url.searchParams.entries()).map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)] as const)
  encodedParams.sort((a, b) => {
    if (a[0] === b[0]) {
      return a[1].localeCompare(b[1])
    }
    return a[0].localeCompare(b[0])
  })
  const canonicalQueryString = encodedParams.map(([key, value]) => `${key}=${value}`).join("&")

  const signedHeadersParam = url.searchParams.get("X-Amz-SignedHeaders")
  if (!signedHeadersParam) {
    throw new Error("Presigned URL is missing the X-Amz-SignedHeaders parameter.")
  }

  const signedHeaders = signedHeadersParam
    .split(";")
    .map((header) => header.trim().toLowerCase())
    .filter((header) => header.length > 0)

  const normalizedHeaders = normalizeHeaderMap(requiredHeaders)
  const securityToken = url.searchParams.get("X-Amz-Security-Token")
  if (securityToken) {
    normalizedHeaders["x-amz-security-token"] = canonicalizeHeaderValue(securityToken)
  }

  const canonicalHeaders = signedHeaders
    .map((headerName) => {
      let value: string | undefined

      switch (headerName) {
        case "host":
          value = url.host
          break
        case "x-amz-content-sha256":
          value = url.searchParams.get("X-Amz-Content-Sha256") ?? url.searchParams.get("X-Amz-Content-SHA256") ?? "UNSIGNED-PAYLOAD"
          break
        case "x-amz-date":
          value = url.searchParams.get("X-Amz-Date") ?? ""
          break
        default:
          value = normalizedHeaders[headerName]
      }

      if (value === undefined) {
        throw new Error(`Missing value for signed header "${headerName}".`)
      }

      return `${headerName}:${canonicalizeHeaderValue(value)}\n`
    })
    .join("")

  const payloadHash = url.searchParams.get("X-Amz-Content-Sha256") ?? url.searchParams.get("X-Amz-Content-SHA256") ?? "UNSIGNED-PAYLOAD"

  const canonicalRequest = `${method.toUpperCase()}\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeadersParam}\n${payloadHash}`

  const amzDate = url.searchParams.get("X-Amz-Date") ?? ""
  const credential = url.searchParams.get("X-Amz-Credential") ?? ""
  const credentialScope = credential.includes("/") ? credential.split("/").slice(1).join("/") : ""
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${sha256Hex(canonicalRequest)}`

  return { canonicalRequest, stringToSign }
}

function normalizeHeaderMap(headers: Record<string, string>): Record<string, string> {
  return Object.entries(headers).reduce<Record<string, string>>((acc, [key, value]) => {
    acc[key.toLowerCase()] = canonicalizeHeaderValue(value)
    return acc
  }, {})
}

function canonicalizeHeaderValue(value: string): string {
  return value.replace(/\s+/g, " ").trim()
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}
