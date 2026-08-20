import { pool, isPostgresAvailable } from '../config/db.js';

export interface FileRecord {
  id: string;
  ownerId: string;
  fileName: string;
  storagePath: string;
  mimeType: string;
  sizeBytes: number;
  uploadedAt: string;
}

// In-Memory file store
export const memoryFiles = new Map<string, FileRecord>();

export class FileRepository {
  async findByOwnerId(ownerId: string): Promise<FileRecord[]> {
    if (!isPostgresAvailable) {
      const results: FileRecord[] = [];
      for (const f of memoryFiles.values()) {
        if (f.ownerId === ownerId) results.push(f);
      }
      return results.sort((a, b) => a.uploadedAt.localeCompare(b.uploadedAt));
    }

    try {
      const query = `
        SELECT 
          id, owner_id AS "ownerId", file_name AS "fileName",
          storage_path AS "storagePath", mime_type AS "mimeType",
          size_bytes AS "sizeBytes", uploaded_at AS "uploadedAt"
        FROM files
        WHERE owner_id = $1
        ORDER BY uploaded_at ASC
      `;
      const res = await pool.query(query, [ownerId]);
      return res.rows.map((row) => ({
        ...row,
        sizeBytes: Number(row.sizeBytes),
        uploadedAt: row.uploadedAt.toISOString(),
      }));
    } catch {
      const results: FileRecord[] = [];
      for (const f of memoryFiles.values()) {
        if (f.ownerId === ownerId) results.push(f);
      }
      return results;
    }
  }

  async findByIdAndOwner(fileId: string, ownerId: string): Promise<FileRecord | null> {
    if (!isPostgresAvailable) {
      const file = memoryFiles.get(fileId);
      if (!file || file.ownerId !== ownerId) return null;
      return file;
    }

    try {
      const query = `
        SELECT 
          id, owner_id AS "ownerId", file_name AS "fileName",
          storage_path AS "storagePath", mime_type AS "mimeType",
          size_bytes AS "sizeBytes", uploaded_at AS "uploadedAt"
        FROM files
        WHERE id = $1 AND owner_id = $2
      `;
      const res = await pool.query(query, [fileId, ownerId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        ...row,
        sizeBytes: Number(row.sizeBytes),
        uploadedAt: row.uploadedAt.toISOString(),
      };
    } catch {
      const file = memoryFiles.get(fileId);
      if (!file || file.ownerId !== ownerId) return null;
      return file;
    }
  }

  async findByIdUnscoped(fileId: string): Promise<FileRecord | null> {
    if (!isPostgresAvailable) {
      return memoryFiles.get(fileId) || null;
    }

    try {
      const query = `
        SELECT 
          id, owner_id AS "ownerId", file_name AS "fileName",
          storage_path AS "storagePath", mime_type AS "mimeType",
          size_bytes AS "sizeBytes", uploaded_at AS "uploadedAt"
        FROM files
        WHERE id = $1
      `;
      const res = await pool.query(query, [fileId]);
      if (res.rows.length === 0) return null;
      const row = res.rows[0];
      return {
        ...row,
        sizeBytes: Number(row.sizeBytes),
        uploadedAt: row.uploadedAt.toISOString(),
      };
    } catch {
      return memoryFiles.get(fileId) || null;
    }
  }

  async createFile(
    id: string,
    ownerId: string,
    fileName: string,
    storagePath: string,
    mimeType: string,
    sizeBytes: number
  ): Promise<FileRecord> {
    const record: FileRecord = {
      id,
      ownerId,
      fileName,
      storagePath,
      mimeType,
      sizeBytes,
      uploadedAt: new Date().toISOString(),
    };

    memoryFiles.set(id, record);

    if (isPostgresAvailable) {
      try {
        const query = `
          INSERT INTO files (id, owner_id, file_name, storage_path, mime_type, size_bytes)
          VALUES ($1, $2, $3, $4, $5, $6)
        `;
        await pool.query(query, [id, ownerId, fileName, storagePath, mimeType, sizeBytes]);
      } catch {
        // Saved in memory
      }
    }

    return record;
  }
}

export const fileRepository = new FileRepository();
