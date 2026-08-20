import { fileRepository } from '../repositories/file.repository.js';
import { ErrorMessages } from '../constants/errors.js';
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import { env } from '../config/env.js';

export class FileService {
  async listFiles(userId: string) {
    const files = await fileRepository.findByOwnerId(userId);
    return {
      status: 200,
      body: { files },
    };
  }

  async getFileMetadata(fileId: string, userId: string) {
    const file = await fileRepository.findByIdUnscoped(fileId);

    if (!file) {
      return {
        status: 404,
        body: { error: ErrorMessages.FILE_NOT_FOUND },
      };
    }

    if (file.ownerId !== userId) {
      logger.authEvent({
        event: 'IDOR_ACCESS_BLOCKED',
        userId,
        resourceId: fileId,
        details: { actualOwner: file.ownerId },
      });

      return {
        status: 403,
        body: { error: ErrorMessages.FILE_FORBIDDEN },
      };
    }

    return {
      status: 200,
      body: { file },
    };
  }

  async prepareDownload(fileId: string, userId: string) {
    const file = await fileRepository.findByIdUnscoped(fileId);

    if (!file) {
      return {
        status: 404,
        errorText: 'File not found',
      };
    }

    if (file.ownerId !== userId) {
      logger.authEvent({
        event: 'IDOR_ACCESS_BLOCKED',
        userId,
        resourceId: fileId,
        details: { action: 'DOWNLOAD_BLOCKED', actualOwner: file.ownerId },
      });

      return {
        status: 403,
        errorText: 'Forbidden',
      };
    }

    // Resolve physical storage path or fallback to mock stand-in bytes
    const physicalPath = path.resolve(process.cwd(), file.storagePath);
    let streamOrContent: fs.ReadStream | string;

    if (fs.existsSync(physicalPath)) {
      streamOrContent = fs.createReadStream(physicalPath);
    } else {
      // Stand-in content matching mock-api format if physical file on disk wasn't created
      streamOrContent = `This is a stand-in for "${file.fileName}" (${file.mimeType}, ${file.sizeBytes} bytes).\nStored securely under owner: ${file.ownerId}.`;
    }

    return {
      status: 200,
      file,
      streamOrContent,
    };
  }
}

export const fileService = new FileService();
