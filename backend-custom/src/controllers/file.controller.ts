import { Response } from 'express';
import { AuthenticatedRequest } from '../middlewares/auth.js';
import { fileService } from '../services/file.service.js';
import fs from 'fs';

export class FileController {
  async listFiles(req: AuthenticatedRequest, res: Response): Promise<void> {
    const result = await fileService.listFiles(req.user!.id);
    res.status(result.status).json(result.body);
  }

  async getFileById(req: AuthenticatedRequest, res: Response): Promise<void> {
    const fileId = req.params.id;
    const result = await fileService.getFileMetadata(fileId, req.user!.id);
    res.status(result.status).json(result.body);
  }

  async downloadFileById(req: AuthenticatedRequest, res: Response): Promise<void> {
    const fileId = req.params.id;
    const result = await fileService.prepareDownload(fileId, req.user!.id);

    if (result.status !== 200 || !result.file) {
      res.status(result.status).send(result.errorText || 'Error');
      return;
    }

    const { file, streamOrContent } = result;

    res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${file.fileName}"`);

    if (typeof streamOrContent === 'string') {
      res.status(200).send(streamOrContent);
    } else if (streamOrContent instanceof fs.ReadStream) {
      streamOrContent.pipe(res);
    } else {
      res.status(200).send('');
    }
  }
}

export const fileController = new FileController();
