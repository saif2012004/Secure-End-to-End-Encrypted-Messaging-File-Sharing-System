import { useState, useRef } from 'react';
import { useChatStore } from '../store/chatStore';
import { encryptFile } from '../utils/crypto';
import '../styles/FileUpload.css';

const CHUNK_SIZE = 1024 * 1024; // 1MB chunks

function FileUpload({ recipientId, onClose }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const fileInputRef = useRef(null);
  const { sendFileChunk } = useChatStore();

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      // Check file size (max 10MB for demo)
      if (selectedFile.size > 10 * 1024 * 1024) {
        alert('File size must be less than 10MB');
        return;
      }
      setFile(selectedFile);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setProgress(0);

    try {
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
      const messageId = `msg_${Date.now()}`;

      // Read and upload file in chunks
      for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        // Read chunk as ArrayBuffer
        const arrayBuffer = await chunk.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);

        // NOTE: Placeholder encryption function
        // Members 1 & 2 will implement actual encryption
        const encrypted = await encryptFile(uint8Array, recipientId);

        // Send encrypted chunk
        await sendFileChunk({
          recipientId,
          messageId,
          chunkNumber: i,
          totalChunks,
          encryptedData: encrypted.ciphertext,
          iv: encrypted.iv,
          tag: encrypted.tag,
          hash: encrypted.hash,
          fileName: file.name,
          fileSize: file.size,
          mimeType: file.type,
        });

        // Update progress
        setProgress(Math.round(((i + 1) / totalChunks) * 100));
      }

      alert('File uploaded successfully!');
      onClose();
    } catch (error) {
      console.error('File upload failed:', error);
      alert('File upload failed. Please try again.');
    } finally {
      setUploading(false);
      setProgress(0);
      setFile(null);
    }
  };

  return (
    <div className="file-upload-overlay" onClick={onClose}>
      <div className="file-upload-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>📎 Upload Encrypted File</h3>
          <button className="btn-close" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          {!file ? (
            <div className="file-drop-zone" onClick={() => fileInputRef.current?.click()}>
              <div className="drop-zone-content">
                <span className="upload-icon">📁</span>
                <p>Click to select a file</p>
                <span className="file-hint">Max size: 10MB</span>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileSelect}
                style={{ display: 'none' }}
              />
            </div>
          ) : (
            <div className="file-preview">
              <div className="file-info">
                <span className="file-icon">📄</span>
                <div className="file-details">
                  <p className="file-name">{file.name}</p>
                  <p className="file-size">
                    {(file.size / 1024).toFixed(2)} KB
                  </p>
                  <p className="file-type">{file.type || 'Unknown type'}</p>
                </div>
              </div>

              {uploading && (
                <div className="upload-progress">
                  <div className="progress-bar">
                    <div
                      className="progress-fill"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                  <p className="progress-text">{progress}% uploaded</p>
                </div>
              )}

              <div className="file-actions">
                <button
                  className="btn-secondary"
                  onClick={() => setFile(null)}
                  disabled={uploading}
                >
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  onClick={handleUpload}
                  disabled={uploading}
                >
                  {uploading ? 'Uploading...' : '🔒 Encrypt & Upload'}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <p className="encryption-notice">
            🔒 Files are encrypted before upload
          </p>
        </div>
      </div>
    </div>
  );
}

export default FileUpload;

