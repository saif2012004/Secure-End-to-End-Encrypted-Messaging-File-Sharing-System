import { useState, useRef } from 'react';
import { useSocketStore } from '../store/socketStore';
import { uploadEncryptedFile } from '../services/fileService';
import { keyExchangeService } from '../services/keyExchangeService';
import '../styles/FileUpload.css';

function FileUpload({ recipientId, sessionKeyBytes, onClose }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('');
  const fileInputRef = useRef(null);
  const { socket } = useSocketStore();

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
    setStatus('Encrypting and uploading...');

    try {
      const keyBytes =
        sessionKeyBytes ||
        (await keyExchangeService.getSessionKey(recipientId)) ||
        (await keyExchangeService.waitForSessionKey(recipientId, '', 5000));
      if (!keyBytes) {
        throw new Error('No session key for recipient; finish key exchange first.');
      }
      await uploadEncryptedFile({
        file,
        sessionKeyBytes: keyBytes,
        socket,
        recipientId,
        onProgress: (pct) => setProgress(pct),
      });

      setStatus('Upload complete (encrypted)');
      alert('File uploaded successfully!');
      onClose();
    } catch (error) {
      console.error('File upload failed:', error);
      setStatus(error.message || 'Upload failed');
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
          <h3>Upload Encrypted File</h3>
          <button className="btn-close" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          {!file ? (
            <div className="file-drop-zone" onClick={() => fileInputRef.current?.click()}>
              <div className="drop-zone-content">
                <span className="upload-icon">Upload</span>
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
                <span className="file-icon">File</span>
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
                  <p className="status-text">{status}</p>
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
                  {uploading ? 'Uploading...' : 'Encrypt & Upload'}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <p className="encryption-notice">
            Files are encrypted before upload
          </p>
        </div>
      </div>
    </div>
  );
}

export default FileUpload;

