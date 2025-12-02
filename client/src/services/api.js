import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Handle response errors
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  register: (username, email, password) =>
    api.post('/auth/register', { username, email, password }),

  login: (email, password) =>
    api.post('/auth/login', { email, password }),

  logout: () =>
    api.post('/auth/logout'),

  getCurrentUser: () =>
    api.get('/auth/me'),

  updatePublicKey: (publicKey) =>
    api.put('/auth/public-key', { publicKey }),
};

// Users API
export const usersAPI = {
  searchUsers: (query) =>
    api.get('/auth/users/search', { params: { query } }),

  getUserById: (userId) =>
    api.get(`/auth/user/${userId}`),
};

// Messages API
export const messagesAPI = {
  sendMessage: (messageData) =>
    api.post('/messages/send', messageData),

  getConversation: (userId, limit = 50, skip = 0) =>
    api.get(`/messages/conversation/${userId}`, {
      params: { limit, skip },
    }),

  getConversations: () =>
    api.get('/messages/conversations'),

  markAsDelivered: (messageId) =>
    api.patch(`/messages/${messageId}/delivered`),

  markAsRead: (messageId) =>
    api.patch(`/messages/${messageId}/read`),

  deleteMessage: (messageId) =>
    api.delete(`/messages/${messageId}`),
};

// Files API
export const filesAPI = {
  uploadChunk: (chunkData) =>
    api.post('/files/upload-chunk', chunkData),

  downloadFile: (messageId) =>
    api.get(`/files/download/${messageId}`),

  getProgress: (messageId) =>
    api.get(`/files/progress/${messageId}`),

  deleteFile: (messageId) =>
    api.delete(`/files/${messageId}`),
};

export default api;

