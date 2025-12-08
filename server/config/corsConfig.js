/**
 * CORS configuration for Express
 * Supports comma-separated origins in env for local dev (e.g., http://localhost:5173,http://localhost:3000)
 */
const rawOrigins = process.env.CORS_ORIGIN || 'http://localhost:3000';
const originList = rawOrigins.split(',').map((o) => o.trim()).filter(Boolean);

export const corsOptions = {
  origin: originList.length === 1 ? originList[0] : originList,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

export default corsOptions;

