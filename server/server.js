import express from 'express';
import { createServer } from 'http';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import connectDB from './config/db.js';
import corsOptions from './config/corsConfig.js';
import { generalLimiter } from './config/rateLimitConfig.js';
import { requestLogger, errorLogger } from './middlewares/loggingMiddleware.js';
import { initializeSocket } from './sockets/chatSocket.js';
import { logger } from './utils/logger.js';

// Import routes
import authRoutes from './routes/authRoutes.js';
import messageRoutes from './routes/messageRoutes.js';
import fileRoutes from './routes/fileRoutes.js';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Create HTTP server
const server = createServer(app);

// Initialize Socket.io
const io = initializeSocket(server);

// Make io accessible to route handlers
app.set('io', io);

// Security middleware
app.use(helmet());

// CORS middleware
app.use(cors(corsOptions));

// Body parser middleware
app.use(express.json({ limit: '10mb' })); // For encrypted file chunks
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use(requestLogger);

// Rate limiting
app.use(generalLimiter);

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Information Security Project - Backend API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      messages: '/api/messages',
      files: '/api/files',
      health: '/health',
    },
  });
});

// 404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.originalUrl,
  });
});

// Error handling middleware (must be last)
app.use(errorLogger);

// Get port from environment or default to 5000
const PORT = process.env.PORT || 5000;

// Connect to database and start server
const startServer = async () => {
  try {
    // Connect to MongoDB
    await connectDB();

    // Start HTTP server
    server.listen(PORT, () => {
      logger.info(`Server running in ${process.env.NODE_ENV || 'development'} mode`);
      logger.info(`Server listening on port ${PORT}`);
      logger.info(`Socket.io initialized and listening`);
      console.log('\n=================================');
      console.log(`🚀 Server is running on port ${PORT}`);
      console.log(`🔗 API: http://localhost:${PORT}`);
      console.log(`🔌 Socket.io: ws://localhost:${PORT}`);
      console.log('=================================\n');
    });
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error(`Unhandled Rejection: ${err.message}`);
  logger.error(err.stack);
  
  // Close server and exit
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error(`Uncaught Exception: ${err.message}`);
  logger.error(err.stack);
  
  // Close server and exit
  server.close(() => {
    process.exit(1);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

// Start the server
startServer();

export default app;

