import jwt from 'jsonwebtoken';

/**
 * Generate JWT token for authenticated user
 * @param {string} userId - User ID
 * @returns {string} JWT token
 */
export const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

/**
 * Verify JWT token
 * @param {string} token - JWT token to verify
 * @returns {object} Decoded token payload
 */
export const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

/**
 * Decode JWT token without verification (for debugging)
 * @param {string} token - JWT token
 * @returns {object} Decoded token
 */
export const decodeToken = (token) => {
  return jwt.decode(token);
};

export default { generateToken, verifyToken, decodeToken };

