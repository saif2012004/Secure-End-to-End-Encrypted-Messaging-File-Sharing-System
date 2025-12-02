import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { authAPI } from '../services/api';
import '../styles/Auth.css';

function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuthStore();

  const validatePassword = (pwd) => {
    const requirements = [];
    
    if (pwd.length < 8) {
      requirements.push('at least 8 characters');
    }
    if (!/[A-Z]/.test(pwd)) {
      requirements.push('one uppercase letter');
    }
    if (!/[a-z]/.test(pwd)) {
      requirements.push('one lowercase letter');
    }
    if (!/[0-9]/.test(pwd)) {
      requirements.push('one number');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) {
      requirements.push('one special character');
    }

    return requirements;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Validate password match
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Validate password strength
    const passwordIssues = validatePassword(password);
    if (passwordIssues.length > 0) {
      setError(`Password must contain ${passwordIssues.join(', ')}`);
      return;
    }

    setLoading(true);

    try {
      const response = await authAPI.register(username, email, password);
      
      if (response.success) {
        login(response.data.token, response.data.user);
        navigate('/chat');
      } else {
        setError(response.error || 'Registration failed');
      }
    } catch (err) {
      setError(
        err.response?.data?.error || 
        err.response?.data?.details?.join(', ') ||
        'Registration failed. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <div className="auth-header">
          <h1>🔒 Secure Messaging</h1>
          <p>End-to-end encrypted chat</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <h2>Register</h2>

          {error && <div className="error-message">{error}</div>}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Choose a username"
              required
              minLength={3}
              maxLength={30}
              pattern="[a-zA-Z0-9_-]+"
              title="Username can only contain letters, numbers, underscores and hyphens"
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              required
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a strong password"
              required
              minLength={8}
              autoComplete="new-password"
            />
            <small className="form-hint">
              Must contain: uppercase, lowercase, number, and special character
            </small>
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              required
              autoComplete="new-password"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating Account...' : 'Register'}
          </button>

          <div className="auth-footer">
            <p>
              Already have an account?{' '}
              <Link to="/login">Login here</Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Register;

