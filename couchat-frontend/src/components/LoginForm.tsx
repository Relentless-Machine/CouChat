// LoginForm.tsx
import React, { useState, FormEvent } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isRegisterMode, setIsRegisterMode] = useState(true); // Default to register mode

  const { login, register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      if (isRegisterMode) {
        await register({ username, deviceName: deviceName || undefined });
        console.log('LoginForm: Registration successful');
        // Optionally, automatically log in or navigate to a page indicating successful registration
        // For now, we will navigate to chat, assuming registration also logs the user in.
      } else {
        await login({ username, deviceName: deviceName || undefined });
        console.log('LoginForm: Login successful');
      }
      navigate('/chat'); // Navigate to chat page on successful login/registration
    } catch (err: any) {
      const errorMessage = err.message || 'An unexpected error occurred.';
      console.error(isRegisterMode ? 'Registration attempt failed:' : 'Login attempt failed:', errorMessage, err);
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px', width: '300px', margin: 'auto' }}>
      <h2>{isRegisterMode ? 'Register New User' : 'Login'}</h2>
      <div>
        <label htmlFor="username" style={{ display: 'block', marginBottom: '5px' }}>Username:</label>
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          disabled={isSubmitting}
          style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
        />
      </div>
      <div>
        <label htmlFor="deviceName" style={{ display: 'block', marginBottom: '5px' }}>Device Name (Optional):</label>
        <input
          type="text"
          id="deviceName"
          value={deviceName}
          placeholder="e.g., My Laptop, Work PC"
          onChange={(e) => setDeviceName(e.target.value)}
          disabled={isSubmitting}
          style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
        />
      </div>
      {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
      <button type="submit" disabled={isSubmitting} style={{ padding: '10px', cursor: 'pointer' }}>
        {isSubmitting ? 'Processing...' : (isRegisterMode ? 'Register' : 'Login')}
      </button>
      <button
        type="button"
        onClick={() => {
          setIsRegisterMode(!isRegisterMode);
          setError(null); // Clear error when switching modes
        }}
        disabled={isSubmitting}
        style={{ padding: '10px', cursor: 'pointer', backgroundColor: 'grey', color: 'white', border: 'none' }}
      >
        {isRegisterMode ? 'Already have an account? Login' : 'Need an account? Register'}
      </button>
    </form>
  );
};

export default LoginForm;
