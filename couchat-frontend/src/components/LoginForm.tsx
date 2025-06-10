// LoginForm.tsx
import React, { useState, ChangeEvent, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as loginService } from '../services/AuthService';
import { useAuth } from '../contexts/AuthContext'; // Import useAuth

const LoginForm: React.FC = () => {
  const navigate = useNavigate();
  const { login: contextLogin } = useAuth(); // Get login function from AuthContext
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false); // For loading state
  const [loginMessage, setLoginMessage] = useState<string>(''); // For displaying login messages

  const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => {
    setUsername(event.target.value);
  };

  const handlePasswordChange = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setLoginMessage(''); // Clear previous messages
    console.log('LoginForm: Attempting login with:', username);

    try {
      const response = await loginService(username, password);
      if (response.success && response.token) { // Check for token as well
        console.log('LoginForm: Login successful via service!', response);
        contextLogin(response.token); // Call context login with the token
        // Clear fields on successful login
        setUsername('');
        setPassword('');
        navigate('/chat'); // Navigate to chat page on success
      } else {
        console.warn('LoginForm: Login failed via service.', response);
        setLoginMessage(`Login failed: ${response.message}`);
      }
    } catch (error) {
      console.error('LoginForm: An error occurred during login:', error);
      setLoginMessage('An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="username">Username:</label>
        <input
          type="text"
          id="username"
          name="username"
          value={username}
          onChange={handleUsernameChange}
          required
        />
      </div>
      <div>
        <label htmlFor="password">Password:</label>
        <input
          type="password"
          id="password"
          name="password"
          value={password}
          onChange={handlePasswordChange}
          required
        />
      </div>
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
      {loginMessage && <p>{loginMessage}</p>}
    </form>
  );
};

export default LoginForm;
