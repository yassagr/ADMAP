import axios from 'axios';

export const apiClient = axios.create({
  baseURL: 'http://localhost:9000/api',
  timeout: 30000,
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // We can add toast notifications here if we want global error handling
    return Promise.reject(error);
  }
);
