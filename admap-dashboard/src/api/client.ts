import axios from 'axios';
import { GATEWAY_URL } from '@/lib/config';

/** Construit la baseURL Axios (`<racine>/api`) à partir de l'URL racine du Gateway. */
function apiBaseUrl(rootUrl: string): string {
  return `${rootUrl.replace(/\/$/, '')}/api`;
}

export const apiClient = axios.create({
  baseURL: apiBaseUrl(GATEWAY_URL),
  timeout: 30000,
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // We can add toast notifications here if we want global error handling
    return Promise.reject(error);
  }
);
