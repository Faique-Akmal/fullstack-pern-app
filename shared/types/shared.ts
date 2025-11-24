// Common interfaces for both frontend and backend

// Base User interface (without password - for frontend safety)
export interface User {
  id: number;
  username: string;
  email: string;
  created_at: string;
}

// User with password (for backend/internal use only)
export interface UserWithPassword extends User {
  password: string;
}

// Request interfaces
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

// Response interfaces
export interface AuthResponse {
  message: string;
  user: User;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}