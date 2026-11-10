import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import api, { tokenStore } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => tokenStore.access);
  const [loading, setLoading] = useState(Boolean(tokenStore.access));

  const logout = useCallback(() => {
    tokenStore.clear();
    setToken(null);
    setUser(null);
  }, []);

  useEffect(() => {
    let cancelled = false;
    if (!token) {
      setLoading(false);
      return undefined;
    }
    setLoading(true);
    api.get('/auth/me')
      .then((response) => { if (!cancelled) setUser(response.data.user); })
      .catch((error) => {
        if (!cancelled && error.response?.status === 401) logout();
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [token, logout]);

  const acceptSession = (data) => {
    tokenStore.set(data);
    setUser(data.user);
    setToken(data.access_token);
    return data;
  };

  const login = async (loginId, password) => {
    const response = await api.post('/auth/login', { login: loginId, password });
    return acceptSession(response.data);
  };

  const signup = async (userData) => {
    const response = await api.post('/auth/signup', userData);
    return acceptSession(response.data);
  };

  const refreshProfile = async () => {
    const response = await api.get('/auth/me');
    setUser(response.data.user);
    return response.data.user;
  };

  const value = useMemo(() => {
    const role = user?.role || 'viewer';
    return {
      user,
      token,
      loading,
      isAuthenticated: Boolean(token && user),
      role,
      isAdmin: role === 'admin',
      canWrite: role === 'admin' || role === 'analyst',
      login,
      signup,
      logout,
      refreshProfile,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, token, loading, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => useContext(AuthContext);
