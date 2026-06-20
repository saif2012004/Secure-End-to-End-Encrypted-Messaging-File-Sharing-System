import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Login from './pages/Login';
import Register from './pages/Register';
import Chat from './pages/Chat';
import { useAuthStore } from './store/authStore';
import { pageVariants } from './animations/variants';

function Page({ children }) {
  return (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
      style={{ height: '100%' }}
    >
      {children}
    </motion.div>
  );
}

function AnimatedRoutes() {
  const { isAuthenticated } = useAuthStore();
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route
          path="/login"
          element={!isAuthenticated ? <Page><Login /></Page> : <Navigate to="/chat" />}
        />
        <Route
          path="/register"
          element={!isAuthenticated ? <Page><Register /></Page> : <Navigate to="/chat" />}
        />
        <Route
          path="/chat"
          element={isAuthenticated ? <Page><Chat /></Page> : <Navigate to="/login" />}
        />
        <Route path="/" element={<Navigate to="/chat" />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  return (
    <Router>
      <AnimatedRoutes />
    </Router>
  );
}

export default App;
