// Shared Framer Motion variants & transitions for the app.
// Keeping them centralized makes motion consistent and easy to tune.

export const spring = { type: 'spring', stiffness: 380, damping: 30 };
export const softSpring = { type: 'spring', stiffness: 260, damping: 26 };
export const ease = [0.22, 1, 0.36, 1];

/* ---- Page (route) transitions ---- */
export const pageVariants = {
  initial: { opacity: 0, y: 14, scale: 0.99 },
  animate: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.4, ease } },
  exit: { opacity: 0, y: -10, scale: 0.99, transition: { duration: 0.25, ease } },
};

/* ---- Staggered list container ---- */
export const listContainer = {
  hidden: { opacity: 1 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.07, delayChildren: 0.05 },
  },
};

/* ---- Generic list item (sidebar, welcome features) ---- */
export const listItem = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: softSpring },
  exit: { opacity: 0, x: -24, transition: { duration: 0.2, ease } },
};

/* ---- Chat message bubble (enter / exit) ---- */
export const messageVariant = {
  hidden: { opacity: 0, y: 18, scale: 0.92 },
  show: { opacity: 1, y: 0, scale: 1, transition: spring },
  exit: { opacity: 0, scale: 0.9, transition: { duration: 0.18, ease } },
};

/* ---- Modal + backdrop ---- */
export const backdropVariant = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { duration: 0.2 } },
  exit: { opacity: 0, transition: { duration: 0.18 } },
};

export const modalVariant = {
  hidden: { opacity: 0, y: 30, scale: 0.94 },
  show: { opacity: 1, y: 0, scale: 1, transition: { ...spring, stiffness: 300 } },
  exit: { opacity: 0, y: 20, scale: 0.96, transition: { duration: 0.2, ease } },
};

/* ---- Reusable gesture props ---- */
export const tapScale = { whileTap: { scale: 0.92 } };
export const hoverLift = {
  whileHover: { y: -2, scale: 1.04 },
  whileTap: { scale: 0.96 },
};
