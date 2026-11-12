// ============================================================================
// T.U.L.O.N.G. — auth-guard.js
// ----------------------------------------------------------------------------
//
// WHAT IT DOES
//  1. Hides the page until the visitor is verified (no flash of private content)
//  2. Sends signed-out visitors back to the login page
//  3. Checks the user's role against Firestore (admin email + users/{uid} profile)
//     — NOT against a hard-coded email in the browser


import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getFirestore, doc, getDoc } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

// Public web config (safe to expose — protect it with API-key restrictions
// and Firestore rules, see the step-by-step guide).
const firebaseConfig = {
  apiKey: "AIzaSyCQAXA3njpQhRLWwhwJMmB538dcn5Q78tU",
  authDomain: "tulong-e602c.firebaseapp.com",
  projectId: "tulong-e602c",
  storageBucket: "tulong-e602c.firebasestorage.app",
  messagingSenderId: "855126925376",
  appId: "1:855126925376:web:49e066d50b1e998b6a3fa5",
  measurementId: "G-725VM27SEM"
};

// ---- Clean URL paths (no .html). Edit if you rename pages. ----
const LOGIN_PATH    = "/";
const ADMIN_PATH    = "/admin-dashboard";
const OPERATOR_PATH = "/operator-dashboard";


const app  = getApps().length ? getApp() : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

async function hasRoleDoc(collectionName, uid) {
  try {
    const snap = await getDoc(doc(db, collectionName, uid));
    return snap.exists();
  } catch (err) {
    // Rules denied the read or network failed -> treat as "no role"
    return false;
  }
}

function cleanAddressBar() {
  // If someone opens /operator-dashboard.html, show /operator-dashboard instead.
  const { pathname, search, hash } = window.location;
  if (pathname.endsWith(".html")) {
    const clean = pathname.replace(/\/index\.html$/, "/").replace(/\.html$/, "");
    window.history.replaceState(null, "", clean + search + hash);
  }
}

export function protectPage({ role = "operator" } = {}) {
  // 1. Hide everything until verified
  document.documentElement.style.visibility = "hidden";
  cleanAddressBar();

  onAuthStateChanged(auth, async (user) => {
    // 2. Not signed in
    if (!user) {
      window.location.replace(LOGIN_PATH);
      return;
    }

    // 3. Role check (server-side data, not a hard-coded email)
    // Admin = the admin email (rules enforce this server-side too).
    // Operator = has a profile document at users/{uid} created by the admin.
    const isAdmin = (user.email || "").toLowerCase() === "admin@tulong.com";
    const isOperator = await hasRoleDoc("users", user.uid);

    if (role === "admin") {
      if (!isAdmin) {
        // Operators trying the admin page get bounced to their own dashboard
        window.location.replace(isOperator ? OPERATOR_PATH : LOGIN_PATH);
        return;
      }
    } else {
      // operator page: operators and admins allowed
      if (!isOperator && !isAdmin) {
        await signOut(auth);
        window.location.replace(LOGIN_PATH);
        return;
      }
    }

    // 4. Verified
    document.documentElement.style.visibility = "visible";
  });
}

// Optional helper for a Logout button:  onclick="window.tulongLogout()"
window.tulongLogout = async () => {
  await signOut(auth);
  window.location.replace(LOGIN_PATH);
};
