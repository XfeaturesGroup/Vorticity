import React, { useState, useEffect, useRef } from 'react';
import { cn } from "./utils/cn";
import { Feed } from "./components/Feed";
import { UserProfile } from "./components/UserProfile";
import { AdminDashboard } from "./components/AdminDashboard";
import { AdminUsers } from "./components/AdminUsers";
import { AdminMedia } from "./components/AdminMedia";
import { Friends } from "./components/Friends";
import { Chats as ChatsPage } from "./components/Chats";
import { AnimatePresence, motion } from 'framer-motion';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Search as SearchPage } from "./components/Search";
import { Settings as SettingsPage } from "./components/Settings";
import { Search, Users, Menu, Home, User, Settings, LogOut, ShieldAlert, Flame, MessageCircle } from 'lucide-react';

import {
    generateKeyPair, exportPublicKey, encryptPrivateKeyForCloud,
    decryptPrivateKeyFromCloud, savePrivateKey, getPrivateKey
} from "./utils/crypto";

const API_URL = import.meta.env.PROD
    ? 'https://vorticity-backend.xfeatures.workers.dev'
    : 'http://localhost:8787';

const TiltCard = ({ children, className }) => {
    const cardRef = useRef(null);
    const [rotation, setRotation] = useState({ x: 0, y: 0 });
    const [glare, setGlare] = useState({ x: 50, y: 50, opacity: 0 });

    const handleMouseMove = (e) => {
        if (!cardRef.current) return;
        const rect = cardRef.current.getBoundingClientRect();
        const xPct = (e.clientX - rect.left) / rect.width - 0.5;
        const yPct = (e.clientY - rect.top) / rect.height - 0.5;
        setRotation({ x: yPct * -5, y: xPct * 5 });
        setGlare({ x: ((e.clientX - rect.left) / rect.width) * 100, y: ((e.clientY - rect.top) / rect.height) * 100, opacity: 1 });
    };

    return (
        <div
            ref={cardRef}
            onMouseMove={handleMouseMove}
            onMouseLeave={() => { setRotation({ x: 0, y: 0 }); setGlare(g => ({ ...g, opacity: 0 })); }}
            className={cn("relative transition-transform duration-200 ease-out", className)}
            style={{ transform: `perspective(1000px) rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)`, transformStyle: 'preserve-3d' }}
        >
            {children}
            <div className="absolute inset-0 pointer-events-none rounded-2xl z-20 transition-opacity duration-300"
                 style={{ background: `radial-gradient(circle at ${glare.x}% ${glare.y}%, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 80%)`, opacity: glare.opacity, mixBlendMode: 'overlay' }} />
        </div>
    );
};

const CyberButton = ({ children, onClick, disabled, className, variant = 'primary', type = "button" }) => (
    <button type={type} onClick={onClick} disabled={disabled} className={cn("relative w-full group cursor-pointer overflow-hidden rounded-md", className)}>
        <div className={cn("absolute inset-0 transition-opacity duration-300 opacity-40 group-hover:opacity-60", variant === 'primary' ? "bg-gradient-to-r from-red-600 to-red-500" : "bg-white/10")} />
        <div className={cn("relative flex items-center justify-center px-6 py-3 font-bold border rounded-md transition-all duration-200", variant === 'primary' ? "bg-black border-red-500/50 text-white hover:border-red-500" : "bg-black/50 border-white/10 text-white/70 hover:text-white hover:border-white/30")}>
            <span className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-red-500/50 group-hover:border-red-500" />
            <span className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-red-500/50 group-hover:border-red-500" />
            {children}
        </div>
    </button>
);

const CyberInput = ({ id, type = "text", placeholder, value, onChange, error }) => {
    const [show, setShow] = useState(false);
    const isPass = type === "password";
    return (
        <div className="mb-4 relative">
            <input id={id} name={id} type={isPass && show ? "text" : type} value={value} onChange={onChange} placeholder={placeholder}
                   className={cn("w-full bg-zinc-900/80 border border-white/10 text-white px-4 py-3 rounded-md outline-none transition-all focus:border-red-500/50 focus:bg-black", error && "border-red-500", isPass && "pr-12")} />
            {isPass && (
                <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white p-1">
                    {show ? "SHW" : "HID"}
                </button>
            )}
        </div>
    );
};

const Navigation = ({ user, logout, pendingRequestsCount, isFullScreenChat }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const [isMenuOpen, setIsMenuOpen] = useState(false);

    const navItems = [
        { id: 'feed', icon: Home, label: 'Лента', path: '/' },
        { id: 'search', icon: Search, label: 'Поиск', path: '/search' },
        { id: 'chats', icon: MessageCircle, label: 'Чаты', path: '/chats' },
        { id: 'friends', icon: Users, label: 'Друзья', path: '/friends', count: pendingRequestsCount },
        { id: 'menu', icon: Menu, label: 'Меню', path: null },
    ];

    const menuActions = [
        { icon: User, label: 'Профиль', onClick: () => navigate(`/user/${user.username}`) },
        { icon: Settings, label: 'Настройки', onClick: () => navigate('/settings') },
        ...(user.is_admin === 1 ? [{ icon: ShieldAlert, label: 'Админ-панель', onClick: () => navigate('/admin'), color: 'text-red-500' }] : []),
        { icon: LogOut, label: 'Выйти', onClick: logout, color: 'text-red-500' },
    ];

    const getActiveIndex = () => {
        if (location.pathname === '/') return 0;
        if (location.pathname.startsWith('/search')) return 1;
        if (location.pathname.startsWith('/chats')) return 2;
        if (location.pathname.startsWith('/friends')) return 3;
        if (location.pathname.startsWith('/user')) return 4;
        return 0;
    };

    return (
        <div className={cn(
            "fixed bottom-12 md:bottom-8 left-1/2 -translate-x-1/2 z-50 transition-all duration-300 pb-[env(safe-area-inset-bottom)]",
            isFullScreenChat ? "translate-y-[200%] opacity-0 md:translate-y-0 md:opacity-100" : "translate-y-0 opacity-100"
        )}>
            <AnimatePresence>
                {isMenuOpen && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 10 }}
                        className="absolute bottom-full left-0 right-0 mb-4 bg-zinc-900/90 backdrop-blur-2xl border border-white/10 rounded-2xl p-2 shadow-2xl flex flex-col gap-1"
                    >
                        {menuActions.map((item, i) => (
                            <button key={i} onClick={() => { item.onClick(); setIsMenuOpen(false); }} className={cn("flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 transition-colors text-sm font-medium", item.color || "text-zinc-300")}>
                                <item.icon size={18} /> {item.label}
                            </button>
                        ))}
                    </motion.div>
                )}
            </AnimatePresence>

            <nav className="relative flex items-center gap-2 px-2 py-2 bg-zinc-900/40 backdrop-blur-2xl border border-white/10 rounded-[24px] shadow-2xl">
                <div className="absolute h-12 bg-red-600/20 border border-red-500/30 rounded-[18px] transition-all duration-500 ease-[cubic-bezier(0.23,1,0.32,1)]"
                     style={{ width: '64px', transform: `translateX(${getActiveIndex() * 72}px)` }} />
                {navItems.map((item) => (
                    <button key={item.id} onClick={() => { if (item.id === 'menu') setIsMenuOpen(!isMenuOpen); else { navigate(item.path); setIsMenuOpen(false); } }}
                            className={cn("relative z-10 flex flex-col items-center justify-center w-16 h-12 transition-colors", getActiveIndex() === navItems.indexOf(item) ? "text-red-500" : "text-zinc-500 hover:text-zinc-300")}>
                        <div className="relative">
                            <item.icon size={20} />
                            {item.count > 0 && (
                                <div className="absolute -top-1.5 -right-1.5 flex items-center justify-center">
                                    <span className="bg-red-600/90 backdrop-blur-sm text-white text-[9px] font-black min-w-[16px] h-[16px] flex items-center justify-center rounded-full border border-white/10 shadow-[0_0_10px_rgba(220,38,38,0.3)] px-1">
                                        {item.count}
                                    </span>
                                </div>
                            )}
                        </div>
                        <span className="text-[8px] mt-1 font-bold uppercase tracking-widest">{item.label}</span>
                    </button>
                ))}
            </nav>
        </div>
    );
};

const AdminRoute = ({ user, children }) => {
    if (!user || user.is_admin !== 1) {
        return <Navigate to="/" replace />;
    }
    return children;
};

function App() {
    const [user, setUser] = useState(null);
    const [pendingRequestsCount, setPendingRequestsCount] = useState(0);
    const [authView, setAuthView] = useState('login');
    const [errorMsg, setErrorMsg] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [formData, setFormData] = useState({ username: '', display_name: '', email: '', password: '' });
    const [require2FA, setRequire2FA] = useState(false);
    const [code2FA, setCode2FA] = useState('');


    useEffect(() => {
        const checkAuth = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                setIsLoading(false);
                return;
            }

            try {
                const res = await fetch(`${API_URL}/me`, {
                    headers: { 'Authorization': token }
                });
                if (res.ok) {
                    const userData = await res.json();
                    setUser(userData);
                    fetchPendingRequests();
                } else {
                    localStorage.removeItem('token');
                }
            } catch (err) {
                console.error("Ошибка проверки сессии:", err);
            } finally {
                setTimeout(() => setIsLoading(false), 300);
            }
        };

        checkAuth();
    }, []);

    const fetchPendingRequests = async () => {
        const token = localStorage.getItem('token');
        if (!token || !user) return;

        try {
            const res = await fetch(`${API_URL}/friends`, {
                headers: { 'Authorization': token }
            });
            if (res.ok) {
                const friends = await res.json();
                if (Array.isArray(friends)) {
                    const incoming = friends.filter(f => f.status === 'pending' && Number(f.sender_id) !== Number(user.id));
                    setPendingRequestsCount(incoming.length);
                }
            }
        } catch (err) {
            console.error("Ошибка получения заявок:", err);
        }
    };

    useEffect(() => {
        if (user) {
            fetchPendingRequests();
            const interval = setInterval(fetchPendingRequests, 10000);
            return () => clearInterval(interval);
        }
    }, [user]);

    useEffect(() => {
        const handleFocus = () => {
            if (user) {
                fetchPendingRequests();
                window.dispatchEvent(new CustomEvent('app-focused'));
            }
        };

        window.addEventListener('focus', handleFocus);
        return () => window.removeEventListener('focus', handleFocus);
    }, [user]);

    const handleChange = (e) => setFormData({ ...formData, [e.target.name]: e.target.value });

    const syncE2EKeys = async (userId, username, password, token) => {
        try {
            const salt = userId.toString();
            let privKey = await getPrivateKey(userId);

            const res = await fetch(`${API_URL}/keys/cloud`, { headers: { 'Authorization': token } });
            if (res.ok) {
                const { encryptedPrivateKey } = await res.json();

                if (encryptedPrivateKey) {
                    if (!privKey) {
                        const decryptedKey = await decryptPrivateKeyFromCloud(encryptedPrivateKey, password, salt);
                        if (decryptedKey) {
                            await savePrivateKey(userId, decryptedKey);
                        }
                    }
                    return;
                }
            }

            const pair = await generateKeyPair();
            const pubJWK = await exportPublicKey(pair.publicKey);
            const encryptedForCloud = await encryptPrivateKeyForCloud(pair.privateKey, password, salt);

            const initRes = await fetch(`${API_URL}/keys/init`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': token },
                body: JSON.stringify({ publicKey: pubJWK, encryptedPrivateKey: encryptedForCloud })
            });

            if (initRes.ok) {
                await savePrivateKey(userId, pair.privateKey);
            }
        } catch (err) {
            console.error("Ошибка синхронизации E2EE:", err);
        }
    };

    const handleAuth = async (e) => {
        e.preventDefault();
        setErrorMsg('');
        setIsSubmitting(true);
        try {
            const payload = { ...formData };
            if (require2FA) payload.code = code2FA;

            const res = await fetch(`${API_URL}${authView === 'register' ? '/register' : '/login'}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            if (res.ok && data.require2fa) {
                setRequire2FA(true);
                setIsSubmitting(false);
                return;
            }

            if (!res.ok) throw new Error(data.error);

            await syncE2EKeys(data.id, payload.username, payload.password, data.token);

            localStorage.setItem('token', data.token);
            setUser(data);
            setRequire2FA(false);
            setCode2FA('');

            setFormData({ username: '', display_name: '', email: '', password: '' });
        } catch (err) {
            setErrorMsg(err.message);
        } finally {
            setIsSubmitting(false);
        }
    };

    const logout = () => { localStorage.removeItem('token'); setUser(null); };

    return (
        <Router>
            <AppContent
                user={user}
                setUser={setUser}
                isLoading={isLoading}
                authView={authView}
                setAuthView={setAuthView}
                errorMsg={errorMsg}
                setErrorMsg={setErrorMsg}
                isSubmitting={isSubmitting}
                formData={formData}
                handleChange={handleChange}
                handleAuth={handleAuth}
                logout={logout}
                pendingRequestsCount={pendingRequestsCount}
                require2FA={require2FA}
                setRequire2FA={setRequire2FA}
                code2FA={code2FA}
                setCode2FA={setCode2FA}
            />
        </Router>
    );
}

function AppContent({
    user, setUser, isLoading, authView, setAuthView,
    errorMsg, setErrorMsg, isSubmitting, formData,
    handleChange, handleAuth, logout, pendingRequestsCount,
    require2FA, setRequire2FA, code2FA, setCode2FA
    }) {
    const location = useLocation();
    const [isFullScreenChat, setIsFullScreenChat] = useState(false);

    return (
        <div className="min-h-screen w-full flex flex-col items-center bg-black text-white relative overflow-x-hidden p-4">
            <div className={cn("fixed inset-0 z-[100] bg-black transition-all duration-500 pointer-events-none", isLoading ? "opacity-100 backdrop-blur-md" : "opacity-0 backdrop-blur-0")} />
            <div className="absolute inset-0 opacity-20 pointer-events-none" style={{ backgroundImage: 'linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

            <div className={cn(
                "relative z-10 w-full mt-10 transition-opacity duration-500",
                location.pathname.startsWith('/admin') ? "max-w-5xl" : "max-w-2xl",
                isLoading ? "opacity-0" : "opacity-100",
                isFullScreenChat && "mt-0 max-w-full p-0 h-[100dvh] md:mt-10 md:max-w-2xl md:p-4 md:h-auto"
            )}>
                {}
                <div className="text-center mb-10 hidden md:block">
                    <h1 className="text-5xl font-bold tracking-tighter mb-2">Vorticity</h1>
                    <div className="h-1 w-20 mx-auto bg-red-600 rounded-full shadow-[0_0_15px_red]" />
                </div>

                {}
                {!isFullScreenChat && (
                     <div className="text-center mb-10 md:hidden block">
                        <h1 className="text-5xl font-bold tracking-tighter mb-2">Vorticity</h1>
                        <div className="h-1 w-20 mx-auto bg-red-600 rounded-full shadow-[0_0_15px_red]" />
                    </div>
                )}

                {!user ? (
                    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
                        <TiltCard className="max-w-md mx-auto">
                            <div className="bg-zinc-950/80 backdrop-blur-md border border-white/10 rounded-2xl p-8 shadow-2xl">
                                <form onSubmit={handleAuth} className="space-y-4">
                                    <h2 className="text-xl font-bold text-center uppercase tracking-widest mb-6 border-b border-white/10 pb-4">
                                        {require2FA ? 'Двухфакторная защита' : (authView === 'login' ? 'Авторизация' : 'Регистрация')}
                                    </h2>

                                    {!require2FA ? (
                                        <>
                                            {authView === 'register' && <CyberInput id="display_name" placeholder="Отображаемое имя" value={formData.display_name} onChange={handleChange} />}
                                            {authView === 'register' && <CyberInput id="email" type="email" placeholder="Email" value={formData.email} onChange={handleChange} />}
                                            <CyberInput id="username" placeholder="Логин" value={formData.username} onChange={handleChange} />
                                            <CyberInput id="password" type="password" placeholder="Пароль" value={formData.password} onChange={handleChange} />
                                        </>
                                    ) : (
                                        <div className="space-y-4">
                                            <p className="text-center text-sm text-zinc-400">Введите 6-значный код из Authenticator</p>
                                            <CyberInput
                                                id="code2FA"
                                                type="text"
                                                placeholder="000000"
                                                value={code2FA}
                                                onChange={(e) => setCode2FA(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                            />
                                        </div>
                                    )}

                                    {errorMsg && <p className="text-red-500 text-xs text-center">{errorMsg}</p>}

                                    <CyberButton type="submit" disabled={isSubmitting || (require2FA && code2FA.length !== 6)}>
                                        {isSubmitting ? 'PROCESSING...' : (require2FA ? 'ПОДТВЕРДИТЬ' : (authView === 'login' ? 'ENTER SYSTEM' : 'REGISTER'))}
                                    </CyberButton>

                                    {!require2FA ? (
                                        <button type="button" className="w-full text-center text-xs text-zinc-500 hover:text-red-400 mt-4 uppercase tracking-wider" onClick={() => setAuthView(authView === 'login' ? 'register' : 'login')}>
                                            {authView === 'login' ? '[ Create New Identity ]' : '[ Return to Login ]'}
                                        </button>
                                    ) : (
                                        <button type="button" className="w-full text-center text-xs text-zinc-500 hover:text-red-400 mt-4 uppercase tracking-wider" onClick={() => setRequire2FA(false)}>
                                            [ Cancel Login ]
                                        </button>
                                    )}
                                </form>
                            </div>
                        </TiltCard>
                    </motion.div>
                ) : (
                    <div className={cn("pb-32", isFullScreenChat && "pb-0 h-full md:pb-32 md:h-auto")}>
                        <Routes>
                            <Route path="/" element={<Feed user={user} API_URL={API_URL} />} />
                            <Route path="/search" element={<SearchPage API_URL={API_URL} />} />
                            <Route path="/chats" element={<ChatsPage currentUser={user} API_URL={API_URL} setIsFullScreenChat={setIsFullScreenChat} />} />
                            <Route path="/friends" element={<Friends API_URL={API_URL} />} />
                            <Route path="/user/:username" element={<UserProfile currentUser={user} API_URL={API_URL} />} />
                            <Route path="/settings" element={<SettingsPage user={user} API_URL={API_URL} onUpdateUser={(updatedFields) => setUser({ ...user, ...updatedFields })}/>}/>

                            <Route path="/admin" element={<AdminRoute user={user}><AdminDashboard user={user} /></AdminRoute>} />
                            <Route path="/admin/users" element={<AdminRoute user={user}><AdminUsers /></AdminRoute>} />
                            <Route path="/admin/media" element={<AdminRoute user={user}><AdminMedia /></AdminRoute>} />

                            <Route path="*" element={<Navigate to="/" />} />
                        </Routes>
                    </div>
                )}
            </div>

            {user && <Navigation user={user} logout={logout} pendingRequestsCount={pendingRequestsCount} isFullScreenChat={isFullScreenChat} />}
        </div>
    );
}

export default App;
