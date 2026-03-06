import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { UserPlus, UserMinus, Check, X, Users, MessageCircle, Search } from 'lucide-react';
import { cn } from "../utils/cn";
import { useNavigate } from 'react-router-dom';
import { UserBadge } from './UserBadge';
import { generateKeyPair, exportPublicKey, savePrivateKey, getPrivateKey } from "../utils/crypto";

export const Friends = ({ API_URL }) => {
    const [friends, setFriends] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('all');

    const fetchFriends = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/friends`, {
                headers: { 'Authorization': localStorage.getItem('token') }
            });
            if (res.ok) {
                const data = await res.json();
                setFriends(data);
            }
        } catch (err) {
            console.error("Error fetching friends:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchFriends();
    }, []);

    const handleAccept = async (targetId) => {
        try {
            const res = await fetch(`${API_URL}/friends/accept`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({ targetId })
            });
            if (res.ok) fetchFriends();
        } catch (err) { console.error(err); }
    };

    const handleRemove = async (targetId) => {
        if (!confirm("Удалить из друзей?")) return;
        try {
            const res = await fetch(`${API_URL}/friends/remove`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({ targetId })
            });
            if (res.ok) fetchFriends();
        } catch (err) { console.error(err); }
    };

    const getCurrentUserId = () => {
        const token = localStorage.getItem('token');
        if (!token) return null;
        try {
            const base64Url = token.split('.')[1];
            if (base64Url) {
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
                return JSON.parse(jsonPayload).id;
            }
        } catch (e) {
            console.error("Token decode error:", e);
        }
        return null;
    };

    const [currentUserId, setCurrentUserId] = useState(null);

    const initCrypto = async (userId) => {
        if (!userId) return;
        try {
            let privKey = await getPrivateKey(userId);
            if (!privKey) {
                const pair = await generateKeyPair();
                await savePrivateKey(userId, pair.privateKey);
                const pubJWK = await exportPublicKey(pair.publicKey);

                await fetch(`${API_URL}/keys/public`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': localStorage.getItem('token')
                    },
                    body: JSON.stringify({ publicKey: pubJWK })
                });
            }
        } catch (err) {
            console.error("Crypto init error:", err);
        }
    };

    useEffect(() => {
        const fetchMe = async () => {
            try {
                const res = await fetch(`${API_URL}/me`, {
                    headers: { 'Authorization': localStorage.getItem('token') }
                });
                if (res.ok) {
                    const data = await res.json();
                    setCurrentUserId(data.id);
                    initCrypto(data.id);
                } else {
                    const id = getCurrentUserId();
                    setCurrentUserId(id);
                    if (id) initCrypto(id);
                }
            } catch (err) {
                const id = getCurrentUserId();
                setCurrentUserId(id);
                if (id) initCrypto(id);
            }
        };
        fetchMe();
    }, [API_URL]);

    const navigate = useNavigate();
    const acceptedFriends = friends.filter(f => f.status === 'accepted');
    const incomingRequests = friends.filter(f => f.status === 'pending' && currentUserId && Number(f.sender_id) !== Number(currentUserId));
    const outgoingRequests = friends.filter(f => f.status === 'pending' && currentUserId && Number(f.sender_id) === Number(currentUserId));

    return (
        <div className="max-w-2xl mx-auto pb-32">
            <div className="flex items-center gap-4 mb-8">
                <div className="p-3 bg-red-600/20 border border-red-500/50 rounded-xl shadow-[0_0_15px_rgba(220,38,38,0.3)]">
                    <Users className="text-red-500" size={24} />
                </div>
                <div>
                    <h1 className="text-3xl font-black text-white tracking-tighter uppercase">Друзья</h1>
                    <div className="h-1 w-12 bg-red-600 rounded-full mt-1 shadow-[0_0_10px_red]" />
                </div>
            </div>

            <div className="flex gap-2 mb-8 bg-zinc-900/50 p-1 rounded-2xl border border-white/5">
                {[
                    { id: 'all', label: 'Друзья', icon: Users },
                    { id: 'requests', label: 'Заявки', icon: UserPlus, count: incomingRequests.length },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={cn(
                            "flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all",
                            activeTab === tab.id ? "bg-white text-black shadow-lg" : "text-zinc-500 hover:text-white hover:bg-white/5"
                        )}
                    >
                        <tab.icon size={16} />
                        {tab.label}
                        {tab.count > 0 && (
                            <span className="bg-red-600 text-white text-[8px] px-1.5 py-0.5 rounded-full ml-1 animate-pulse">
                                {tab.count}
                            </span>
                        )}
                    </button>
                ))}
            </div>

            <AnimatePresence mode="wait">
                {activeTab === 'all' && (
                    <motion.div
                        key="all"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="space-y-3"
                    >
                        {acceptedFriends.length === 0 ? (
                            <div className="text-center py-20 bg-zinc-900/20 rounded-3xl border border-dashed border-white/5">
                                <Users className="mx-auto mb-4 text-zinc-800" size={48} />
                                <p className="text-zinc-500 font-bold uppercase tracking-widest text-xs">Список друзей пуст</p>
                            </div>
                        ) : acceptedFriends.map(friend => (
                            <div key={friend.id} className="flex items-center justify-between p-4 bg-zinc-900/40 backdrop-blur-md border border-white/5 rounded-2xl hover:border-white/10 transition-all group">
                                <div className="flex items-center gap-4 cursor-pointer" onClick={() => navigate(`/user/${friend.username}`)}>
                                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-zinc-800 to-zinc-900 flex items-center justify-center border border-white/10 overflow-hidden">
                                        {friend.avatar_url ? (
                                            <img src={friend.avatar_url} alt="" className="w-full h-full object-cover" />
                                        ) : (
                                            <span className="text-lg font-bold text-red-500">{friend.display_name[0]}</span>
                                        )}
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-bold text-white">{friend.display_name}</h3>
                                        <p className="text-[10px] text-zinc-500 font-medium lowercase tracking-wider">@{friend.username}</p>
                                    </div>
                                </div>
                                <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <button
                                        onClick={async (e) => {
                                            e.stopPropagation();
                                            try {
                                                const res = await fetch(`${API_URL}/chats`, {
                                                    method: 'POST',
                                                    headers: {
                                                        'Content-Type': 'application/json',
                                                        'Authorization': localStorage.getItem('token')
                                                    },
                                                    body: JSON.stringify({ partnerId: friend.id })
                                                });
                                                if (res.ok) {
                                                    navigate('/chats');
                                                }
                                            } catch (err) {
                                                console.error("Error creating chat:", err);
                                                navigate('/chats');
                                            }
                                        }}
                                        className="p-2 text-zinc-500 hover:text-white hover:bg-white/5 rounded-xl transition-all"
                                    >
                                        <MessageCircle size={18} />
                                    </button>
                                    <button onClick={(e) => { e.stopPropagation(); handleRemove(friend.id); }} className="p-2 text-zinc-500 hover:text-red-500 hover:bg-red-500/10 rounded-xl transition-all">
                                        <UserMinus size={18} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </motion.div>
                )}

                {activeTab === 'requests' && (
                    <motion.div
                        key="requests"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="space-y-6"
                    >
                        {incomingRequests.length > 0 && (
                            <div className="space-y-3">
                                <h4 className="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em] ml-2">Входящие заявки</h4>
                                {incomingRequests.map(req => (
                                    <div key={req.id} className="flex items-center justify-between p-4 bg-zinc-900/40 backdrop-blur-md border border-white/5 rounded-2xl">
                                        <div className="flex items-center gap-4 cursor-pointer" onClick={() => navigate(`/user/${req.username}`)}>
                                            <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center border border-white/10 overflow-hidden">
                                                {req.avatar_url ? (
                                                    <img src={req.avatar_url} alt="" className="w-full h-full object-cover" />
                                                ) : (
                                                    <span className="text-lg font-bold text-zinc-500">{req.display_name[0]}</span>
                                                )}
                                            </div>
                                            <div>
                                                <h3 className="text-sm font-bold text-white">{req.display_name}</h3>
                                                <p className="text-[10px] text-zinc-500 font-medium lowercase tracking-wider">@{req.username}</p>
                                            </div>
                                        </div>
                                        <div className="flex gap-2">
                                            <button onClick={() => handleAccept(req.id)} className="p-2 bg-red-600 text-white rounded-xl hover:bg-red-500 transition-all shadow-lg shadow-red-900/20">
                                                <Check size={18} />
                                            </button>
                                            <button onClick={() => handleRemove(req.id)} className="p-2 bg-zinc-800 text-zinc-400 rounded-xl hover:bg-zinc-700 transition-all">
                                                <X size={18} />
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}

                        {outgoingRequests.length > 0 && (
                            <div className="space-y-3">
                                <h4 className="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em] ml-2">Исходящие заявки</h4>
                                {outgoingRequests.map(req => (
                                    <div key={req.id} className="flex items-center justify-between p-4 bg-zinc-900/20 border border-white/5 rounded-2xl opacity-60">
                                        <div className="flex items-center gap-4 cursor-pointer" onClick={() => navigate(`/user/${req.username}`)}>
                                            <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center border border-white/10 overflow-hidden">
                                                {req.avatar_url ? (
                                                    <img src={req.avatar_url} alt="" className="w-full h-full object-cover" />
                                                ) : (
                                                    <span className="text-lg font-bold text-zinc-500">{req.display_name[0]}</span>
                                                )}
                                            </div>
                                            <div>
                                                <h3 className="text-sm font-bold text-white">{req.display_name}</h3>
                                                <p className="text-[10px] text-zinc-500 font-medium lowercase tracking-wider">@{req.username}</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => handleRemove(req.id)}
                                            className="flex items-center gap-2 px-3 py-2 bg-zinc-800/50 hover:bg-red-500/10 text-zinc-500 hover:text-red-500 rounded-xl transition-all text-[10px] font-bold uppercase tracking-widest border border-white/5"
                                        >
                                            <X size={14} /> Отменить
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}

                        {incomingRequests.length === 0 && outgoingRequests.length === 0 && (
                            <div className="text-center py-20">
                                <UserPlus className="mx-auto mb-4 text-zinc-800" size={48} />
                                <p className="text-zinc-500 font-bold uppercase tracking-widest text-xs">Нет активных заявок</p>
                            </div>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};
