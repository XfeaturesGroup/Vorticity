import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search as SearchIcon, User as UserIcon, ArrowRight, Sparkles, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { cn } from "../utils/cn";
import { UserBadge } from './UserBadge';

export const Search = ({ API_URL }) => {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    const [isSearching, setIsSearching] = useState(false);
    const [suggestions, setSuggestions] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        fetch(`${API_URL}/users/suggestions`)
            .then(res => res.ok ? res.json() : [])
            .then(data => setSuggestions(data))
            .catch(err => console.error(err));
    }, [API_URL]);

    useEffect(() => {
        const delayDebounceFn = setTimeout(async () => {
            if (query.length < 2) {
                setResults([]);
                return;
            }

            setIsSearching(true);
            try {
                const res = await fetch(`${API_URL}/search?q=${encodeURIComponent(query)}`);
                if (res.ok) {
                    const data = await res.json();
                    setResults(data);
                }
            } catch (err) {
                console.error(err);
            } finally {
                setIsSearching(false);
            }
        }, 300);

        return () => clearTimeout(delayDebounceFn);
    }, [query, API_URL]);

    return (
        <div className="space-y-6 pb-20">
            <div className="flex items-center gap-4 mb-8">
                <div className="p-3 bg-red-600/20 border border-red-500/50 rounded-xl shadow-[0_0_15px_rgba(220,38,38,0.3)]">
                    <SearchIcon className="text-red-500" size={24} />
                </div>
                <div>
                    <h1 className="text-3xl font-black text-white tracking-tighter uppercase">Поиск</h1>
                    <div className="h-1 w-12 bg-red-600 rounded-full mt-1 shadow-[0_0_10px_red]" />
                </div>
            </div>

            <div className="relative group">
                <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                    {isSearching ? (
                        <Loader2 className="text-red-500 animate-spin" size={20} />
                    ) : (
                        <SearchIcon className="text-zinc-500 group-focus-within:text-red-500 transition-colors" size={20} />
                    )}
                </div>
                <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Поиск по логину или имени..."
                    className="w-full bg-zinc-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white outline-none focus:border-red-500/50 focus:bg-zinc-900/80 transition-all shadow-2xl"
                />
            </div>

            <div className="space-y-4">
                <AnimatePresence mode="wait">
                    {query.length >= 2 ? (
                        <motion.div
                            key="results"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="space-y-2"
                        >
                            <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500 px-2">Результаты поиска</h3>
                            {results.length > 0 ? (
                                results.map(user => <UserCard key={user.id} user={user} navigate={navigate} API_URL={API_URL} />)
                            ) : (
                                !isSearching && <p className="text-zinc-600 text-sm px-2">Никого не нашли...</p>
                            )}
                        </motion.div>
                    ) : (
                        <motion.div
                            key="suggestions"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="space-y-2"
                        >
                            <div className="flex items-center gap-2 px-2 mb-4">
                                <Sparkles size={14} className="text-red-500" />
                                <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Рекомендации</h3>
                            </div>
                            {suggestions.map(user => <UserCard key={user.id} user={user} navigate={navigate} API_URL={API_URL} />)}
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

const UserCard = ({ user, navigate, API_URL }) => {
    const getAvatarUrl = (url) => {
        if (!url) return null;
        if (url.startsWith('http') || url.startsWith('data:')) return url;
        const baseUrl = API_URL.endsWith('/') ? API_URL.slice(0, -1) : API_URL;
        const imageUrl = url.startsWith('/') ? url.slice(1) : url;
        return `${baseUrl}/${imageUrl}`;
    };

    const avatarSrc = getAvatarUrl(user.avatar_url);

    return (
        <motion.div
            whileHover={{ x: 4 }}
            onClick={() => navigate(`/user/${user.username}`)}
            className="group flex items-center gap-4 p-4 bg-zinc-900/30 border border-white/5 rounded-xl cursor-pointer hover:bg-zinc-900/50 hover:border-red-500/30 transition-all"
        >
            <div className="w-12 h-12 flex-shrink-0 rounded-full bg-gradient-to-br from-zinc-800 to-zinc-900 flex items-center justify-center border border-white/10 group-hover:border-red-500/50 transition-colors overflow-hidden">
                {avatarSrc ? (
                    <img
                        src={avatarSrc}
                        alt={user.display_name}
                        className="w-full h-full object-cover"
                        onError={(e) => {
                            e.currentTarget.style.display = 'none';
                            e.currentTarget.nextElementSibling.style.display = 'flex';
                        }}
                    />
                ) : null}
                <UserIcon className={`text-zinc-500 group-hover:text-red-500 transition-colors ${avatarSrc ? 'hidden' : 'flex'}`} size={24} />
            </div>
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                    <h4 className="font-bold text-white truncate group-hover:text-red-500 transition-colors">{user.display_name}</h4>
                    <UserBadge type={user.account_type} iconSize={14} className="flex-shrink-0" />
                </div>
                <p className="text-zinc-500 text-xs truncate">@{user.username}</p>
            </div>
            <ArrowRight size={18} className="text-zinc-700 flex-shrink-0 group-hover:text-red-500 transition-all transform group-hover:translate-x-1" />
        </motion.div>
    );
};