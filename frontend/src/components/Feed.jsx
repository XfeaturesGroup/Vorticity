import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { cn } from "../utils/cn";
import { formatRelativeTime } from "../utils/formatDate";
import { PullToRefresh } from "./PullToRefresh";
import { PostContent } from './PostContent';
import { UserBadge } from './UserBadge';
import {
    ImagePlus, Trash2, Edit3, Check, X, Heart, MessageSquare, Send, User as UserIcon,
    ChevronDown, ChevronUp, Home, Loader2, Sparkles
} from 'lucide-react';

const CommentSection = ({ postId, API_URL, currentUser }) => {
    const [comments, setComments] = useState([]);
    const [text, setText] = useState('');
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    const fetchComments = async () => {
        try {
            const res = await fetch(`${API_URL}/posts/${postId}/comments`);
            if (res.ok) {
                const data = await res.json();
                setComments(data);
            }
        } catch (err) {
            console.error("Ошибка загрузки комментариев:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchComments(); }, [postId]);

    const submitComment = async (e) => {
        e.preventDefault();
        if (!text.trim()) return;
        try {
            const res = await fetch(`${API_URL}/posts/${postId}/comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({ content: text })
            });
            if (res.ok) {
                setText('');
                fetchComments();
            }
        } catch (err) {
            console.error("Ошибка отправки комментария:", err);
        }
    };

    return (
        <div className="mt-4 pt-4 border-t border-white/5 space-y-4">
            <form onSubmit={submitComment} className="flex gap-2">
                <input
                    type="text"
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    placeholder="Написать комментарий..."
                    className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs outline-none focus:border-red-500/50 transition-colors"
                />
                <button type="submit" className="p-1.5 text-zinc-500 hover:text-red-500 transition-colors">
                    <Send size={18} />
                </button>
            </form>
            <div className="space-y-3 max-h-60 overflow-y-auto pr-2">
                {loading ? (
                    <div className="text-[10px] text-zinc-600 uppercase animate-pulse">Загрузка...</div>
                ) : comments.map(comment => (
                    <div key={comment.id} className="flex gap-2 group">
                        <div
                            className="w-6 h-6 rounded-full bg-zinc-800 flex items-center justify-center flex-shrink-0 overflow-hidden cursor-pointer"
                            onClick={() => navigate(`/user/${comment.username}`)}
                        >
                            {comment.avatar_url ? (
                                <img src={comment.avatar_url} alt="" className="w-full h-full object-cover" />
                            ) : (
                                <UserIcon size={12} className="text-zinc-500" />
                            )}
                        </div>
                        <div className="flex-1">
                            <div className="flex items-center gap-2">
                                <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] font-bold text-zinc-400 cursor-pointer hover:text-red-500 transition-colors" onClick={() => navigate(`/user/${comment.username}`)}>
                                        {comment.display_name}
                                    </span>
                                    <UserBadge type={comment.account_type} iconSize={12} />
                                </div>
                                <span className="text-[8px] text-zinc-600">{formatRelativeTime(comment.created_at)}</span>
                            </div>
                            <p className="text-[11px] text-zinc-300 leading-relaxed">{comment.content}</p>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

const PostImages = ({ imagesJson }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const [shouldShowExpand, setShouldShowExpand] = useState(false);
    const contentRef = useRef(null);
    const maxHeight = 1200;

    useEffect(() => {
        if (contentRef.current) {
            setShouldShowExpand(contentRef.current.scrollHeight > maxHeight);
        }
    }, [imagesJson]);

    if (!imagesJson) return null;

    try {
        const images = typeof imagesJson === 'string' ? JSON.parse(imagesJson) : imagesJson;
        if (!Array.isArray(images) || images.length === 0) return null;

        return (
            <div className="relative mt-3 overflow-hidden">
                <div
                    ref={contentRef}
                    className={cn(
                        "grid gap-2 transition-all duration-500 ease-in-out",
                        images.length === 1 ? "grid-cols-1" : "grid-cols-2",
                        !isExpanded && shouldShowExpand ? "max-h-[1200px]" : "max-h-none"
                    )}
                >
                    {images.map((url, idx) => (
                        <img
                            key={idx}
                            src={url}
                            alt=""
                            className={cn(
                                "w-full object-cover rounded-lg border border-white/5 hover:border-white/20 transition-colors",
                                images.length === 1 ? "max-h-[600px]" : "aspect-square"
                            )}
                            loading="lazy"
                        />
                    ))}
                </div>

                {!isExpanded && shouldShowExpand && (
                    <div className="absolute bottom-0 left-0 right-0 h-40 bg-gradient-to-t from-black to-transparent flex items-end justify-center pb-4">
                        <button
                            onClick={() => setIsExpanded(true)}
                            className="flex items-center gap-2 bg-zinc-900/90 backdrop-blur-md border border-white/10 px-4 py-2 rounded-full text-[10px] font-bold uppercase tracking-widest hover:bg-red-600 transition-colors"
                        >
                            <ChevronDown size={14} /> Показать полностью
                        </button>
                    </div>
                )}

                {isExpanded && shouldShowExpand && (
                    <button
                        onClick={() => setIsExpanded(false)}
                        className="mt-4 w-full flex items-center justify-center gap-2 bg-zinc-900/50 border border-white/5 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest hover:bg-white/5 transition-colors"
                    >
                        <ChevronUp size={14} /> Свернуть
                    </button>
                )}
            </div>
        );
    } catch (e) { return null; }
};

export const Feed = ({ user, API_URL }) => {
    const [posts, setPosts] = useState([]);
    const [activeTab, setActiveTab] = useState(() => sessionStorage.getItem('feedTab') || 'recommended');
    const [newPost, setNewPost] = useState('');
    const [files, setFiles] = useState([]);
    const [editingId, setEditingId] = useState(null);
    const [editContent, setEditContent] = useState('');
    const [expandedComments, setExpandedComments] = useState({});
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const navigate = useNavigate();
    const viewedPosts = useRef(new Set());
    const MAX_CHARS = 4000;
    const scrollRestored = useRef(false);

    const fetchPosts = async () => {
        try {
            const res = await fetch(`${API_URL}/posts?tab=${activeTab}`, {
                headers: { 'Authorization': localStorage.getItem('token') || '' }
            });
            if (res.ok) {
                const data = await res.json();
                setPosts(data);
                setHasMore(data.length === 20);
                scrollRestored.current = false;
            }
        } catch (err) {
            console.error("Ошибка загрузки ленты:", err);
        }
    };

    useEffect(() => {
        sessionStorage.setItem('feedTab', activeTab);
        fetchPosts();
    }, [activeTab]);

    useEffect(() => {
        if (posts.length > 0 && !scrollRestored.current) {
            const savedScroll = sessionStorage.getItem(`scrollPosition_${activeTab}`);
            if (savedScroll) {
                window.scrollTo(0, parseInt(savedScroll, 10));
            }
            scrollRestored.current = true;
        }
    }, [posts, activeTab]);

    const loadMore = async () => {
        if (isLoadingMore || !hasMore || posts.length === 0) return;
        setIsLoadingMore(true);
        try {
            let url = `${API_URL}/posts?tab=${activeTab}`;

            if (activeTab === 'new') {
                const lastId = posts[posts.length - 1].id;
                url += `&cursor=${lastId}`;
            } else if (activeTab === 'recommended') {
                url += `&offset=${posts.length}`;
            }

            const res = await fetch(url, {
                headers: { 'Authorization': localStorage.getItem('token') || '' }
            });

            if (res.ok) {
                const data = await res.json();
                if (data.length === 0) {
                    setHasMore(false);
                } else {
                    setPosts(prev => [...prev, ...data]);
                }
            }
        } catch (err) {
            console.error("Ошибка при дозагрузке:", err);
        } finally {
            setIsLoadingMore(false);
        }
    };

    useEffect(() => {
        const handleScroll = () => {
            sessionStorage.setItem(`scrollPosition_${activeTab}`, window.scrollY);
            if (window.innerHeight + document.documentElement.scrollTop + 150 >= document.documentElement.offsetHeight) {
                loadMore();
            }
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, [hasMore, isLoadingMore, activeTab, posts]);

    const handleLike = async (postId) => {
        setPosts(currentPosts => currentPosts.map(post => {
            if (post.id === postId) {
                const isLiked = !post.is_liked;
                return {
                    ...post,
                    is_liked: isLiked,
                    likes_count: post.likes_count + (isLiked ? 1 : -1)
                };
            }
            return post;
        }));

        try {
            await fetch(`${API_URL}/posts/${postId}/like`, {
                method: 'POST',
                headers: { 'Authorization': localStorage.getItem('token') || '' }
            });
        } catch (err) {
            console.error("Ошибка при лайке:", err);
        }
    };

    const toggleComments = (postId) => {
        setExpandedComments(prev => ({ ...prev, [postId]: !prev[postId] }));
    };

    const handleFileChange = (e) => {
        const selectedFiles = Array.from(e.target.files);
        const validFiles = selectedFiles.filter(file =>
            ['image/png', 'image/jpeg', 'image/gif', 'image/jpg'].includes(file.type) &&
            file.size <= 25 * 1024 * 1024
        );
        if (validFiles.length + files.length > 6) return alert("Максимум 6 изображений");
        setFiles([...files, ...validFiles]);
        e.target.value = '';
    };

    const removeFile = (index) => setFiles(files.filter((_, i) => i !== index));

    const handleCreatePost = async (e) => {
        e.preventDefault();
        if (!newPost.trim() && files.length === 0) return;
        if (newPost.length > MAX_CHARS) return;

        const formData = new FormData();
        formData.append('content', newPost);
        files.forEach(file => formData.append('images', file));
        try {
            const res = await fetch(`${API_URL}/posts`, {
                method: 'POST',
                headers: { 'Authorization': localStorage.getItem('token') },
                body: formData
            });
            if (res.ok) {
                setNewPost('');
                setFiles([]);
                fetchPosts();
            }
        } catch (err) {
            console.error("Ошибка создания поста:", err);
        }
    };

    const handleDeletePost = async (id) => {
        if (!confirm("Удалить этот пост?")) return;
        try {
            const res = await fetch(`${API_URL}/posts/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': localStorage.getItem('token') }
            });
            if (res.ok) fetchPosts();
        } catch (err) { console.error(err); }
    };

    const handleUpdatePost = async (id) => {
        if (editContent.length > MAX_CHARS) return;
        try {
            const res = await fetch(`${API_URL}/posts/${id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({ content: editContent })
            });
            if (res.ok) {
                setEditingId(null);
                fetchPosts();
            }
        } catch (err) { console.error(err); }
    };

    useEffect(() => {
        if (!user || posts.length === 0) return;

        const observer = new IntersectionObserver((entries) => {
            const newViews = [];

            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const postId = entry.target.getAttribute('data-post-id');
                    if (postId && !viewedPosts.current.has(postId)) {
                        viewedPosts.current.add(postId);
                        newViews.push(Number(postId));
                    }
                }
            });

            if (newViews.length > 0) {
                fetch(`${API_URL}/posts/views`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': localStorage.getItem('token') || ''
                    },
                    body: JSON.stringify({ postIds: newViews })
                }).catch(console.error);
            }
        }, { threshold: 0.5 });

        const elements = document.querySelectorAll('.post-card');
        elements.forEach(el => observer.observe(el));

        return () => observer.disconnect();
    }, [posts, user, API_URL]);

    return (
        <PullToRefresh onRefresh={fetchPosts}>
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6">
                <div className="flex items-center gap-4 mb-8">
                    <div className="p-3 bg-red-600/20 border border-red-500/50 rounded-xl shadow-[0_0_15px_rgba(220,38,38,0.3)]">
                        <Home className="text-red-500" size={24} />
                    </div>
                    <div>
                        <h1 className="text-3xl font-black text-white tracking-tighter uppercase">Лента</h1>
                        <div className="h-1 w-12 bg-red-600 rounded-full mt-1 shadow-[0_0_10px_red]" />
                    </div>
                </div>

                <div className="bg-zinc-950/80 backdrop-blur-md border border-white/10 rounded-xl p-4 shadow-xl">
                    <textarea
                        value={newPost}
                        onChange={(e) => setNewPost(e.target.value)}
                        placeholder="Что нового?"
                        maxLength={MAX_CHARS}
                        className="w-full bg-transparent border-none outline-none text-white resize-none h-24 text-sm"
                    />

                    <div className="flex justify-end mb-2">
                        <span className={cn(
                            "text-[10px] font-mono tracking-widest",
                            newPost.length >= MAX_CHARS ? "text-red-500" : "text-zinc-600"
                        )}>
                            {newPost.length} / {MAX_CHARS}
                        </span>
                    </div>

                    {files.length > 0 && (
                        <div className="flex flex-wrap gap-2 mb-3">
                            {files.map((f, i) => (
                                <div key={i} className="relative group">
                                    <img src={URL.createObjectURL(f)} className="w-20 h-20 object-cover rounded-lg border border-white/10" alt="" />
                                    <button onClick={() => removeFile(i)} className="absolute -top-2 -right-2 bg-red-600 rounded-full p-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <X size={12} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}

                    <div className="flex justify-between items-center mt-2 pt-2 border-t border-white/5">
                        <div className="flex items-center gap-4">
                            <label className="cursor-pointer text-zinc-500 hover:text-red-500 transition-colors flex items-center gap-1.5">
                                <input type="file" multiple accept="image/*" className="hidden" onChange={handleFileChange} />
                                <ImagePlus size={18} />
                                <span className="text-[10px] font-bold uppercase tracking-tighter">Attach</span>
                            </label>
                            <span className="text-[10px] text-zinc-600 font-bold uppercase tracking-tighter">
                                {files.length}/6 Images
                            </span>
                        </div>
                        <button
                            onClick={handleCreatePost}
                            disabled={newPost.length > MAX_CHARS || (!newPost.trim() && files.length === 0)}
                            className="bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-1.5 rounded-md text-sm font-bold transition-colors"
                        >
                            POST
                        </button>
                    </div>
                </div>

                <div className="flex bg-zinc-900/50 border border-white/10 rounded-xl p-1 backdrop-blur-md mb-6 relative">
                    <motion.div
                        className="absolute top-1 bottom-1 w-[calc(50%-4px)] bg-red-600 rounded-lg shadow-[0_0_15px_rgba(220,38,38,0.3)] z-0"
                        animate={{ left: activeTab === 'recommended' ? '4px' : 'calc(50% + 0px)' }}
                        transition={{ type: "spring", stiffness: 300, damping: 30 }}
                    />

                    <button
                        onClick={() => setActiveTab('recommended')}
                        className={cn(
                            "flex-1 py-2.5 text-xs font-black uppercase tracking-widest z-10 transition-colors rounded-lg",
                            activeTab === 'recommended' ? "text-white" : "text-zinc-500 hover:text-white"
                        )}
                    >
                        Рекомендации
                    </button>
                    <button
                        onClick={() => setActiveTab('new')}
                        className={cn(
                            "flex-1 py-2.5 text-xs font-black uppercase tracking-widest z-10 transition-colors rounded-lg",
                            activeTab === 'new' ? "text-white" : "text-zinc-500 hover:text-white"
                        )}
                    >
                        Новое
                    </button>
                </div>

                <div className="space-y-4">
                    {posts.map((post) => (
                        <motion.div
                            layout
                            key={post.id}
                            data-post-id={post.id}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="post-card bg-zinc-900/40 backdrop-blur-sm border border-white/5 rounded-xl p-5 hover:border-white/10 transition-all group"
                        >
                            <div className="flex justify-between items-start mb-4">
                                <div className="flex items-center gap-3 cursor-pointer" onClick={() => navigate(`/user/${post.username}`)}>
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-zinc-800 to-zinc-900 flex items-center justify-center border border-white/10 overflow-hidden">
                                        {post.avatar_url ? (
                                            <img src={post.avatar_url} alt="" className="w-full h-full object-cover" />
                                        ) : (
                                            <UserIcon size={20} className="text-zinc-500" />
                                        )}
                                    </div>
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <h3 className="text-sm font-bold text-white leading-none">{post.display_name}</h3>
                                            <UserBadge type={post.account_type} />
                                        </div>
                                        <p className="text-[10px] text-zinc-500 mt-1 font-medium">@{post.username} • {formatRelativeTime(post.created_at)}</p>
                                    </div>
                                </div>

                                {user && user.id === post.user_id && (
                                    <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <button onClick={() => { setEditingId(post.id); setEditContent(post.content); }} className="p-1.5 text-zinc-500 hover:text-white transition-colors">
                                            <Edit3 size={16} />
                                        </button>
                                        <button onClick={() => handleDeletePost(post.id)} className="p-1.5 text-zinc-500 hover:text-red-500 transition-colors">
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                )}
                            </div>

                            {editingId === post.id ? (
                                <div className="space-y-3">
                                    <textarea
                                        value={editContent}
                                        onChange={(e) => setEditContent(e.target.value)}
                                        maxLength={MAX_CHARS}
                                        className="w-full bg-black/50 border border-red-500/30 rounded-lg p-3 text-sm text-white outline-none focus:border-red-500"
                                    />
                                    <div className="flex justify-end gap-2">
                                        <button onClick={() => setEditingId(null)} className="p-2 text-zinc-500 hover:text-white"><X size={18} /></button>
                                        <button onClick={() => handleUpdatePost(post.id)} className="p-2 text-green-500 hover:text-green-400"><Check size={18} /></button>
                                    </div>
                                </div>
                            ) : (
                                <PostContent content={post.content} />
                            )}

                            <PostImages imagesJson={post.images} />

                            <div className="flex items-center gap-6 mt-6 pt-4 border-t border-white/5">
                                <button
                                    onClick={() => handleLike(post.id)}
                                    className={cn(
                                        "flex items-center gap-2 text-xs font-bold transition-colors",
                                        post.is_liked ? "text-red-500" : "text-zinc-500 hover:text-red-500"
                                    )}
                                >
                                    <Heart size={18} fill={post.is_liked ? "currentColor" : "none"} />
                                    {post.likes_count || 0}
                                </button>
                                <button
                                    onClick={() => toggleComments(post.id)}
                                    className="flex items-center gap-2 text-xs font-bold text-zinc-500 hover:text-white transition-colors"
                                >
                                    <MessageSquare size={18} />
                                    {post.comments_count || 0}
                                </button>
                            </div>

                            <AnimatePresence>
                                {expandedComments[post.id] && (
                                    <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        className="overflow-hidden"
                                    >
                                        <CommentSection postId={post.id} API_URL={API_URL} currentUser={user} />
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </motion.div>
                    ))}
                </div>
                {isLoadingMore && (
                    <div className="flex justify-center py-6">
                        <Loader2 className="text-red-500 animate-spin" size={32} />
                    </div>
                )}

                {posts.length === 0 && activeTab === 'recommended' && !isLoadingMore && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="bg-zinc-900/50 border border-white/5 rounded-2xl p-10 text-center mt-8 backdrop-blur-sm"
                    >
                        <div className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
                            <Sparkles className="text-red-500" size={36} />
                        </div>
                        <h3 className="text-2xl font-black text-white mb-3 tracking-tight">Ого, вы прочитали всё!</h3>
                        <p className="text-zinc-400 max-w-md mx-auto leading-relaxed text-sm">
                            Вы просмотрели все актуальные рекомендованные посты. Загляните во вкладку <button onClick={() => setActiveTab('new')} className="text-red-500 font-bold hover:underline transition-all">Новое</button>, чтобы увидеть самые свежие публикации от наших авторов, или возвращайтесь позже!
                        </p>
                    </motion.div>
                )}

                {posts.length === 0 && activeTab === 'new' && !isLoadingMore && (
                    <div className="text-center py-10 text-zinc-500">Пока нет новых публикаций...</div>
                )}
            </motion.div>
        </PullToRefresh>
    );
};