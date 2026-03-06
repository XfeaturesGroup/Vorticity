import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { getPrivateKey, encryptPrivateKeyForCloud } from '../utils/crypto';
import { cn } from "../utils/cn";
import {
    User, Shield, Eye, Smartphone, Share2, Bell, ChevronRight, Save, Globe, MapPin, Github, Link as LinkIcon, Settings as SettingsIcon, Camera, Loader2, QrCode, Lock, CheckCircle, Copy
} from 'lucide-react';

const SettingSection = ({ title, children }) => (
    <section className="space-y-4 mb-8">
        <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-500 border-b border-white/5 pb-2">{title}</h3>
        <div className="space-y-4">{children}</div>
    </section>
);

const Toggle = ({ enabled, onChange, label }) => (
    <div className="flex items-center justify-between py-2">
        <span className="text-sm text-zinc-300">{label}</span>
        <button
            onClick={() => onChange(!enabled)}
            className={cn(
                "w-10 h-5 rounded-full transition-colors relative",
                enabled ? "bg-red-600" : "bg-zinc-700"
            )}
        >
            <div className={cn(
                "absolute top-1 w-3 h-3 bg-white rounded-full transition-all",
                enabled ? "left-6" : "left-1"
            )} />
        </button>
    </div>
);

export const Settings = ({ user, API_URL, onUpdateUser }) => {
    const [activeTab, setActiveTab] = useState('profile');
    const [loading, setLoading] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [is2FAModalOpen, setIs2FAModalOpen] = useState(false);
    const [is2FAEnabled, setIs2FAEnabled] = useState(false);
    const [twoFactorStep, setTwoFactorStep] = useState('init');
    const [qrCodeUrl, setQrCodeUrl] = useState('');
    const [twoFactorSecret, setTwoFactorSecret] = useState('');
    const [twoFactorCode, setTwoFactorCode] = useState('');
    const [twoFactorLoading, setTwoFactorLoading] = useState(false);
    const [disable2FAPassword, setDisable2FAPassword] = useState('');
    const [profileData, setProfileData] = useState({
        display_name: user.display_name || '',
        bio: user.bio || '',
        country: user.country || '',
        city: user.city || '',
        avatar_url: user.avatar_url || '',
        banner_url: user.banner_url || '',
        links: user.links ? (typeof user.links === 'string' ? JSON.parse(user.links) : user.links) : { github: '', steam: '', website: '' }
    });

    const [passwordData, setPasswordData] = useState({
        oldPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [passwordLoading, setPasswordLoading] = useState(false);
    const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);

    useEffect(() => {
        setProfileData({
            display_name: user.display_name || '',
            bio: user.bio || '',
            country: user.country || '',
            city: user.city || '',
            avatar_url: user.avatar_url || '',
            banner_url: user.banner_url || '',
            links: user.links ? (typeof user.links === 'string' ? JSON.parse(user.links) : user.links) : { github: '', steam: '', website: '' }
        });
        setIs2FAEnabled(!!user.is_2fa_enabled);
    }, [user]);

    const handleAvatarUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('avatar', file);

        try {
            const res = await fetch(`${API_URL}/users/avatar`, {
                method: 'POST',
                headers: {
                    'Authorization': localStorage.getItem('token')
                },
                body: formData
            });

            if (res.ok) {
                const data = await res.json();
                const updatedProfile = { ...profileData, avatar_url: data.avatar_url };
                setProfileData(updatedProfile);

                await fetch(`${API_URL}/users/profile`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': localStorage.getItem('token')
                    },
                    body: JSON.stringify(updatedProfile)
                });

                if (onUpdateUser) onUpdateUser({ avatar_url: data.avatar_url });
            } else {
                const data = await res.json();
                alert(data.error || 'Ошибка при загрузке');
            }
        } catch (err) {
            console.error(err);
            alert('Ошибка при загрузке аватарки');
        } finally {
            setUploading(false);
        }
    };

    const handleBannerUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('banner', file);

        try {
            const res = await fetch(`${API_URL}/users/banner`, {
                method: 'POST',
                headers: {
                    'Authorization': localStorage.getItem('token')
                },
                body: formData
            });

            if (res.ok) {
                const data = await res.json();
                const updatedProfile = { ...profileData, banner_url: data.banner_url };
                setProfileData(updatedProfile);

                await fetch(`${API_URL}/users/profile`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': localStorage.getItem('token')
                    },
                    body: JSON.stringify(updatedProfile)
                });

                if (onUpdateUser) onUpdateUser({ banner_url: data.banner_url });
            } else {
                const data = await res.json();
                alert(data.error || 'Ошибка при загрузке');
            }
        } catch (err) {
            console.error(err);
            alert('Ошибка при загрузке баннера');
        } finally {
            setUploading(false);
        }
    };

    const handleSave = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/users/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify(profileData)
            });
            if (res.ok) {
                if (onUpdateUser) onUpdateUser(profileData);
                alert('Профиль успешно обновлен!');
            } else {
                const data = await res.json();
                alert(data.error || 'Ошибка при сохранении');
            }
        } catch (err) {
            console.error(err);
            alert('Ошибка соединения с сервером');
        } finally {
            setLoading(false);
        }
    };

    const handleChangePassword = async (e) => {
        e.preventDefault();
        if (passwordData.newPassword !== passwordData.confirmPassword) {
            alert("Новые пароли не совпадают");
            return;
        }

        setPasswordLoading(true);
        try {
            let encryptedPrivateKey = null;
            const privateKey = await getPrivateKey(user.id);
            if (privateKey) {
                encryptedPrivateKey = await encryptPrivateKeyForCloud(
                    privateKey,
                    passwordData.newPassword,
                    user.id.toString()
                );
            }

            const res = await fetch(`${API_URL}/change-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({
                    oldPassword: passwordData.oldPassword,
                    newPassword: passwordData.newPassword,
                    encryptedPrivateKey
                })
            });

            const data = await res.json();
            if (res.ok) {
                alert("Пароль успешно изменен");
                setPasswordData({ oldPassword: '', newPassword: '', confirmPassword: '' });
                setIsPasswordModalOpen(false);
            } else {
                alert(data.error || "Ошибка при смене пароля");
            }
        } catch (err) {
            console.error(err);
            alert("Ошибка сети");
        } finally {
            setPasswordLoading(false);
        }
    };

    const start2FASetup = async () => {
        setTwoFactorLoading(true);
        try {
            const res = await fetch(`${API_URL}/auth/2fa/generate`, {
                method: 'POST',
                headers: { 'Authorization': localStorage.getItem('token') }
            });
            if (res.ok) {
                const data = await res.json();
                setQrCodeUrl(data.qrCodeUrl);
                setTwoFactorSecret(data.secret);
                setTwoFactorStep('scan');
            } else { alert("Ошибка генерации ключа"); }
        } catch (e) { console.error(e); } finally { setTwoFactorLoading(false); }
    };

    const confirm2FA = async (e) => {
        e.preventDefault();
        setTwoFactorLoading(true);
        try {
            const res = await fetch(`${API_URL}/auth/2fa/enable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token') },
                body: JSON.stringify({ code: twoFactorCode })
            });
            const data = await res.json();
            if (res.ok) {
                setIs2FAEnabled(true);
                setTwoFactorStep('success');
                if (onUpdateUser) onUpdateUser({ is_2fa_enabled: 1 });
            } else { alert(data.error || "Неверный код"); }
        } catch (e) { alert("Ошибка сети"); } finally { setTwoFactorLoading(false); }
    };

    const disable2FA = async (e) => {
        e.preventDefault();
        setTwoFactorLoading(true);
        try {
            const res = await fetch(`${API_URL}/auth/2fa/disable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token') },
                body: JSON.stringify({ password: disable2FAPassword })
            });
            if (res.ok) {
                setIs2FAEnabled(false);
                setIs2FAModalOpen(false);
                setDisable2FAPassword('');
                setTwoFactorStep('init');
                if (onUpdateUser) onUpdateUser({ is_2fa_enabled: 0 });
                alert("2FA отключена");
            } else {
                const data = await res.json();
                alert(data.error || "Неверный пароль");
            }
        } catch (e) { alert("Ошибка сети"); } finally { setTwoFactorLoading(false); }
    };

    const tabs = [
        { id: 'profile', label: 'Профиль', icon: User },
        { id: 'security', label: 'Безопасность', icon: Shield },
        { id: 'content', label: 'Контент', icon: Eye },
        { id: 'devices', label: 'Устройства', icon: Smartphone },
        { id: 'integrations', label: 'Интеграции', icon: Share2 },
        { id: 'notifications', label: 'Уведомления', icon: Bell },
    ];

    return (
        <div className="max-w-4xl mx-auto pb-32">
            <div className="flex items-center gap-4 mb-8">
                <div className="p-3 bg-red-600/20 border border-red-500/50 rounded-xl shadow-[0_0_15px_rgba(220,38,38,0.3)]">
                    <SettingsIcon className="text-red-500" size={24} />
                </div>
                <div>
                    <h1 className="text-3xl font-black text-white tracking-tighter uppercase">Настройки</h1>
                    <div className="h-1 w-12 bg-red-600 rounded-full mt-1 shadow-[0_0_10px_red]" />
                </div>
            </div>

            <div className="flex flex-col md:flex-row gap-8">
                <div className="w-full md:w-64 space-y-1">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={cn(
                                "w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all text-sm font-medium",
                                activeTab === tab.id
                                    ? "bg-red-600/10 text-red-500 border border-red-500/20"
                                    : "text-zinc-400 hover:bg-white/5 hover:text-white"
                            )}
                        >
                            <tab.icon size={18} />
                            {tab.label}
                        </button>
                    ))}
                </div>

                <div className="flex-1 bg-zinc-900/40 backdrop-blur-sm border border-white/5 rounded-2xl p-6 min-h-[500px]">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={activeTab}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            transition={{ duration: 0.2 }}
                        >
                            {activeTab === 'profile' && (
                                <div className="flex-1">
                                    <SettingSection title="Основная информация">
                                        <div className="flex flex-col md:flex-row gap-8 items-center mb-8 pb-8 border-b border-white/5">
                                            <div className="relative group">
                                                <div className="w-24 h-24 bg-zinc-950 border-2 border-white/10 rounded-3xl flex items-center justify-center text-3xl font-bold text-red-500 overflow-hidden shadow-2xl">
                                                    {profileData.avatar_url ? (
                                                        <img src={profileData.avatar_url} alt="Avatar" className="w-full h-full object-cover" />
                                                    ) : (
                                                        profileData.display_name?.[0] || '?'
                                                    )}
                                                    {uploading && (
                                                        <div className="absolute inset-0 bg-black/60 flex items-center justify-center">
                                                            <Loader2 className="text-white animate-spin" size={24} />
                                                        </div>
                                                    )}
                                                </div>
                                                <label className="absolute -bottom-2 -right-2 p-2 bg-red-600 hover:bg-red-500 text-white rounded-xl cursor-pointer shadow-lg transition-all active:scale-90">
                                                    <Camera size={16} />
                                                    <input type="file" className="hidden" accept="image/*" onChange={handleAvatarUpload} disabled={uploading} />
                                                </label>
                                            </div>
                                            <div className="flex-1 space-y-4 w-full">
                                                <div>
                                                    <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Отображаемое имя</label>
                                                    <input
                                                        type="text"
                                                        value={profileData.display_name}
                                                        onChange={(e) => setProfileData({ ...profileData, display_name: e.target.value })}
                                                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-all"
                                                        placeholder="Как вас называть?"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">О себе</label>
                                                    <textarea
                                                        value={profileData.bio}
                                                        onChange={(e) => setProfileData({ ...profileData, bio: e.target.value })}
                                                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-all min-h-[100px] resize-none"
                                                        placeholder="Расскажите что-нибудь интересное..."
                                                    />
                                                </div>
                                            </div>
                                        </div>

                                        <div className="mb-8 pb-8 border-b border-white/5">
                                            <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3 ml-1">Баннер профиля</label>
                                            <div className="relative h-32 w-full bg-zinc-950 border border-white/10 rounded-2xl overflow-hidden group">
                                                {profileData.banner_url ? (
                                                    <img src={profileData.banner_url} alt="Banner" className="w-full h-full object-cover" />
                                                ) : (
                                                    <div className="w-full h-full bg-gradient-to-r from-zinc-900 to-zinc-800" />
                                                )}

                                                {uploading && (
                                                    <div className="absolute inset-0 bg-black/60 flex items-center justify-center z-10">
                                                        <Loader2 className="text-white animate-spin" size={24} />
                                                    </div>
                                                )}

                                                <label className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center cursor-pointer">
                                                    <div className="flex items-center gap-2 bg-white/10 backdrop-blur-md border border-white/20 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-widest">
                                                        <Camera size={16} /> Изменить баннер
                                                    </div>
                                                    <input type="file" className="hidden" accept="image/*" onChange={handleBannerUpload} disabled={uploading} />
                                                </label>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <div>
                                                <label className="text-[10px] uppercase text-zinc-500 font-bold mb-1 block">Страна</label>
                                                <input
                                                    type="text"
                                                    placeholder="Россия"
                                                    value={profileData.country}
                                                    onChange={(e) => setProfileData({...profileData, country: e.target.value})}
                                                    className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2 text-sm focus:border-red-500 outline-none"
                                                />
                                            </div>
                                            <div>
                                                <label className="text-[10px] uppercase text-zinc-500 font-bold mb-1 block">Город</label>
                                                <input
                                                    type="text"
                                                    placeholder="Москва"
                                                    value={profileData.city}
                                                    onChange={(e) => setProfileData({...profileData, city: e.target.value})}
                                                    className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2 text-sm focus:border-red-500 outline-none"
                                                />
                                            </div>
                                        </div>

                                        <div className="space-y-3">
                                            <label className="text-[10px] uppercase text-zinc-500 font-bold block">Социальные ссылки</label>
                                            <div className="flex items-center gap-3 bg-black/30 p-2 rounded-lg border border-white/5">
                                                <Github size={18} className="text-zinc-500" />
                                                <input
                                                    type="text"
                                                    placeholder="GitHub username"
                                                    maxLength={32}
                                                    value={profileData.links.github}
                                                    onChange={(e) => setProfileData({...profileData, links: {...profileData.links, github: e.target.value}})}
                                                    className="bg-transparent border-none outline-none text-sm flex-1"
                                                />
                                            </div>
                                            <div className="flex items-center gap-3 bg-black/30 p-2 rounded-lg border border-white/5">
                                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" className="w-4 h-4 text-zinc-500" viewBox="0 0 16 16">
                                                    <path d="M.329 10.333A8.01 8.01 0 0 0 7.99 16C12.414 16 16 12.418 16 8s-3.586-8-8.009-8A8.006 8.006 0 0 0 0 7.468l.003.006 4.304 1.769A2.2 2.2 0 0 1 5.62 8.88l1.96-2.844-.001-.04a3.046 3.046 0 0 1 3.042-3.043 3.046 3.046 0 0 1 3.042 3.043 3.047 3.047 0 0 1-3.111 3.044l-2.804 2a2.223 2.223 0 0 1-3.075 2.11 2.22 2.22 0 0 1-1.312-1.568L.33 10.333Z"/>
                                                    <path d="M4.868 12.683a1.715 1.715 0 0 0 1.318-3.165 1.7 1.7 0 0 0-1.263-.02l1.023.424a1.261 1.261 0 1 1-.97 2.33l-.99-.41a1.7 1.7 0 0 0 .882.84Zm3.726-6.687a2.03 2.03 0 0 0 2.027 2.029 2.03 2.03 0 0 0 2.027-2.029 2.03 2.03 0 0 0-2.027-2.027 2.03 2.03 0 0 0-2.027 2.027m2.03-1.527a1.524 1.524 0 1 1-.002 3.048 1.524 1.524 0 0 1 .002-3.048"/>
                                                </svg>
                                                <input
                                                    type="text"
                                                    placeholder="Steam Username"
                                                    maxLength={32}
                                                    value={profileData.links.steam}
                                                    onChange={(e) => setProfileData({...profileData, links: {...profileData.links, steam: e.target.value}})}
                                                    className="bg-transparent border-none outline-none text-sm flex-1"
                                                />
                                            </div>
                                            <div className="flex items-center gap-3 bg-black/30 p-2 rounded-lg border border-white/5">
                                                <LinkIcon size={18} className="text-zinc-500" />
                                                <input
                                                    type="text"
                                                    placeholder="Личный сайт"
                                                    maxLength={64}
                                                    value={profileData.links.website}
                                                    onChange={(e) => setProfileData({...profileData, links: {...profileData.links, website: e.target.value}})}
                                                    className="bg-transparent border-none outline-none text-sm flex-1"
                                                />
                                            </div>
                                        </div>

                                        <button
                                            onClick={handleSave}
                                            disabled={loading}
                                            className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white px-6 py-2 rounded-lg text-sm font-bold transition-colors flex items-center gap-2"
                                        >
                                            <Save size={16} /> {loading ? 'Сохранение...' : 'Сохранить изменения'}
                                        </button>
                                    </SettingSection>
                                </div>
                            )}

                            {activeTab === 'security' && (
                                <SettingSection title="Безопасность">
                                    <div className="space-y-4">
                                        <button onClick={() => setIsPasswordModalOpen(true)} className="w-full text-left px-4 py-3 bg-white/5 rounded-xl hover:bg-white/10 transition-colors flex justify-between items-center group">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 bg-red-500/10 rounded-lg text-red-500 group-hover:bg-red-500 group-hover:text-white transition-colors">
                                                    <Shield size={16} />
                                                </div>
                                                <span className="text-sm font-medium">Сменить пароль</span>
                                            </div>
                                            <ChevronRight size={16} className="text-zinc-500" />
                                        </button>

                                        <button
                                            onClick={() => {
                                                setIs2FAModalOpen(true);
                                                if (!is2FAEnabled && twoFactorStep !== 'success') setTwoFactorStep('init');
                                            }}
                                            className={cn(
                                                "w-full text-left px-4 py-3 rounded-xl transition-all flex justify-between items-center group border",
                                                is2FAEnabled
                                                    ? "bg-green-500/10 border-green-500/30 hover:bg-green-500/20"
                                                    : "bg-white/5 border-transparent hover:bg-white/10"
                                            )}
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className={cn("p-2 rounded-lg transition-colors", is2FAEnabled ? "bg-green-500/20 text-green-500" : "bg-red-500/10 text-red-500")}>
                                                    <Smartphone size={16} />
                                                </div>
                                                <div>
                                                    <span className="text-sm font-medium block">Двухфакторная аутентификация</span>
                                                    <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">
                                                    {is2FAEnabled ? "Активно" : "Отключено"}
                                                    </span>
                                                </div>
                                            </div>
                                            <ChevronRight size={16} className="text-zinc-500" />
                                        </button>
                                    </div>
                                </SettingSection>
                            )}

                            {activeTab === 'notifications' && (
                                <SettingSection title="Уведомления">
                                    <Toggle label="Новые лайки" enabled={true} onChange={() => {}} />
                                    <Toggle label="Новые комментарии" enabled={true} onChange={() => {}} />
                                    <Toggle label="Новые подписчики" enabled={false} onChange={() => {}} />
                                    <Toggle label="Системные оповещения" enabled={true} onChange={() => {}} />
                                </SettingSection>
                            )}

                            {activeTab === 'devices' && (
                                <SettingSection title="Активные сессии">
                                    <div className="p-4 bg-white/5 rounded-xl border border-white/5 flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <Smartphone className="text-red-500" />
                                            <div>
                                                <p className="text-sm font-bold">Xiaomi redmi poco x4 5g pro max saudi chicken mc nugets ultra se с 18 камерами</p>
                                                <p className="text-[10px] text-zinc-500">Киев, Россия • Сейчас в сети</p>
                                            </div>
                                        </div>
                                        <button className="text-xs text-red-500 font-bold hover:underline">Завершить</button>
                                    </div>
                                </SettingSection>
                            )}

                            {['content', 'integrations'].includes(activeTab) && (
                                <div className="flex flex-col items-center justify-center h-64 text-zinc-500">
                                    <Share2 size={48} className="mb-4 opacity-20" />
                                    <p className="text-sm">Этот раздел находится в разработке</p>
                                </div>
                            )}
                        </motion.div>
                    </AnimatePresence>
                </div>
            </div>

            <AnimatePresence>
                {isPasswordModalOpen && (
                    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            onClick={() => setIsPasswordModalOpen(false)}
                            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
                        />
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            className="relative w-full max-w-md bg-zinc-900 border border-white/10 rounded-3xl p-6 shadow-2xl overflow-hidden"
                        >
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-red-600 to-transparent" />

                            <div className="flex items-center justify-between mb-6">
                                <h3 className="text-xl font-black uppercase tracking-tighter text-white">Смена пароля</h3>
                                <button
                                    onClick={() => setIsPasswordModalOpen(false)}
                                    className="p-2 hover:bg-white/5 rounded-xl text-zinc-500 hover:text-white transition-colors"
                                >
                                    <ChevronRight size={20} className="rotate-90" />
                                </button>
                            </div>

                            <form onSubmit={handleChangePassword} className="space-y-4">
                                <div>
                                    <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Старый пароль</label>
                                    <input
                                        type="password"
                                        value={passwordData.oldPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, oldPassword: e.target.value })}
                                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-all"
                                        placeholder="••••••••"
                                        required
                                    />
                                </div>
                                <div className="h-px bg-white/5 my-2" />
                                <div>
                                    <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Новый пароль</label>
                                    <input
                                        type="password"
                                        value={passwordData.newPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-all"
                                        placeholder="Минимум 8 символов"
                                        required
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Подтверждение</label>
                                    <input
                                        type="password"
                                        value={passwordData.confirmPassword}
                                        onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-all"
                                        placeholder="Повторите новый пароль"
                                        required
                                    />
                                </div>

                                <div className="pt-4 flex gap-3">
                                    <button
                                        type="button"
                                        onClick={() => setIsPasswordModalOpen(false)}
                                        className="flex-1 px-6 py-3 rounded-xl text-sm font-bold text-zinc-400 hover:bg-white/5 transition-all"
                                    >
                                        Отмена
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={passwordLoading}
                                        className="flex-[2] bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white px-6 py-3 rounded-xl text-sm font-bold transition-all shadow-lg shadow-red-900/20 flex items-center justify-center gap-2"
                                    >
                                        {passwordLoading ? (
                                            <Loader2 className="animate-spin" size={18} />
                                        ) : (
                                            <>
                                                <Save size={18} /> Сохранить
                                            </>
                                        )}
                                    </button>
                                </div>
                            </form>
                        </motion.div>
                    </div>
                )}
            </AnimatePresence>
            <AnimatePresence>
                {is2FAModalOpen && (
                    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            onClick={() => setIs2FAModalOpen(false)}
                            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
                        />
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            className="relative w-full max-w-md bg-zinc-900 border border-white/10 rounded-3xl p-6 shadow-2xl overflow-hidden"
                        >
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-red-600 to-transparent" />

                            <div className="flex items-center justify-between mb-6">
                                <h3 className="text-xl font-black uppercase tracking-tighter text-white flex items-center gap-2">
                                    <QrCode className="text-red-500" /> 2FA Защита
                                </h3>
                                <button
                                    onClick={() => setIs2FAModalOpen(false)}
                                    className="p-2 hover:bg-white/5 rounded-xl text-zinc-500 hover:text-white transition-colors"
                                >
                                    <ChevronRight size={20} className="rotate-90" />
                                </button>
                            </div>

                            {is2FAEnabled && twoFactorStep !== 'success' ? (
                                <div className="space-y-4">
                                    <div className="bg-green-500/10 border border-green-500/20 p-4 rounded-xl flex items-center gap-4">
                                        <div className="bg-green-500/20 p-2 rounded-full text-green-500"><Shield size={24} /></div>
                                        <div>
                                            <h4 className="font-bold text-green-500">Ваш аккаунт защищен</h4>
                                            <p className="text-xs text-zinc-400">Двухфакторная аутентификация активна.</p>
                                        </div>
                                    </div>

                                    <div className="pt-4 border-t border-white/5">
                                        <h4 className="text-sm font-bold text-zinc-300 mb-2">Отключить защиту</h4>
                                        <form onSubmit={disable2FA} className="space-y-3">
                                            <input
                                                type="password"
                                                value={disable2FAPassword}
                                                onChange={(e) => setDisable2FAPassword(e.target.value)}
                                                placeholder="Введите пароль для подтверждения"
                                                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50"
                                                required
                                            />
                                            <button type="submit" disabled={twoFactorLoading} className="w-full bg-zinc-800 hover:bg-zinc-700 text-zinc-300 py-3 rounded-xl text-sm font-bold transition-colors">
                                                {twoFactorLoading ? 'Обработка...' : 'Отключить 2FA'}
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            ) : (
                                <div className="space-y-6">
                                    {twoFactorStep === 'init' && (
                                        <div className="text-center space-y-6">
                                            <div className="w-20 h-20 bg-red-600/10 rounded-full flex items-center justify-center mx-auto text-red-500">
                                                <Smartphone size={40} />
                                            </div>
                                            <div>
                                                <p className="text-zinc-300 text-sm mb-4">Защитите свой аккаунт, используя Google Authenticator или аналогичное приложение.</p>
                                                <button onClick={start2FASetup} disabled={twoFactorLoading} className="w-full bg-red-600 hover:bg-red-500 text-white py-3 rounded-xl font-bold shadow-lg shadow-red-900/20 flex items-center justify-center gap-2">
                                                    {twoFactorLoading ? <Loader2 className="animate-spin" size={18} /> : 'Начать настройку'}
                                                </button>
                                            </div>
                                        </div>
                                    )}

                                    {twoFactorStep === 'scan' && (
                                        <div className="space-y-6">
                                            <div className="text-center">
                                                <div className="bg-white p-2 rounded-xl w-48 h-48 mx-auto mb-4">
                                                    {qrCodeUrl && <img src={qrCodeUrl} alt="QR Code" className="w-full h-full" />}
                                                </div>
                                                <p className="text-xs text-zinc-500 mb-2">Отсканируйте QR-код в приложении</p>
                                                <div className="flex items-center justify-center gap-2 bg-black/30 py-2 rounded-lg cursor-pointer hover:bg-black/50 transition-colors" onClick={() => navigator.clipboard.writeText(twoFactorSecret)}>
                                                    <span className="font-mono text-xs text-zinc-400">{twoFactorSecret}</span>
                                                    <Copy size={12} className="text-zinc-500" />
                                                </div>
                                            </div>

                                            <form onSubmit={confirm2FA} className="space-y-3">
                                                <input
                                                    type="text"
                                                    value={twoFactorCode}
                                                    onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                                    placeholder="Введите 6-значный код"
                                                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-center text-xl tracking-[0.5em] font-mono text-white outline-none focus:border-red-500/50"
                                                    autoFocus
                                                />
                                                <button type="submit" disabled={twoFactorCode.length !== 6 || twoFactorLoading} className="w-full bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white py-3 rounded-xl font-bold flex items-center justify-center gap-2">
                                                    {twoFactorLoading ? <Loader2 className="animate-spin" size={18} /> : 'Подтвердить'}
                                                </button>
                                            </form>
                                        </div>
                                    )}

                                    {twoFactorStep === 'success' && (
                                        <div className="text-center space-y-6 py-4">
                                            <div className="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto text-green-500">
                                                <CheckCircle size={40} />
                                            </div>
                                            <div>
                                                <h4 className="text-xl font-bold text-white mb-2">Готово!</h4>
                                                <p className="text-zinc-400 text-sm">Ваш аккаунт теперь защищен двухфакторной аутентификацией.</p>
                                            </div>
                                            <button onClick={() => setIs2FAModalOpen(false)} className="w-full bg-zinc-800 hover:bg-zinc-700 text-white py-3 rounded-xl font-bold">
                                                Отлично
                                            </button>
                                        </div>
                                    )}
                                </div>
                            )}
                        </motion.div>
                    </div>
                )}
            </AnimatePresence>
        </div>
    );
};

