import React from 'react';
import { ShieldAlert, ShieldCheck, Bot, BadgeCheck, Crown, TestTube2, Award, Bug, Star, UserX } from 'lucide-react';
import { cn } from '../utils/cn';

export const UserBadge = ({ type, className, iconSize = 14 }) => {
    if (!type || type === 'user') return null;

    const badges = {
        creator: { icon: Crown, label: "Создатель", color: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/20", animation: "creator-badge-animation" },
        moderator: { icon: ShieldCheck, label: "Модератор", color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/20" },
        official: { icon: BadgeCheck, label: "Официальный аккаунт", color: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/20" },
        beta_tester: { icon: TestTube2, label: "Бета-Тестер", color: "text-green-500", bg: "bg-green-500/10", border: "border-green-500/20" },
        early_adopter: { icon: Award, label: "Ранний пользователь", color: "text-indigo-500", bg: "bg-indigo-500/10", border: "border-indigo-500/20" },
        contributor: { icon: ShieldAlert, label: "Контрибьютор", color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/20" },
        bug_hunter: { icon: Bug, label: "Охотник за багами", color: "text-red-600", bg: "bg-red-600/10", border: "border-red-600/20" },
        banned: { icon: UserX, label: "Заблокирован", color: "text-red-700", bg: "bg-red-700/10", border: "border-red-700/20" },
        bot_aggregator: { icon: Bot, label: "Приложение (Бот-агрегатор)", color: "text-purple-500", bg: "bg-purple-500/10", border: "border-purple-500/20" },
        bot_xfeatures: { icon: Bot, label: "Приложение (Бот Xfeatures)", color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/20" },
        bot_verified: { icon: Bot, label: "Приложение (Верифицированный Бот)", color: "text-cyan-500", bg: "bg-cyan-500/10", border: "border-cyan-500/20" },
        bot: { icon: Bot, label: "Приложение (Бот)", color: "text-zinc-400", bg: "bg-zinc-400/10", border: "border-zinc-400/20" },
    };

    const badge = badges[type];
    if (!badge) return null;

    const Icon = badge.icon;

    return (
        <div
            className={cn("group relative inline-flex items-center justify-center cursor-help", className)}
            title={badge.label}
        >
            <div className={cn("p-1 rounded-md border flex items-center justify-center transition-all", badge.bg, badge.color, badge.border, badge.animation)}>
                <Icon size={iconSize} />
            </div>
        </div>
    );
};
