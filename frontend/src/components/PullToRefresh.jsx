import React, { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';

export const PullToRefresh = ({ onRefresh, children }) => {
    const [startY, setStartY] = useState(0);
    const [pullY, setPullY] = useState(0);
    const [isRefreshing, setIsRefreshing] = useState(false);

    useEffect(() => {
        const handleTouchStart = (e) => {
            if (window.scrollY === 0) {
                setStartY(e.touches[0].clientY);
            }
        };

        const handleTouchMove = (e) => {
            if (startY === 0) return;
            const currentY = e.touches[0].clientY;
            const dy = currentY - startY;

            if (window.scrollY === 0 && dy > 0) {
                setPullY(Math.min(dy * 0.4, 120));
            } else {
                setPullY(0);
            }
        };

        const handleTouchEnd = async () => {
            if (pullY > 80 && !isRefreshing) {
                setIsRefreshing(true);
                setPullY(80);

                try {
                    await onRefresh();
                } finally {
                    setTimeout(() => {
                        setIsRefreshing(false);
                        setPullY(0);
                        setStartY(0);
                    }, 500);
                }
            } else {
                setPullY(0);
                setStartY(0);
            }
        };

        window.addEventListener('touchstart', handleTouchStart);
        window.addEventListener('touchmove', handleTouchMove);
        window.addEventListener('touchend', handleTouchEnd);

        return () => {
            window.removeEventListener('touchstart', handleTouchStart);
            window.removeEventListener('touchmove', handleTouchMove);
            window.removeEventListener('touchend', handleTouchEnd);
        };
    }, [startY, pullY, isRefreshing, onRefresh]);

    return (
        <>
            <div
                className="fixed top-0 left-0 right-0 z-[100] flex justify-center pointer-events-none"
                style={{
                    transform: `translateY(${pullY - 60}px)`,
                    transition: (isRefreshing || pullY === 0) ? 'transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.4s' : 'none',
                    opacity: (pullY > 0 || isRefreshing) ? 1 : 0
                }}
            >
                <div className="mt-4 bg-black/80 backdrop-blur-xl border border-white/10 p-3 rounded-full shadow-2xl shadow-red-500/20">
                    <RefreshCw
                        className={`text-red-500 w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`}
                        style={{ transform: `rotate(${pullY * 3}deg)` }}
                    />
                </div>
            </div>

            {children}
        </>
    );
};