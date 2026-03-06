import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from "../utils/cn";
import { useNavigate } from 'react-router-dom';

export const PostContent = ({ content }) => {
    const navigate = useNavigate();

    const processContent = (text) => {
        if (!text) return text;

        let processed = text.replace(/(^|\s)@([a-zA-Z0-9_]+)/g, '$1[@$2](/user/$2)');

        processed = processed.replace(/(^|\s)#([a-zA-Z0-9_А-Яа-яЁё]+)/g, '$1[#$2](/search?q=%23$2)');

        return processed;
    };

    return (
        <div className="text-zinc-300 leading-relaxed w-full overflow-hidden break-words">
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    h1: ({ node, ...props }) => <h1 className="text-3xl font-black text-white mt-8 first:mt-0 mb-4 border-b border-white/10 pb-2" {...props} />,
                    h2: ({ node, ...props }) => <h2 className="text-2xl font-extrabold text-white mt-6 first:mt-0 mb-3 border-b border-white/5 pb-1" {...props} />,
                    h3: ({ node, ...props }) => <h3 className="text-xl font-bold text-zinc-100 mt-5 first:mt-0 mb-2" {...props} />,
                    h4: ({ node, ...props }) => <h4 className="text-lg font-bold text-zinc-200 mt-4 first:mt-0 mb-2" {...props} />,
                    p: ({ node, ...props }) => <p className="mb-4 last:mb-0" {...props} />,

                    a: ({ node, href, children, ...props }) => {
                        const isInternal = href && href.startsWith('/');
                        return (
                            <a
                                href={href}
                                className="text-red-500 no-underline hover:underline transition-colors cursor-pointer"
                                onClick={(e) => {
                                    if (isInternal) {
                                        e.preventDefault();
                                        navigate(href);
                                    }
                                }}
                                target={isInternal ? undefined : "_blank"}
                                rel={isInternal ? undefined : "noopener noreferrer"}
                                {...props}
                            >
                                {children}
                            </a>
                        );
                    },

                    ul: ({ node, ...props }) => <ul className="list-disc pl-6 mb-4 space-y-1 marker:text-zinc-500" {...props} />,
                    ol: ({ node, ...props }) => <ol className="list-decimal pl-6 mb-4 space-y-1 marker:text-zinc-500" {...props} />,
                    li: ({ node, ...props }) => <li className="pl-1" {...props} />,
                    blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-red-500 pl-4 py-2 my-4 bg-white/5 rounded-r-lg italic text-zinc-400 quote-nested" {...props} />,

                    code: ({ node, className, children, ...props }) => (
                        <code className={cn("bg-zinc-800 px-1.5 py-0.5 rounded font-mono text-[0.9em] border border-white/5", className)} {...props}>
                            {children}
                        </code>
                    ),
                    pre: ({ node, children, ...props }) => (
                        <div className="relative my-4 rounded-xl overflow-hidden border border-white/10 bg-black/60 shadow-sm">
                            <pre className={cn("overflow-x-auto p-4 m-0 text-sm text-zinc-300", "[&_code]:bg-transparent [&_code]:p-0 [&_code]:text-inherit [&_code]:border-none")} {...props}>
                                {children}
                            </pre>
                        </div>
                    ),
                    table: ({ node, ...props }) => <div className="overflow-x-auto my-6 rounded-lg border border-white/10"><table className="w-full text-left border-collapse text-sm" {...props} /></div>,
                    thead: ({ node, ...props }) => <thead className="bg-white/5 text-zinc-200" {...props} />,
                    tbody: ({ node, ...props }) => <tbody className="divide-y divide-white/10" {...props} />,
                    tr: ({ node, ...props }) => <tr className="hover:bg-white/5 transition-colors border-b border-white/10 last:border-0" {...props} />,
                    th: ({ node, ...props }) => <th className="p-3 font-semibold border-r border-white/10 last:border-0" {...props} />,
                    td: ({ node, ...props }) => <td className="p-3 border-r border-white/10 last:border-0 align-top" {...props} />,
                    hr: ({ node, ...props }) => <hr className="my-8 border-white/10" {...props} />,
                }}
            >
                {processContent(content)}
            </ReactMarkdown>
        </div>
    );
};