export function isValidEmail(email) {
    if (!email || !email.includes('@')) return false;
    const domain = email.split('@')[1].toLowerCase();
    const allowedDomains = [
        'xfeatures.net', 'gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com',
        'me.com', 'yahoo.com', 'yandex.ru', 'yandex.com', 'ya.ru', 'mail.ru',
        'bk.ru', 'inbox.ru', 'list.ru', 'internet.ru', 'inbox.lv', 'proton.me',
        'protonmail.com', 'mail.com', 'email.com', 'null.net', 'europe.com',
        'asia.com', 'usa.com', 'berlin.com', 'post.com', 'techie.com', 'engineer.com'
    ];
    return allowedDomains.includes(domain);
}

export function isValidUsername(username) {
    const regex = /^[a-z0-9]{3,16}$/;
    return regex.test(username);
}