# authlogic

This library provides authentication logic for [Actix Web](https://actix.rs/) applications in Rust.

The library makes some sensible choices about how authentication works:

- Users can reset their password by completing an email challenge.
- Users should be notified when their passwords are changed.
- Allow users to authenticate by password. Or if you prefer, they can log in by clicking a link in an email.
- Let users register accounts by verifying their email address. Or if you prefer, let an administrative account create accounts for them with temporary initial passwords.

Meanwhile, it stays agnostic on everything else:

- Provide your own API endpoints for login, logout, register, etc.; or use server-side rendering with any templating engine you like.
- You control the database: use any driver or ORM you like. You can even choose the shape of the table and the column names, if you want to.
- You control how email challenges and notifications are composed and sent.
- Define your own user roles and privileges with whatever logic is suitable for your application.


## How to use

To integrate authlogic into your Actix Web application, you will need to provide types for your application state and your users, and implement a few traits.

Examples coming soon.


## Security

- Passwords are stored and verified using the [Argon2id](https://en.wikipedia.org/wiki/Argon2) password hashing algorithm.
- Session tokens are always generated on server-side, to prevent session-fixation attacks.
- Session cookies are [sent only via HTTPS](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies#secure), and [inaccessible to client-side JavaScript](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies#httponly).
- Session tokens and email challenge codes are random tokens with enough entropy to resist brute-force attacks. They are stored as [SHA-2](https://en.wikipedia.org/wiki/SHA-2) hashes and compared in constant time.
- Session tokens are automatically replaced when elevating privileges.
- Secrets (passwords, hashes, tokens, etc.) are censored in logs, and automatically [zeroized](https://en.wikipedia.org/wiki/Zeroisation) after use.

Please note that the security of this crate has not been independently audited. Use at your own risk.
