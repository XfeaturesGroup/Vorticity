<div align="center">
  <img src="https://vort.xfeatures.net/vorticity.ico" alt="Vorticity Logo" width="120" />

  <h1>🌪️ Vorticity</h1>

  <p>
    <strong>A secure, cross-platform social networking and real-time chat application built for the modern web.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB" alt="React" />
    <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white" alt="Tailwind" />
    <img src="https://img.shields.io/badge/Cloudflare_Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white" alt="Cloudflare Workers" />
    <img src="https://img.shields.io/badge/Capacitor-119EFF?style=flat-square&logo=capacitor&logoColor=white" alt="Capacitor" />
    <img src="https://img.shields.io/badge/SQLite_D1-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="Cloudflare D1" />
  </p>
</div>

---

> [!CAUTION]
> ## 🛑 ⚠️ STRICTLY PROPRIETARY LICENSE - DO NOT USE ⚠️ 🛑
>
> **THIS REPOSITORY IS FOR SHOWCASE AND PORTFOLIO PURPOSES ONLY.**
>
> The source code, assets, and architecture contained within this repository are the exclusive intellectual property of **XfeaturesGroup**. 
> 
> * **NO** permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.
> * **NO** open-source license (such as MIT, GPL, or Apache) applies to this project.
> * Any unauthorized use, reproduction, or commercial exploitation of this code is strictly prohibited and will be subject to legal action.
> 
> By viewing this repository, you agree to these terms.

---

## 📖 About The Project

**Vorticity** is a full-stack, high-performance social platform designed with security and scalability in mind. It features a complete ecosystem including user authentication, content feeds, social graphs (friends), and a highly secure End-to-End Encrypted (E2EE) real-time chat system. 

The application is engineered to run seamlessly on the web and natively on Android devices.

## ✨ Key Features

* **🛡️ End-to-End Encrypted (E2EE) Chats:** Secure messaging utilizing the WebCrypto API (ECDH curve P-256 for key derivation, AES-GCM for encryption). Private keys are securely encrypted before being synced to the cloud.
* **🔐 Advanced Authentication:** * Password hashing using PBKDF2 (SHA-256) with unique per-user salts.
  * Time-based One-Time Password (TOTP) implementation for robust Two-Factor Authentication (2FA).
* **📱 Cross-Platform Support:** Fully responsive web interface and a native Android application built via Capacitor.
* **🌍 Edge-Optimized Backend:** Serverless architecture deployed directly to Cloudflare edge networks for ultra-low latency.
* **🖼️ Rich Media Handling:** High-performance image uploads and delivery utilizing Cloudflare R2 object storage.
* **⚙️ Admin Dashboard:** Built-in moderation tools for managing users, media, and content.

---

## 🛠️ Technology Stack

| Module | Technologies |
| :--- | :--- |
| **Backend (Edge API)** | ⚡ Cloudflare Workers, `itty-router`, D1 (Serverless SQLite), R2 Storage |
| **Security** | 🔑 Native WebCrypto API (Hashing, Salting, ECDH, AES-GCM), Custom TOTP |
| **Frontend (Web)** | ⚛️ React.js, Vite, Tailwind CSS, IndexedDB |
| **Mobile Runtime** | 📱 Capacitor (Android Native Build) |

---

## 🏗️ Architecture Highlights

* **Stateless Edge API:** The backend operates entirely on Cloudflare Workers, ensuring horizontal scalability without cold starts.
* **Zero-Knowledge Architecture Ready:** The chat module's implementation ensures the server never sees plain-text messages or unencrypted private keys, emphasizing user privacy.
* **Automated CI/CD:** Integrated directly with Cloudflare Pages for seamless, continuous deployment pipelines.

---

<div align="center">
  <sub>Copyright © 2026 XfeaturesGroup. All Rights Reserved.</sub>
</div>
