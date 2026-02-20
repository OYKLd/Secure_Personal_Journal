class SecureJournal {
    constructor() {
        this.entries = [];
        this.password = null;
        this.isUnlocked = false;
        this.entryToDelete = null;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkFirstTime();
    }

    bindEvents() {
        // Écran de verrouillage
        document.getElementById('unlockBtn').addEventListener('click', () => this.unlock());
        document.getElementById('setupBtn').addEventListener('click', () => this.setupPassword());
        document.getElementById('lockBtn').addEventListener('click', () => this.lock());
        
        // Journal
        document.getElementById('saveBtn').addEventListener('click', () => this.saveEntry());
        document.getElementById('clearBtn').addEventListener('click', () => this.clearForm());
        
        // Modal
        document.getElementById('confirmDelete').addEventListener('click', () => this.confirmDelete());
        document.getElementById('cancelDelete').addEventListener('click', () => this.closeModal());
        
        // Enter key sur les inputs de mot de passe
        document.getElementById('passwordInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.unlock();
        });
        
        document.getElementById('setupPasswordInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') document.getElementById('confirmPasswordInput').focus();
        });
        
        document.getElementById('confirmPasswordInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.setupPassword();
        });
    }

    checkFirstTime() {
        const hasPassword = localStorage.getItem('journal_password');
        if (!hasPassword) {
            this.showSetupScreen();
        } else {
            this.showLoginScreen();
        }
    }

    showSetupScreen() {
        document.getElementById('passwordSection').classList.add('hidden');
        document.getElementById('setupSection').classList.remove('hidden');
        document.getElementById('lockMessage').textContent = 'Bienvenue ! Créez votre mot de passe principal';
    }

    showLoginScreen() {
        document.getElementById('passwordSection').classList.remove('hidden');
        document.getElementById('setupSection').classList.add('hidden');
        document.getElementById('lockMessage').textContent = 'Entrez votre mot de passe pour accéder à votre journal';
    }

    async setupPassword() {
        const password = document.getElementById('setupPasswordInput').value;
        const confirmPassword = document.getElementById('confirmPasswordInput').value;

        if (!password || !confirmPassword) {
            this.showError('Veuillez remplir tous les champs');
            return;
        }

        if (password.length < 6) {
            this.showError('Le mot de passe doit contenir au moins 6 caractères');
            return;
        }

        if (password !== confirmPassword) {
            this.showError('Les mots de passe ne correspondent pas');
            return;
        }

        try {
            // Hasher le mot de passe avec Web Crypto API
            const hashedPassword = await this.hashPassword(password);
            localStorage.setItem('journal_password', hashedPassword);
            
            this.password = password;
            this.isUnlocked = true;
            this.showJournalScreen();
            this.showSuccess('Mot de passe créé avec succès !');
        } catch (error) {
            this.showError('Erreur lors de la création du mot de passe');
        }
    }

    async unlock() {
        const password = document.getElementById('passwordInput').value;

        if (!password) {
            this.showError('Veuillez entrer votre mot de passe');
            return;
        }

        try {
            const storedHash = localStorage.getItem('journal_password');
            const isValid = await this.verifyPassword(password, storedHash);

            if (isValid) {
                this.password = password;
                this.isUnlocked = true;
                this.showJournalScreen();
                this.loadEntries();
            } else {
                this.showError('Mot de passe incorrect');
                document.getElementById('passwordInput').value = '';
            }
        } catch (error) {
            this.showError('Erreur lors de la vérification du mot de passe');
        }
    }

    lock() {
        this.isUnlocked = false;
        this.password = null;
        this.entries = [];
        this.showLockScreen();
        document.getElementById('passwordInput').value = '';
    }

    showJournalScreen() {
        document.getElementById('lockScreen').classList.remove('active');
        document.getElementById('journalScreen').classList.add('active');
    }

    showLockScreen() {
        document.getElementById('journalScreen').classList.remove('active');
        document.getElementById('lockScreen').classList.add('active');
    }

    // Chiffrement simple mais efficace
    async encrypt(text, password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        // Générer une clé à partir du mot de passe
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );

        // Combiner salt + iv + encrypted data
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);

        return btoa(String.fromCharCode(...combined));
    }

    async decrypt(encryptedText, password) {
        try {
            const encoder = new TextEncoder();
            const decoder = new TextDecoder();
            
            const combined = new Uint8Array(
                atob(encryptedText).split('').map(char => char.charCodeAt(0))
            );

            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const encrypted = combined.slice(28);

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );

            return decoder.decode(decrypted);
        } catch (error) {
            throw new Error('Erreur de déchiffrement');
        }
    }

    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async verifyPassword(password, hash) {
        const hashedPassword = await this.hashPassword(password);
        return hashedPassword === hash;
    }

    async saveEntry() {
        if (!this.isUnlocked) {
            this.showError('Journal verrouillé');
            return;
        }

        const title = document.getElementById('entryTitle').value.trim();
        const content = document.getElementById('entryContent').value.trim();

        if (!title || !content) {
            this.showError('Veuillez remplir le titre et le contenu');
            return;
        }

        try {
            const entry = {
                id: Date.now(),
                title: title,
                content: content,
                date: new Date().toISOString()
            };

            // Chiffrer le contenu
            const encryptedEntry = {
                ...entry,
                title: await this.encrypt(title, this.password),
                content: await this.encrypt(content, this.password)
            };

            this.entries.push(encryptedEntry);
            await this.saveToStorage();
            
            this.clearForm();
            this.renderEntries();
            this.showSuccess('Entrée sauvegardée avec succès !');
        } catch (error) {
            this.showError('Erreur lors de la sauvegarde');
        }
    }

    async loadEntries() {
        if (!this.isUnlocked) return;

        try {
            const stored = localStorage.getItem('journal_entries');
            if (stored) {
                this.entries = JSON.parse(stored);
                this.renderEntries();
            }
        } catch (error) {
            this.showError('Erreur lors du chargement des entrées');
            this.entries = [];
        }
    }

    async saveToStorage() {
        try {
            localStorage.setItem('journal_entries', JSON.stringify(this.entries));
        } catch (error) {
            this.showError('Erreur lors de la sauvegarde');
        }
    }

    async renderEntries() {
        const container = document.getElementById('entriesContainer');
        const entryCount = document.getElementById('entryCount');
        
        entryCount.textContent = `${this.entries.length} entrée${this.entries.length > 1 ? 's' : ''}`;

        if (this.entries.length === 0) {
            container.innerHTML = '<p class="empty-state">Aucune entrée pour le moment</p>';
            return;
        }

        try {
            // Déchiffrer les entrées pour l'affichage
            const decryptedEntries = await Promise.all(
                this.entries.map(async (entry) => ({
                    ...entry,
                    title: await this.decrypt(entry.title, this.password),
                    content: await this.decrypt(entry.content, this.password)
                }))
            );

            // Trier par date (plus récent en premier)
            decryptedEntries.sort((a, b) => new Date(b.date) - new Date(a.date));

            container.innerHTML = decryptedEntries.map(entry => `
                <div class="entry-item fade-in" data-id="${entry.id}">
                    <div class="entry-title">${this.escapeHtml(entry.title)}</div>
                    <div class="entry-date">${this.formatDate(entry.date)}</div>
                    <div class="entry-preview">${this.escapeHtml(entry.content.substring(0, 200))}${entry.content.length > 200 ? '...' : ''}</div>
                    <div class="entry-actions-row">
                        <button class="btn btn-small btn-secondary" onclick="journal.viewEntry(${entry.id})">Voir</button>
                        <button class="btn btn-small btn-danger" onclick="journal.deleteEntry(${entry.id})">Supprimer</button>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            this.showError('Erreur lors de l\'affichage des entrées');
        }
    }

    async viewEntry(id) {
        const entry = this.entries.find(e => e.id === id);
        if (!entry) return;

        try {
            const decryptedEntry = {
                ...entry,
                title: await this.decrypt(entry.title, this.password),
                content: await this.decrypt(entry.content, this.password)
            };

            // Créer une modal pour voir l'entrée complète
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <h3>${this.escapeHtml(decryptedEntry.title)}</h3>
                    <div class="entry-date">${this.formatDate(decryptedEntry.date)}</div>
                    <div class="entry-preview" style="max-height: 400px; overflow-y: auto; white-space: pre-wrap; text-align: left; margin: 20px 0;">
                        ${this.escapeHtml(decryptedEntry.content)}
                    </div>
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Fermer</button>
                </div>
            `;
            document.body.appendChild(modal);
        } catch (error) {
            this.showError('Erreur lors de l\'affichage de l\'entrée');
        }
    }

    deleteEntry(id) {
        this.entryToDelete = id;
        document.getElementById('confirmModal').classList.remove('hidden');
    }

    async confirmDelete() {
        if (!this.entryToDelete) return;

        this.entries = this.entries.filter(entry => entry.id !== this.entryToDelete);
        await this.saveToStorage();
        this.renderEntries();
        this.closeModal();
        this.showSuccess('Entrée supprimée avec succès');
        this.entryToDelete = null;
    }

    closeModal() {
        document.getElementById('confirmModal').classList.add('hidden');
        this.entryToDelete = null;
    }

    clearForm() {
        document.getElementById('entryTitle').value = '';
        document.getElementById('entryContent').value = '';
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('fr-FR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showError(message) {
        this.showMessage(message, 'error');
    }

    showSuccess(message) {
        this.showMessage(message, 'success');
    }

    showMessage(message, type) {
        // Créer une notification temporaire
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            ${type === 'error' ? 'background: #e74c3c;' : 'background: #27ae60;'}
        `;

        document.body.appendChild(notification);

        // Animation d'entrée
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Auto-suppression
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Initialiser l'application
const journal = new SecureJournal();