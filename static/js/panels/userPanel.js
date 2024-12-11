// User panel functionality
export default class UserPanel {
    constructor(socket) {
        if (!socket) {
            throw new Error('Socket instance is required for UserPanel');
        }
        
        this.socket = socket;
        this.userList = document.getElementById('userList');
        
        if (!this.userList) {
            console.warn('UserList element not found in the DOM');
        }
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        this.socket.on('active_users', (data) => {
            console.log('Received active users:', data);
            if (data && data.users) {
                this.updateUserList(data.users);
            }
        });
    }

    updateUserList(users) {
        if (!this.userList || !Array.isArray(users)) {
            console.error('Invalid users data or missing userList element');
            return;
        }
        
        console.log('Updating user list with:', users);
        
        this.userList.innerHTML = users.map(user => {
            const rolesBadges = user.roles ? 
                user.roles.map(role => `<span class="role-badge ${role.name}">${role.name}</span>`).join('') : '';
            
            return `
                <div class="user-item ${user.presence_state || 'offline'}" data-user-id="${user.id}">
                    <span class="user-status"></span>
                    <span class="user-name">${user.display_name || user.username}</span>
                    ${user.status ? `<div class="user-activity">${user.status_emoji || ''} ${user.status}</div>` : ''}
                    ${rolesBadges ? `<div class="user-roles">${rolesBadges}</div>` : ''}
                </div>
            `;
        }).join('');
        
        console.log('User list updated');
    }
}
