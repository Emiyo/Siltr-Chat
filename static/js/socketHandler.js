// Centralized socket management
class SocketHandler {
    constructor() {
        this.socket = io({
            transports: ['websocket'],
            upgrade: false,
            reconnection: true,
            reconnectionAttempts: 5
        });
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        this.socket.on('connect', () => {
            console.log('Socket connected successfully');
            this.emit('system_message', {
                type: 'system',
                text: 'Connected to server',
                timestamp: new Date().toISOString()
            });
        });

        this.socket.on('connect_error', (error) => {
            console.error('Socket connection error:', error);
            this.emit('system_message', {
                type: 'system',
                text: 'Connection error: ' + error.message,
                timestamp: new Date().toISOString()
            });
        });
    }

    emit(event, data) {
        this.socket.emit(event, data);
    }

    on(event, callback) {
        this.socket.on(event, callback);
    }

    getSocket() {
        return this.socket;
    }
}

export default SocketHandler;
