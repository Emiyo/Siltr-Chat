// Initialize Redux store
document.addEventListener('DOMContentLoaded', function() {
    if (!window.RTK || !window.profileReducer) {
        console.error('Redux Toolkit or profile reducer not loaded');
        return;
    }

    window.store = window.RTK.configureStore({
        reducer: {
            profile: window.profileReducer
        },
        middleware: (getDefaultMiddleware) =>
            getDefaultMiddleware({
                thunk: true,
                serializableCheck: false
            })
    });

    // Make displayUserProfile available globally after store initialization
    window.displayUserProfile = (userId) => {
        if (!window.store) {
            console.error('Redux store not initialized');
            return;
        }
        window.store.dispatch(window.profileActions.displayUserProfile(userId));
    };
});
