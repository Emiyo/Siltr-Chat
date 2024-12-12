// Initialize Redux store and profile functionality
const initializeStore = () => {
    if (!window.RTK || !window.profileReducer) {
        console.error('Redux Toolkit or profile reducer not loaded');
        return;
    }

    const store = window.RTK.configureStore({
        reducer: {
            profile: window.profileReducer
        },
        middleware: (getDefaultMiddleware) =>
            getDefaultMiddleware({
                thunk: true,
                serializableCheck: false
            })
    });

    // Create the async action creator
    const displayUserProfile = (userId) => async (dispatch) => {
        dispatch(window.profileActions.setLoading(true));
        try {
            dispatch(window.profileActions.setCurrentUserId(userId));
            const endpoint = userId === 'current' ? '/api/user/profile' : `/api/user/by_id/${userId}`;
            const response = await fetch(endpoint);
            if (!response.ok) throw new Error('Failed to fetch user profile');
            const userData = await response.json();
            dispatch(window.profileActions.setUserData(userData));
            dispatch(window.profileActions.openModal());
        } catch (error) {
            console.error('Error fetching user profile:', error);
            dispatch(window.profileActions.setError(error.message));
        } finally {
            dispatch(window.profileActions.setLoading(false));
        }
    };

    // Assign to window object after everything is initialized
    window.store = store;
    window.displayUserProfile = (userId) => store.dispatch(displayUserProfile(userId));

    return store;
};

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeStore();
});
