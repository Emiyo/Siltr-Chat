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
        console.log('displayUserProfile called with userId:', userId);
        dispatch(window.profileActions.setLoading(true));
        try {
            console.log('Setting current user ID:', userId);
            dispatch(window.profileActions.setCurrentUserId(userId));
            
            const endpoint = userId === 'current' ? '/api/user/profile' : `/api/user/by_id/${userId}`;
            console.log('Fetching user data from endpoint:', endpoint);
            
            const response = await fetch(endpoint);
            console.log('API response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`Failed to fetch user profile: ${response.status}`);
            }
            
            const userData = await response.json();
            console.log('Received user data:', userData);
            
            dispatch(window.profileActions.setUserData(userData));
            console.log('User data set in store');
            
            dispatch(window.profileActions.openModal());
            console.log('Modal open action dispatched');
            
        } catch (error) {
            console.error('Error in displayUserProfile:', error);
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
